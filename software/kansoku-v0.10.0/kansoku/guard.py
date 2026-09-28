from __future__ import annotations

from typing import List, Optional

from .models import (
    ActionProposal,
    ApprovalRecord,
    ApprovalStatus,
    GuardDecision,
    GuardStatus,
)
from .safety import SafetyPolicy


# Backward-compatible alias for code that imported GuardPolicy directly.
GuardPolicy = SafetyPolicy


class GuardEngine:
    """Validate proposed actions before execution under a SafetyPolicy."""

    def __init__(self, policy: SafetyPolicy | None = None):
        self.policy = policy or SafetyPolicy()
        self.policy.validate()

    def validate(
        self,
        proposal: ActionProposal,
        approval: Optional[ApprovalRecord] = None,
    ) -> GuardDecision:
        reasons: List[str] = []
        allowed = self.policy.allowed_action_set

        if proposal.action not in allowed:
            reasons.append(f"action is not allowed: {proposal.action}")

        if proposal.action in set(self.policy.blocked_actions):
            reasons.append(f"action is blocked by policy: {proposal.action}")

        if proposal.action in {"tc_netem_apply", "tc_netem_clear"} and not self.policy.allow_system_changes:
            reasons.append(
                f"system-changing action is disabled by policy: {proposal.action}"
            )

        if proposal.target in set(self.policy.blocked_targets):
            reasons.append(f"target is blocked by policy: {proposal.target}")

        if (
            proposal.action in self.policy.rollback_required_action_set
            and not proposal.rollback
        ):
            reasons.append("rollback is required but not defined")

        if proposal.rollback:
            rollback_action = proposal.rollback.get("action")
            if rollback_action not in allowed:
                reasons.append(f"rollback action is not allowed: {rollback_action}")

        if not proposal.postconditions:
            reasons.append("postconditions are required to verify action effect")

        if proposal.action in {"increase_observation_rate", "restore_observation_rate"}:
            try:
                interval = int(proposal.parameters.get("interval_sec", 0))
            except (TypeError, ValueError):
                interval = 0
            if interval < self.policy.minimum_observation_interval_sec:
                reasons.append(
                    "requested observation interval is below policy minimum: "
                    f"{interval}s < {self.policy.minimum_observation_interval_sec}s"
                )

        if approval and approval.proposal_id != proposal.proposal_id:
            reasons.append("approval record does not match the proposal")

        if approval and approval.status == ApprovalStatus.REJECTED.value:
            reasons.append(f"human approval was rejected by {approval.actor}")

        if reasons:
            return GuardDecision(
                proposal_id=proposal.proposal_id,
                status=GuardStatus.REJECTED.value,
                reasons=reasons,
                policy_version=self.policy.version,
                policy_id=self.policy.policy_id,
            )

        approval_required = (
            proposal.action in self.policy.approval_required_action_set
            or proposal.risk_level in {"medium", "high"}
        )

        if approval_required:
            if approval and approval.status == ApprovalStatus.APPROVED.value:
                return GuardDecision(
                    proposal_id=proposal.proposal_id,
                    status=GuardStatus.APPROVED.value,
                    reasons=[
                        f"human approval recorded by {approval.actor}",
                        f"proposal satisfies {self.policy.version}",
                    ],
                    policy_version=self.policy.version,
                    policy_id=self.policy.policy_id,
                )
            return GuardDecision(
                proposal_id=proposal.proposal_id,
                status=GuardStatus.REQUIRE_APPROVAL.value,
                reasons=[
                    f"human approval is required for action={proposal.action} "
                    f"risk_level={proposal.risk_level}"
                ],
                policy_version=self.policy.version,
                policy_id=self.policy.policy_id,
            )

        if proposal.action not in self.policy.auto_approve_action_set:
            return GuardDecision(
                proposal_id=proposal.proposal_id,
                status=GuardStatus.REQUIRE_APPROVAL.value,
                reasons=[
                    f"action is allowed but not auto-approved by {self.policy.version}: "
                    f"{proposal.action}"
                ],
                policy_version=self.policy.version,
                policy_id=self.policy.policy_id,
            )

        return GuardDecision(
            proposal_id=proposal.proposal_id,
            status=GuardStatus.APPROVED.value,
            reasons=[f"proposal satisfies {self.policy.version} and is auto-approved"],
            policy_version=self.policy.version,
            policy_id=self.policy.policy_id,
        )
