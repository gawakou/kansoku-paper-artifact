from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from .act import ActEngine
from .guard import GuardEngine
from .hub import Hub
from .models import (
    ActionProposal,
    ActionResult,
    ActionStatus,
    ApprovalRecord,
    ControlTransaction,
    GuardDecision,
    GuardStatus,
    TransactionOutcome,
    VerificationResult,
    VerificationStatus,
)
from .profiles import ObservationPlan
from .safety import SafetyPolicy
from .verifier import verify_action


@dataclass
class ControllerOutcome:
    proposal: ActionProposal
    policy: SafetyPolicy
    decision: GuardDecision
    approval: Optional[ApprovalRecord]
    result: Optional[ActionResult]
    verification: Optional[VerificationResult]
    rollback_result: Optional[ActionResult]
    transaction: ControlTransaction


class SafeController:
    """Persistent Guard -> Approval -> Act -> Verify -> Rollback controller."""

    def __init__(
        self,
        hub: Hub,
        *,
        verifier: Callable[[Hub, ActionProposal, ActionResult], VerificationResult] = verify_action,
    ):
        self.hub = hub
        self.verifier = verifier

    def process(
        self,
        proposal: ActionProposal,
        *,
        execute: bool = False,
        allow_system_changes: bool = False,
    ) -> ControllerOutcome:
        policy = self.hub.get_safety_policy(proposal.target) or SafetyPolicy()
        approval = self.hub.latest_approval(proposal.proposal_id)
        decision = GuardEngine(policy).validate(proposal, approval=approval)
        self.hub.add_guard_decision(decision)

        if decision.status == GuardStatus.REQUIRE_APPROVAL.value:
            transaction = self._transaction(
                proposal,
                TransactionOutcome.WAITING_APPROVAL.value,
                decision=decision,
                approval=approval,
                message="proposal is waiting for explicit human approval",
            )
            return ControllerOutcome(
                proposal, policy, decision, approval, None, None, None, transaction
            )

        if decision.status == GuardStatus.REJECTED.value:
            transaction = self._transaction(
                proposal,
                TransactionOutcome.REJECTED.value,
                decision=decision,
                approval=approval,
                message="proposal was rejected by KANSOKU Guard",
            )
            return ControllerOutcome(
                proposal, policy, decision, approval, None, None, None, transaction
            )

        effective_system_permission = bool(
            allow_system_changes and policy.allow_system_changes
        )
        result = ActEngine().execute(
            proposal,
            decision,
            execute=execute,
            allow_system_changes=effective_system_permission,
        )
        self.hub.add_action_result(result)

        if execute and result.status == ActionStatus.EXECUTED.value:
            self._persist_internal_effect(proposal)

        verification = self.verifier(self.hub, proposal, result)
        self.hub.add_verification(verification)

        rollback_result: Optional[ActionResult] = None
        if (
            execute
            and verification.status == VerificationStatus.FAILED.value
            and policy.rollback_on_verification_failure
            and proposal.rollback
        ):
            rollback_result = self._rollback(
                proposal,
                decision,
                allow_system_changes=effective_system_permission,
            )

        if rollback_result and rollback_result.status == ActionStatus.EXECUTED.value:
            outcome = TransactionOutcome.ROLLED_BACK.value
            message = "verification failed and rollback executed"
        elif result.status == ActionStatus.DRY_RUN.value:
            outcome = TransactionOutcome.DRY_RUN.value
            message = "action completed as dry-run"
        elif result.status != ActionStatus.EXECUTED.value:
            outcome = TransactionOutcome.FAILED.value
            message = f"action did not execute successfully: {result.status}"
        elif verification.status == VerificationStatus.PASSED.value:
            outcome = TransactionOutcome.VERIFIED.value
            message = "action executed and postconditions passed"
        elif verification.status == VerificationStatus.INCONCLUSIVE.value:
            outcome = TransactionOutcome.INCONCLUSIVE.value
            message = "action executed but verification requires new observations"
        else:
            outcome = TransactionOutcome.FAILED.value
            message = "action verification failed"

        transaction = self._transaction(
            proposal,
            outcome,
            decision=decision,
            approval=approval,
            result=result,
            verification=verification,
            rollback_result=rollback_result,
            message=message,
        )
        return ControllerOutcome(
            proposal,
            policy,
            decision,
            approval,
            result,
            verification,
            rollback_result,
            transaction,
        )

    def _persist_internal_effect(self, proposal: ActionProposal) -> None:
        if proposal.action not in {
            "increase_observation_rate",
            "restore_observation_rate",
        }:
            return
        interval = int(proposal.parameters.get("interval_sec", 30))
        mode = "intensive" if proposal.action == "increase_observation_rate" else "normal"
        self.hub.set_observation_plan(
            ObservationPlan(
                target=proposal.target,
                interval_sec=interval,
                mode=mode,
                reason=proposal.expected_effect,
                source_proposal_id=proposal.proposal_id,
            )
        )

    def _rollback(
        self,
        original: ActionProposal,
        original_decision: GuardDecision,
        *,
        allow_system_changes: bool,
    ) -> ActionResult:
        rollback = original.rollback or {}
        rollback_proposal = ActionProposal(
            target=original.target,
            action=str(rollback.get("action", "")),
            parameters=dict(rollback.get("parameters", {})),
            expected_effect=f"Rollback of {original.action}",
            rollback=None,
            source_state_id=original.source_state_id,
            proposal_id=original.proposal_id,
            risk_level=original.risk_level,
            preconditions=["original action verification failed"],
            postconditions=["pre-action configuration is restored"],
        )
        result = ActEngine().execute(
            rollback_proposal,
            original_decision,
            execute=True,
            allow_system_changes=allow_system_changes,
            is_rollback=True,
        )
        self.hub.add_action_result(result)
        if result.status == ActionStatus.EXECUTED.value:
            self._persist_internal_effect(rollback_proposal)
        return result

    def _transaction(
        self,
        proposal: ActionProposal,
        outcome: str,
        *,
        decision: GuardDecision,
        approval: Optional[ApprovalRecord],
        result: Optional[ActionResult] = None,
        verification: Optional[VerificationResult] = None,
        rollback_result: Optional[ActionResult] = None,
        message: str,
    ) -> ControlTransaction:
        transaction = ControlTransaction(
            target=proposal.target,
            proposal_id=proposal.proposal_id,
            outcome=outcome,
            guard_decision_id=decision.decision_id,
            approval_id=approval.approval_id if approval else None,
            action_result_id=result.result_id if result else None,
            verification_id=verification.verification_id if verification else None,
            rollback_result_id=rollback_result.result_id if rollback_result else None,
            message=message,
        )
        self.hub.add_control_transaction(transaction)
        return transaction
