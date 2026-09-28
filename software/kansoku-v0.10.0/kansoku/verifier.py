from __future__ import annotations

from typing import Dict, List

from .hub import Hub
from .models import (
    ActionProposal,
    ActionResult,
    ActionStatus,
    OperationalState,
    VerificationResult,
    VerificationStatus,
)


_STATE_SEVERITY = {
    OperationalState.NORMAL.value: 0,
    OperationalState.WARNING.value: 1,
    OperationalState.DEGRADED.value: 2,
    OperationalState.CRITICAL.value: 3,
}


def verify_action(hub: Hub, proposal: ActionProposal, result: ActionResult) -> VerificationResult:
    """Verify an action using persisted postconditions and current Hub state."""

    if result.status == ActionStatus.DRY_RUN.value:
        return VerificationResult(
            proposal_id=proposal.proposal_id,
            action_result_id=result.result_id,
            status=VerificationStatus.SKIPPED.value,
            reason="dry-run actions are not postcondition-verified",
        )

    if result.status != ActionStatus.EXECUTED.value or result.returncode != 0:
        return VerificationResult(
            proposal_id=proposal.proposal_id,
            action_result_id=result.result_id,
            status=VerificationStatus.FAILED.value,
            reason=f"action execution did not succeed: status={result.status} rc={result.returncode}",
            checks=[{"check": "execution_success", "passed": False}],
        )

    if proposal.action in {"increase_observation_rate", "restore_observation_rate"}:
        expected = int(proposal.parameters.get("interval_sec", 0))
        plan = hub.get_observation_plan(proposal.target)
        actual = plan.interval_sec if plan else None
        passed = actual == expected
        return VerificationResult(
            proposal_id=proposal.proposal_id,
            action_result_id=result.result_id,
            status=(
                VerificationStatus.PASSED.value if passed else VerificationStatus.FAILED.value
            ),
            reason=(
                f"observation interval verified at {actual}s"
                if passed
                else f"observation interval verification failed: expected={expected}s actual={actual}"
            ),
            checks=[
                {
                    "check": "observation_interval",
                    "expected": expected,
                    "actual": actual,
                    "passed": passed,
                }
            ],
        )

    source_state = hub.get_state(proposal.source_state_id)
    latest_state = hub.latest_state(proposal.target)
    if source_state and latest_state and latest_state.state_id != source_state.state_id:
        before = _STATE_SEVERITY.get(source_state.state, 99)
        after = _STATE_SEVERITY.get(latest_state.state, 99)
        passed = after <= before
        return VerificationResult(
            proposal_id=proposal.proposal_id,
            action_result_id=result.result_id,
            status=(
                VerificationStatus.PASSED.value if passed else VerificationStatus.FAILED.value
            ),
            reason=(
                f"post-action state is non-worsening: {source_state.state} -> {latest_state.state}"
                if passed
                else f"post-action state worsened: {source_state.state} -> {latest_state.state}"
            ),
            checks=[
                {
                    "check": "state_non_worsening",
                    "before": source_state.state,
                    "after": latest_state.state,
                    "passed": passed,
                }
            ],
        )

    return VerificationResult(
        proposal_id=proposal.proposal_id,
        action_result_id=result.result_id,
        status=VerificationStatus.INCONCLUSIVE.value,
        reason="no post-action observation or adapter-specific verification is available yet",
        checks=[{"check": "post_action_observation", "passed": None}],
    )
