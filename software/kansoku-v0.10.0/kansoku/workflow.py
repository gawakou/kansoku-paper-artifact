from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .hub import Hub
from .models import ActionProposal, ActionResult, GuardDecision, StateEstimate
from .controller import SafeController
from .profiles import ObservationPlan, TargetProfile
from .state import RuleBasedStateEngine


@dataclass
class EvaluationOutcome:
    state: StateEstimate
    proposal: Optional[ActionProposal]
    previous_state: Optional[StateEstimate]


def evaluate_and_persist(
    hub: Hub,
    target: str,
    *,
    limit: int = 100,
    profile: Optional[TargetProfile] = None,
) -> EvaluationOutcome:
    """Evaluate a target and persist state/proposal as one workflow step."""

    previous = hub.latest_state(target)
    observations = hub.latest_observations(target, limit=limit)
    resolved_profile = profile or hub.get_target_profile(target)
    engine = RuleBasedStateEngine(profile=resolved_profile)
    state = engine.estimate(target, observations)
    hub.add_state(state)

    proposal = engine.propose_action(state, previous_state=previous)
    # Avoid producing identical proposals on every observation cycle.  A new
    # proposal is emitted on a state transition or when the action changes.
    if proposal:
        latest = hub.latest_proposal(target)
        if latest and latest.action == proposal.action and previous and previous.state == state.state:
            proposal = None
        else:
            hub.add_proposal(proposal)

    return EvaluationOutcome(state=state, proposal=proposal, previous_state=previous)


def apply_low_risk_observation_action(
    hub: Hub,
    proposal: ActionProposal,
    *,
    execute: bool,
) -> tuple[GuardDecision, ActionResult, Optional[ObservationPlan]]:
    """Compatibility wrapper over the v0.4 safe controller lifecycle."""

    outcome = SafeController(hub).process(proposal, execute=execute)
    if outcome.result is None:
        raise RuntimeError(
            f"low-risk action did not reach Act: guard={outcome.decision.status}"
        )
    plan = hub.get_observation_plan(proposal.target) if execute else None
    return outcome.decision, outcome.result, plan

