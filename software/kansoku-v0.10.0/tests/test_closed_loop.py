from pathlib import Path
import tempfile

from kansoku.act import ActEngine
from kansoku.agent import SimulatedNetworkAgent
from kansoku.guard import GuardEngine
from kansoku.hub import Hub
from kansoku.models import GuardStatus
from kansoku.state import RuleBasedStateEngine


def test_minimal_closed_loop():
    with tempfile.TemporaryDirectory() as tmpdir:
        hub = Hub(Path(tmpdir) / "kansoku.db")
        agent = SimulatedNetworkAgent()
        observations = agent.observe("demo-path", profile="degraded", count=3)
        hub.add_observations(observations)

        engine = RuleBasedStateEngine()
        state = engine.estimate("demo-path", hub.latest_observations("demo-path"))
        hub.add_state(state)
        assert state.state in {"DEGRADED", "CRITICAL"}

        proposal = engine.propose_action(state)
        assert proposal is not None
        hub.add_proposal(proposal)

        decision = GuardEngine().validate(proposal)
        hub.add_guard_decision(decision)
        assert decision.status in {GuardStatus.APPROVED.value, GuardStatus.REQUIRE_APPROVAL.value}

        result = ActEngine().execute(proposal, decision, execute=False)
        hub.add_action_result(result)
        if decision.status == GuardStatus.APPROVED.value:
            assert result.status == "DRY_RUN"
        else:
            assert result.status == "SKIPPED"
