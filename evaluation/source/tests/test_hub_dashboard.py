from pathlib import Path
import tempfile

from kansoku.agent import SimulatedNetworkAgent
from kansoku.dashboard import build_snapshot
from kansoku.hub import Hub
from kansoku.models import CollectionRun
from kansoku.state import RuleBasedStateEngine


def test_collection_run_and_dashboard_snapshot():
    with tempfile.TemporaryDirectory() as tmpdir:
        hub = Hub(Path(tmpdir) / "kansoku.db")
        observations = SimulatedNetworkAgent().observe("demo", profile="degraded", count=2)
        hub.add_observations(observations)
        run = CollectionRun(agent="test", target="demo", source="host", command=["echo", "test"], returncode=0)
        hub.add_collection_run(run)
        state = RuleBasedStateEngine().estimate("demo", hub.latest_observations("demo"))
        hub.add_state(state)

        snapshot = build_snapshot(hub, "demo")
        assert snapshot["target"] == "demo"
        assert snapshot["state"]["state"] in {"DEGRADED", "CRITICAL"}
        assert "rtt_ms" in snapshot["latest_metrics"]
        assert snapshot["runs"][0]["run_id"] == run.run_id
        assert hub.get_collection_run(run.run_id).command == ["echo", "test"]
