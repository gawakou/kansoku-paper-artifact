from pathlib import Path
import sqlite3
import tempfile

import pytest

from kansoku.cli import main
from kansoku.dashboard import build_snapshot
from kansoku.hub import Hub
from kansoku.models import Domain, Observation
from kansoku.profiles import TargetProfile, learn_throughput_baseline
from kansoku.state import RuleBasedStateEngine
from kansoku.workflow import apply_low_risk_observation_action, evaluate_and_persist


def observations(target: str, throughput: float, rtt: float = 4.2, loss: float = 0.0):
    return [
        Observation(target=target, domain=Domain.NETWORK.value, metric="throughput_mbps", value=throughput, unit="Mbps"),
        Observation(target=target, domain=Domain.NETWORK.value, metric="rtt_ms", value=rtt, unit="ms"),
        Observation(target=target, domain=Domain.NETWORK.value, metric="packet_loss_pct", value=loss, unit="%"),
        Observation(target=target, domain=Domain.NETWORK.value, metric="reachability", value=1, unit="bool"),
    ]


def test_profile_relative_100m_path_treats_94m_as_normal():
    profile = TargetProfile(target="path", expected_bandwidth_mbps=100)
    state = RuleBasedStateEngine(profile).estimate("path", observations("path", 94.05))
    assert state.state == "NORMAL"
    assert state.features["throughput_ratio"] == pytest.approx(0.9405)
    assert state.features["profile_mode"] == "relative"
    assert "94.0%" in state.reason


def test_profile_relative_degradation_and_absolute_fallback():
    profile = TargetProfile(target="path", expected_bandwidth_mbps=100)
    relative = RuleBasedStateEngine(profile).estimate("path", observations("path", 60))
    assert relative.state == "DEGRADED"
    assert "60.0%" in relative.reason

    fallback = RuleBasedStateEngine().estimate("path", observations("path", 94.05))
    assert fallback.state == "WARNING"
    assert fallback.features["profile_mode"] == "absolute_fallback"


def test_learned_median_baseline_is_robust():
    target = "path"
    rows = [
        Observation(target=target, domain="network", metric="throughput_mbps", value=v, unit="Mbps")
        for v in (94, 95, 10)
    ]
    assert learn_throughput_baseline(target, rows) == 94


def test_auto_evaluation_and_recovery_proposal_persisted():
    with tempfile.TemporaryDirectory() as tmpdir:
        hub = Hub(Path(tmpdir) / "kansoku.db")
        hub.set_target_profile(TargetProfile(target="path", expected_bandwidth_mbps=100))
        hub.add_observations(observations("path", 75))
        first = evaluate_and_persist(hub, "path")
        assert first.state.state == "WARNING"
        assert first.proposal.action == "increase_observation_rate"

        hub.add_observations(observations("path", 94))
        recovered = evaluate_and_persist(hub, "path")
        assert recovered.state.state == "NORMAL"
        assert recovered.proposal.action == "restore_observation_rate"


def test_low_risk_observation_action_updates_plan_only_when_executed():
    with tempfile.TemporaryDirectory() as tmpdir:
        hub = Hub(Path(tmpdir) / "kansoku.db")
        hub.set_target_profile(TargetProfile(target="path", expected_bandwidth_mbps=100))
        hub.add_observations(observations("path", 75))
        proposal = evaluate_and_persist(hub, "path").proposal
        assert proposal is not None

        _, dry_result, dry_plan = apply_low_risk_observation_action(hub, proposal, execute=False)
        assert dry_result.status == "DRY_RUN"
        assert dry_plan is None
        assert hub.get_observation_plan("path") is None

        _, result, plan = apply_low_risk_observation_action(hub, proposal, execute=True)
        assert result.status == "EXECUTED"
        assert plan.interval_sec == 5
        assert hub.get_observation_plan("path").mode == "intensive"


def test_dashboard_snapshot_exposes_profile_series_and_evidence():
    with tempfile.TemporaryDirectory() as tmpdir:
        hub = Hub(Path(tmpdir) / "kansoku.db")
        hub.set_target_profile(TargetProfile(target="path", name="100M path", expected_bandwidth_mbps=100))
        hub.add_observations(observations("path", 94))
        evaluate_and_persist(hub, "path")
        snapshot = build_snapshot(hub, "path")
        assert snapshot["profile"]["name"] == "100M path"
        assert snapshot["series"]["throughput_mbps"][-1]["value"] == 94
        assert snapshot["evidence"]
        assert snapshot["state"]["features"]["throughput_ratio"] == pytest.approx(0.94)


def test_cli_simulation_auto_evaluates():
    with tempfile.TemporaryDirectory() as tmpdir:
        db = str(Path(tmpdir) / "kansoku.db")
        assert main(["--db", db, "agent", "simulate", "--target", "demo", "--profile", "normal", "--count", "1"]) == 0
        assert Hub(db).latest_state("demo") is not None


def test_v02_database_is_migrated_without_data_loss():
    with tempfile.TemporaryDirectory() as tmpdir:
        db = Path(tmpdir) / "v02.db"
        with sqlite3.connect(db) as conn:
            conn.executescript(
                """
                CREATE TABLE observations (
                    observation_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL,
                    target TEXT NOT NULL, source TEXT NOT NULL, domain TEXT NOT NULL,
                    metric TEXT NOT NULL, value REAL NOT NULL, unit TEXT NOT NULL,
                    method TEXT NOT NULL, payload TEXT NOT NULL
                );
                """
            )
            obs = Observation(target="legacy", domain="network", metric="rtt_ms", value=1, unit="ms")
            import json
            conn.execute(
                "INSERT INTO observations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (obs.observation_id, obs.timestamp, obs.target, obs.source, obs.domain, obs.metric, obs.value, obs.unit, obs.method, json.dumps(obs.to_dict())),
            )
        hub = Hub(db)
        assert hub.latest_observations("legacy")[0].value == 1
        hub.set_target_profile(TargetProfile(target="legacy", expected_bandwidth_mbps=100))
        assert hub.get_target_profile("legacy").expected_bandwidth_mbps == 100
