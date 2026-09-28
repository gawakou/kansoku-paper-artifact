from pathlib import Path
import sqlite3
import tempfile

import pytest

from kansoku.agent import AgentConfig
from kansoku.cli import main
from kansoku.dashboard import build_snapshot
from kansoku.hub import Hub
from kansoku.inventory import ManagedTarget
from kansoku.models import CollectionResult, CollectionRun, Observation
from kansoku.profiles import TargetProfile
from kansoku.service import ObservationService


class FakePingAgent:
    def __init__(self):
        self.calls = 0

    def collect(self, target: str, count: int = 3, timeout: float = 5.0):
        self.calls += 1
        run = CollectionRun(
            agent="ping",
            target=target,
            source="test",
            command=["fake-ping", target],
            returncode=0,
        )
        observations = [
            Observation(target=target, domain="network", metric="rtt_ms", value=1.0, unit="ms", source="test", method="fake"),
            Observation(target=target, domain="network", metric="packet_loss_pct", value=0.0, unit="%", source="test", method="fake"),
            Observation(target=target, domain="network", metric="reachability", value=1.0, unit="bool", source="test", method="fake"),
        ]
        for obs in observations:
            obs.labels["run_id"] = run.run_id
        return CollectionResult(observations=observations, run=run)




class FixedWarningAgent:
    def observe(self, target: str, profile: str = "warning", count: int = 1):
        return [
            Observation(target=target, domain="network", metric="throughput_mbps", value=75.0, unit="Mbps", source="test", method="simulation"),
            Observation(target=target, domain="network", metric="rtt_ms", value=10.0, unit="ms", source="test", method="simulation"),
            Observation(target=target, domain="network", metric="packet_loss_pct", value=0.0, unit="%", source="test", method="simulation"),
            Observation(target=target, domain="network", metric="reachability", value=1.0, unit="bool", source="test", method="simulation"),
        ]


class FakeIperfAgent:
    def __init__(self):
        self.calls = 0

    def collect(self, target: str, **kwargs):
        self.calls += 1
        run = CollectionRun(
            agent="iperf3",
            target=target,
            source="test",
            command=["fake-iperf3", target],
            returncode=0,
        )
        obs = Observation(
            target=target,
            domain="network",
            metric="throughput_mbps",
            value=94.0,
            unit="Mbps",
            source="test",
            method="fake",
            labels={"run_id": run.run_id},
        )
        return CollectionResult(observations=[obs], run=run)


def test_managed_target_inventory_crud_and_validation():
    with tempfile.TemporaryDirectory() as tmpdir:
        hub = Hub(Path(tmpdir) / "kansoku.db")
        target = ManagedTarget(target="host-a", name="Host A")
        hub.set_managed_target(target)
        assert hub.get_managed_target("host-a").name == "Host A"
        assert hub.list_managed_targets(enabled_only=True)[0].target == "host-a"
        hub.set_managed_target(target.updated(enabled=False))
        assert hub.list_managed_targets(enabled_only=True) == []
        assert hub.delete_managed_target("host-a") is True

    with pytest.raises(ValueError):
        ManagedTarget(
            target="bad",
            name="Bad",
            iperf3_enabled=True,
            iperf3_every_n_cycles=0,
        ).validate()


def test_service_once_simulation_persists_state_cycle_and_due_status():
    with tempfile.TemporaryDirectory() as tmpdir:
        hub = Hub(Path(tmpdir) / "kansoku.db")
        target = ManagedTarget(target="sim-a", name="Simulation A", ping_enabled=False)
        hub.set_managed_target(target)
        service = ObservationService(hub, owner_id="svc-test")

        cycles = service.run_once(force=True, simulate_profile="normal")
        assert len(cycles) == 1
        assert cycles[0].status == "SUCCESS"
        assert cycles[0].observation_count == 3
        assert hub.latest_state("sim-a") is not None
        assert hub.latest_scheduler_cycle("sim-a").cycle_id == cycles[0].cycle_id
        assert service.due_status(target).due is False
        assert service.run_once(simulate_profile="normal") == []


def test_disabled_target_is_not_scheduled():
    with tempfile.TemporaryDirectory() as tmpdir:
        hub = Hub(Path(tmpdir) / "kansoku.db")
        hub.set_managed_target(ManagedTarget(target="off", name="Off", enabled=False))
        service = ObservationService(hub, owner_id="svc-test")
        assert service.run_once(force=True, simulate_profile="normal") == []
        assert hub.count_scheduler_cycles("off") == 0


def test_scheduler_lease_blocks_second_instance_and_can_be_recovered():
    with tempfile.TemporaryDirectory() as tmpdir:
        hub = Hub(Path(tmpdir) / "kansoku.db")
        hub.set_managed_target(ManagedTarget(target="sim", name="Sim"))
        assert hub.acquire_scheduler_lease(ObservationService.LEASE_NAME, "owner-a", ttl_sec=60)
        with pytest.raises(RuntimeError, match="owner-a"):
            ObservationService(hub, owner_id="owner-b").run_once(
                force=True, simulate_profile="normal"
            )
        assert hub.release_scheduler_lease(
            ObservationService.LEASE_NAME, "", force=True
        )
        assert ObservationService(hub, owner_id="owner-b").run_once(
            force=True, simulate_profile="normal"
        )


def test_real_collection_uses_iperf_cadence_and_persists_raw_runs():
    with tempfile.TemporaryDirectory() as tmpdir:
        raw_dir = str(Path(tmpdir) / "raw")
        hub = Hub(Path(tmpdir) / "kansoku.db")
        target = ManagedTarget(
            target="host-a",
            name="Host A",
            iperf3_enabled=True,
            iperf3_every_n_cycles=2,
            raw_dir=raw_dir,
        )
        hub.set_managed_target(target)
        ping = FakePingAgent()
        iperf = FakeIperfAgent()
        service = ObservationService(
            hub, owner_id="svc-test", ping_agent=ping, iperf3_agent=iperf
        )

        first = service.run_once(force=True)[0]
        second = service.run_once(force=True)[0]
        assert ping.calls == 2
        assert iperf.calls == 1
        assert len(first.collection_run_ids) == 1
        assert len(second.collection_run_ids) == 2
        assert len(list(Path(raw_dir).glob("run-*.json"))) == 3


def test_low_risk_proposal_is_auto_processed_by_service():
    with tempfile.TemporaryDirectory() as tmpdir:
        hub = Hub(Path(tmpdir) / "kansoku.db")
        hub.set_target_profile(TargetProfile(target="path", expected_bandwidth_mbps=100))
        hub.set_managed_target(
            ManagedTarget(target="path", name="Path", ping_enabled=False)
        )
        cycle = ObservationService(
            hub, owner_id="svc-test", simulated_agent=FixedWarningAgent()
        ).run_once(force=True, simulate_profile="warning")[0]
        assert cycle.proposal_id is not None
        assert cycle.transaction_id is not None
        assert hub.get_observation_plan("path").interval_sec == 5
        assert hub.latest_control_transaction("path").outcome == "VERIFIED"


def test_dashboard_exposes_inventory_scheduler_and_fleet():
    with tempfile.TemporaryDirectory() as tmpdir:
        hub = Hub(Path(tmpdir) / "kansoku.db")
        hub.set_managed_target(ManagedTarget(target="sim", name="Managed Sim"))
        ObservationService(hub, owner_id="svc-test").run_once(
            force=True, simulate_profile="normal"
        )
        snapshot = build_snapshot(hub, "sim")
        assert snapshot["managed_target"]["name"] == "Managed Sim"
        assert snapshot["scheduler_cycles"][0]["status"] == "SUCCESS"
        assert snapshot["scheduler_due"]["due"] is False


def test_cli_target_and_service_simulation_flow():
    with tempfile.TemporaryDirectory() as tmpdir:
        db = str(Path(tmpdir) / "kansoku.db")
        assert main([
            "--db", db, "target", "set", "--target", "sim-cli", "--name", "CLI Sim",
            "--no-ping-enabled",
        ]) == 0
        assert main([
            "--db", db, "service", "once", "--target", "sim-cli", "--force",
            "--simulate-profile", "normal", "--owner-id", "cli-test",
        ]) == 0
        assert Hub(db).latest_scheduler_cycle("sim-cli").status == "SUCCESS"
        assert main(["--db", db, "service", "status", "--target", "sim-cli"]) == 0


def test_v04_database_is_migrated_with_service_tables():
    with tempfile.TemporaryDirectory() as tmpdir:
        db = Path(tmpdir) / "v04.db"
        with sqlite3.connect(db) as conn:
            conn.execute(
                "CREATE TABLE control_transactions (transaction_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, target TEXT NOT NULL, proposal_id TEXT NOT NULL, outcome TEXT NOT NULL, payload TEXT NOT NULL)"
            )
        Hub(db)
        with sqlite3.connect(db) as conn:
            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
        assert {"managed_targets", "scheduler_cycles", "scheduler_leases"} <= tables
