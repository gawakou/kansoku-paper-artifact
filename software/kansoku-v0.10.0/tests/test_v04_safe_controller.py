from pathlib import Path
import sqlite3
import tempfile

from kansoku.cli import main
from kansoku.controller import SafeController
from kansoku.dashboard import build_snapshot
from kansoku.hub import Hub
from kansoku.models import (
    ActionProposal,
    ApprovalRecord,
    ApprovalStatus,
    VerificationResult,
    VerificationStatus,
)
from kansoku.safety import SafetyPolicy


def observation_rate_proposal(target: str = "path", interval: int = 5) -> ActionProposal:
    return ActionProposal(
        target=target,
        action="increase_observation_rate",
        parameters={"interval_sec": interval},
        expected_effect="Increase observation frequency.",
        rollback={
            "action": "restore_observation_rate",
            "parameters": {"interval_sec": 30},
        },
        source_state_id="state-test",
        risk_level="low",
        preconditions=["target is observable"],
        postconditions=[f"observation interval becomes {interval} seconds"],
    )


def route_proposal(target: str = "path") -> ActionProposal:
    return ActionProposal(
        target=target,
        action="switch_route",
        parameters={"route": "secondary"},
        expected_effect="Move traffic to the secondary route.",
        rollback={"action": "switch_route", "parameters": {"route": "primary"}},
        source_state_id="state-test",
        risk_level="medium",
        preconditions=["secondary route exists"],
        postconditions=["packet loss decreases"],
    )


def test_low_risk_action_is_executed_verified_and_audited():
    with tempfile.TemporaryDirectory() as tmpdir:
        hub = Hub(Path(tmpdir) / "kansoku.db")
        proposal = observation_rate_proposal()
        hub.add_proposal(proposal)

        outcome = SafeController(hub).process(proposal, execute=True)

        assert outcome.decision.status == "APPROVED"
        assert outcome.result.status == "EXECUTED"
        assert outcome.verification.status == "PASSED"
        assert outcome.transaction.outcome == "VERIFIED"
        assert hub.get_observation_plan("path").interval_sec == 5
        assert hub.latest_control_transaction("path").proposal_id == proposal.proposal_id


def test_medium_risk_action_waits_for_approval_then_runs_as_dry_run():
    with tempfile.TemporaryDirectory() as tmpdir:
        hub = Hub(Path(tmpdir) / "kansoku.db")
        proposal = route_proposal()
        hub.add_proposal(proposal)

        waiting = SafeController(hub).process(proposal, execute=False)
        assert waiting.decision.status == "REQUIRE_APPROVAL"
        assert waiting.result is None
        assert waiting.transaction.outcome == "WAITING_APPROVAL"

        approval = ApprovalRecord(
            proposal_id=proposal.proposal_id,
            status=ApprovalStatus.APPROVED.value,
            actor="operator@example.org",
            comment="Approved for a controlled test.",
        )
        hub.add_approval(approval)
        processed = SafeController(hub).process(proposal, execute=False)
        assert processed.decision.status == "APPROVED"
        assert processed.result.status == "DRY_RUN"
        assert processed.verification.status == "SKIPPED"
        assert processed.transaction.outcome == "DRY_RUN"


def test_explicit_rejection_blocks_action():
    with tempfile.TemporaryDirectory() as tmpdir:
        hub = Hub(Path(tmpdir) / "kansoku.db")
        proposal = route_proposal()
        hub.add_proposal(proposal)
        hub.add_approval(
            ApprovalRecord(
                proposal_id=proposal.proposal_id,
                status=ApprovalStatus.REJECTED.value,
                actor="operator@example.org",
                comment="Change window is closed.",
            )
        )
        outcome = SafeController(hub).process(proposal, execute=True)
        assert outcome.decision.status == "REJECTED"
        assert outcome.result is None
        assert outcome.transaction.outcome == "REJECTED"


def test_policy_minimum_interval_and_blocked_action_are_enforced():
    with tempfile.TemporaryDirectory() as tmpdir:
        hub = Hub(Path(tmpdir) / "kansoku.db")
        policy = SafetyPolicy(
            target="path",
            minimum_observation_interval_sec=10,
            blocked_actions=["switch_route"],
        )
        hub.set_safety_policy(policy)

        too_fast = observation_rate_proposal(interval=5)
        hub.add_proposal(too_fast)
        fast_outcome = SafeController(hub).process(too_fast, execute=True)
        assert fast_outcome.transaction.outcome == "REJECTED"
        assert "below policy minimum" in " ".join(fast_outcome.decision.reasons)

        route = route_proposal()
        hub.add_proposal(route)
        route_outcome = SafeController(hub).process(route, execute=False)
        assert route_outcome.transaction.outcome == "REJECTED"
        assert "blocked by policy" in " ".join(route_outcome.decision.reasons)


def test_failed_verification_executes_rollback_and_restores_plan():
    def always_fail(hub, proposal, result):
        return VerificationResult(
            proposal_id=proposal.proposal_id,
            action_result_id=result.result_id,
            status=VerificationStatus.FAILED.value,
            reason="forced verification failure for rollback test",
            checks=[{"check": "forced", "passed": False}],
        )

    with tempfile.TemporaryDirectory() as tmpdir:
        hub = Hub(Path(tmpdir) / "kansoku.db")
        proposal = observation_rate_proposal(interval=5)
        hub.add_proposal(proposal)
        outcome = SafeController(hub, verifier=always_fail).process(proposal, execute=True)

        assert outcome.transaction.outcome == "ROLLED_BACK"
        assert outcome.rollback_result is not None
        assert outcome.rollback_result.is_rollback is True
        assert hub.get_observation_plan("path").interval_sec == 30


def test_dashboard_exposes_safety_policy_and_action_lifecycle():
    with tempfile.TemporaryDirectory() as tmpdir:
        hub = Hub(Path(tmpdir) / "kansoku.db")
        hub.set_safety_policy(SafetyPolicy(target="path", name="lab policy"))
        proposal = observation_rate_proposal()
        hub.add_proposal(proposal)
        SafeController(hub).process(proposal, execute=True)

        snapshot = build_snapshot(hub, "path")
        assert snapshot["safety_policy"]["name"] == "lab policy"
        assert snapshot["control_transactions"][0]["outcome"] == "VERIFIED"
        assert snapshot["action_lifecycle"][0]["guard_status"] == "APPROVED"
        assert snapshot["action_lifecycle"][0]["verification_status"] == "PASSED"


def test_cli_policy_approval_and_controller_flow():
    with tempfile.TemporaryDirectory() as tmpdir:
        db = str(Path(tmpdir) / "kansoku.db")
        hub = Hub(db)
        proposal = route_proposal("router-a")
        hub.add_proposal(proposal)

        assert main(["--db", db, "policy", "set", "--target", "router-a", "--name", "router policy"]) == 0
        assert main(["--db", db, "controller", "process", "--proposal-id", proposal.proposal_id]) == 0
        assert Hub(db).latest_control_transaction("router-a").outcome == "WAITING_APPROVAL"

        assert main([
            "--db", db, "approval", "set", "--proposal-id", proposal.proposal_id,
            "--decision", "approve", "--actor", "ogawa",
        ]) == 0
        assert main([
            "--db", db, "controller", "process", "--proposal-id", proposal.proposal_id,
        ]) == 0
        assert Hub(db).latest_control_transaction("router-a").outcome == "DRY_RUN"



def test_dashboard_preserves_transaction_specific_approval_history():
    with tempfile.TemporaryDirectory() as tmpdir:
        hub = Hub(Path(tmpdir) / "kansoku.db")
        proposal = route_proposal("router-history")
        hub.add_proposal(proposal)
        SafeController(hub).process(proposal, execute=False)
        hub.add_approval(
            ApprovalRecord(
                proposal_id=proposal.proposal_id,
                status=ApprovalStatus.APPROVED.value,
                actor="operator",
            )
        )
        SafeController(hub).process(proposal, execute=False)

        rows = build_snapshot(hub, "router-history")["action_lifecycle"]
        assert rows[0]["outcome"] == "DRY_RUN"
        assert rows[0]["approval_status"] == "APPROVED"
        assert rows[1]["outcome"] == "WAITING_APPROVAL"
        assert rows[1]["approval_status"] is None
        assert rows[1]["guard_status"] == "REQUIRE_APPROVAL"

def test_v03_database_is_migrated_with_safety_tables():
    with tempfile.TemporaryDirectory() as tmpdir:
        db = Path(tmpdir) / "v03.db"
        with sqlite3.connect(db) as conn:
            conn.execute(
                "CREATE TABLE target_profiles (target TEXT PRIMARY KEY, updated_at TEXT NOT NULL, payload TEXT NOT NULL)"
            )
        hub = Hub(db)
        hub.set_safety_policy(SafetyPolicy(target="legacy"))
        assert hub.get_safety_policy("legacy").target == "legacy"
        with sqlite3.connect(db) as conn:
            tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"safety_policies", "approvals", "verifications", "control_transactions"} <= tables
