from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import hashlib
import sqlite3
from typing import Iterable, List, Optional

from .models import (
    ActionProposal,
    ActionResult,
    ApprovalRecord,
    CollectionRun,
    ControlTransaction,
    GuardDecision,
    Observation,
    StateEstimate,
    VerificationResult,
    dumps,
    loads,
    utc_now,
)
from .inventory import ManagedTarget
from .profiles import ObservationPlan, TargetProfile
from .scheduler import SchedulerCycle, SchedulerLease, parse_time
from .safety import SafetyPolicy
from .remote import AgentHeartbeat, IngestBatch, IngestReceipt, RemoteAgentRegistration
from .capture import CaptureSession, FlowRecord
from .network_state import (
    FlowAssessment, L2Link, NetworkDevice, NetworkInterface, NetworkSnapshot,
    PolicyRule, RouteEntry, VlanRecord,
)
from .recommendation import ConfigurationRecommendation, require_approval_eligible
from .evidence import EvidenceGraph
from .remediation import RemediationExecution
from .experiment import ExperimentDefinition, ExperimentTrial


class Hub:
    """SQLite-backed local data hub.

    v0.2 adds collection-run records so raw command output and normalized
    observations remain linked as reproducible measurement evidence.
    """

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_db()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self) -> None:
        with self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS observations (
                    observation_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    target TEXT NOT NULL,
                    source TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    metric TEXT NOT NULL,
                    value REAL NOT NULL,
                    unit TEXT NOT NULL,
                    method TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_observations_target_time
                ON observations(target, timestamp);
                CREATE INDEX IF NOT EXISTS idx_observations_metric_time
                ON observations(metric, timestamp);

                CREATE TABLE IF NOT EXISTS collection_runs (
                    run_id TEXT PRIMARY KEY,
                    started_at TEXT NOT NULL,
                    finished_at TEXT NOT NULL,
                    agent TEXT NOT NULL,
                    target TEXT NOT NULL,
                    source TEXT NOT NULL,
                    returncode INTEGER NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_collection_runs_target_time
                ON collection_runs(target, started_at);

                CREATE TABLE IF NOT EXISTS states (
                    state_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    target TEXT NOT NULL,
                    state TEXT NOT NULL,
                    control_mode TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_states_target_time
                ON states(target, timestamp);

                CREATE TABLE IF NOT EXISTS proposals (
                    proposal_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    target TEXT NOT NULL,
                    action TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    payload TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS guard_decisions (
                    decision_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    proposal_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    payload TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS action_results (
                    result_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    proposal_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    returncode INTEGER NOT NULL,
                    payload TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS target_profiles (
                    target TEXT PRIMARY KEY,
                    updated_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS observation_plans (
                    target TEXT PRIMARY KEY,
                    updated_at TEXT NOT NULL,
                    interval_sec INTEGER NOT NULL,
                    mode TEXT NOT NULL,
                    payload TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS safety_policies (
                    target TEXT PRIMARY KEY,
                    updated_at TEXT NOT NULL,
                    policy_id TEXT NOT NULL,
                    payload TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS approvals (
                    approval_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    proposal_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_approvals_proposal_time
                ON approvals(proposal_id, timestamp);

                CREATE TABLE IF NOT EXISTS verifications (
                    verification_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    proposal_id TEXT NOT NULL,
                    action_result_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_verifications_proposal_time
                ON verifications(proposal_id, timestamp);

                CREATE TABLE IF NOT EXISTS control_transactions (
                    transaction_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    target TEXT NOT NULL,
                    proposal_id TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_control_transactions_target_time
                ON control_transactions(target, timestamp);


                CREATE TABLE IF NOT EXISTS managed_targets (
                    target TEXT PRIMARY KEY,
                    target_id TEXT NOT NULL,
                    enabled INTEGER NOT NULL,
                    updated_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_managed_targets_enabled_updated
                ON managed_targets(enabled, updated_at);

                CREATE TABLE IF NOT EXISTS scheduler_cycles (
                    cycle_id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    owner_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_scheduler_cycles_target_time
                ON scheduler_cycles(target, finished_at);

                CREATE TABLE IF NOT EXISTS scheduler_leases (
                    name TEXT PRIMARY KEY,
                    owner_id TEXT NOT NULL,
                    acquired_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS remote_agents (
                    agent_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    enabled INTEGER NOT NULL,
                    token_fingerprint TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_seen_at TEXT,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_remote_agents_enabled_updated
                ON remote_agents(enabled, updated_at);

                CREATE TABLE IF NOT EXISTS agent_heartbeats (
                    heartbeat_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    queue_depth INTEGER NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_agent_heartbeats_agent_time
                ON agent_heartbeats(agent_id, timestamp);

                CREATE TABLE IF NOT EXISTS ingest_batches (
                    batch_id TEXT PRIMARY KEY,
                    receipt_id TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    observation_count INTEGER NOT NULL,
                    run_count INTEGER NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_ingest_batches_agent_time
                ON ingest_batches(agent_id, received_at);

                CREATE TABLE IF NOT EXISTS capture_sessions (
                    capture_id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    source TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    packet_count INTEGER NOT NULL,
                    flow_count INTEGER NOT NULL,
                    file_size INTEGER NOT NULL,
                    storage_scope TEXT NOT NULL,
                    sha256 TEXT NOT NULL DEFAULT '',
                    dedupe_key TEXT NOT NULL DEFAULT '',
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_capture_sessions_target_time
                ON capture_sessions(target, finished_at);

                CREATE TABLE IF NOT EXISTS flow_records (
                    flow_id TEXT PRIMARY KEY,
                    capture_id TEXT NOT NULL,
                    target TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT NOT NULL,
                    wire_bytes INTEGER NOT NULL,
                    packets INTEGER NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_flow_records_capture_bytes
                ON flow_records(capture_id, wire_bytes DESC);
                CREATE INDEX IF NOT EXISTS idx_flow_records_target_time
                ON flow_records(target, last_seen);

                CREATE TABLE IF NOT EXISTS network_devices (
                    device_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    device_type TEXT NOT NULL,
                    platform TEXT NOT NULL,
                    enabled INTEGER NOT NULL,
                    updated_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_network_devices_type_name
                ON network_devices(device_type, name);

                CREATE TABLE IF NOT EXISTS network_snapshots (
                    snapshot_id TEXT PRIMARY KEY,
                    device_id TEXT NOT NULL,
                    collector TEXT NOT NULL,
                    source TEXT NOT NULL,
                    status TEXT NOT NULL,
                    finished_at TEXT NOT NULL,
                    raw_sha256 TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_network_snapshots_device_time
                ON network_snapshots(device_id, finished_at);

                CREATE TABLE IF NOT EXISTS network_interfaces (
                    interface_id TEXT PRIMARY KEY,
                    snapshot_id TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    oper_up INTEGER NOT NULL,
                    observed_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_network_interfaces_device_name
                ON network_interfaces(device_id, name);

                CREATE TABLE IF NOT EXISTS network_vlans (
                    record_id TEXT PRIMARY KEY,
                    snapshot_id TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    vlan_id INTEGER NOT NULL,
                    observed_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_network_vlans_device_vlan
                ON network_vlans(device_id, vlan_id);

                CREATE TABLE IF NOT EXISTS network_links (
                    link_id TEXT PRIMARY KEY,
                    snapshot_id TEXT NOT NULL,
                    device_a TEXT NOT NULL,
                    device_b TEXT NOT NULL,
                    status TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_network_links_devices
                ON network_links(device_a, device_b);

                CREATE TABLE IF NOT EXISTS network_routes (
                    route_id TEXT PRIMARY KEY,
                    snapshot_id TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    prefix TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    installed INTEGER NOT NULL,
                    observed_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_network_routes_device_prefix
                ON network_routes(device_id, prefix);

                CREATE TABLE IF NOT EXISTS network_policy_rules (
                    rule_id TEXT PRIMARY KEY,
                    snapshot_id TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    policy_type TEXT NOT NULL,
                    action TEXT NOT NULL,
                    priority INTEGER NOT NULL,
                    observed_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_network_policy_device_priority
                ON network_policy_rules(device_id, priority);

                CREATE TABLE IF NOT EXISTS flow_assessments (
                    assessment_id TEXT PRIMARY KEY,
                    flow_id TEXT NOT NULL,
                    capture_id TEXT NOT NULL,
                    target TEXT NOT NULL,
                    ingress_device_id TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_flow_assessments_target_time
                ON flow_assessments(target, timestamp);

                CREATE TABLE IF NOT EXISTS configuration_recommendations (
                    recommendation_id TEXT PRIMARY KEY,
                    assessment_id TEXT NOT NULL,
                    flow_id TEXT NOT NULL,
                    capture_id TEXT NOT NULL,
                    target TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    category TEXT NOT NULL,
                    status TEXT NOT NULL,
                    simulation_status TEXT NOT NULL,
                    generated_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_configuration_recommendations_target_time
                ON configuration_recommendations(target, generated_at);
                CREATE INDEX IF NOT EXISTS idx_configuration_recommendations_assessment
                ON configuration_recommendations(assessment_id);

                CREATE TABLE IF NOT EXISTS evidence_graphs (
                    graph_id TEXT PRIMARY KEY,
                    assessment_id TEXT NOT NULL,
                    flow_id TEXT NOT NULL,
                    generated_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_evidence_graphs_assessment_time
                ON evidence_graphs(assessment_id, generated_at);

                CREATE TABLE IF NOT EXISTS remediation_executions (
                    execution_id TEXT PRIMARY KEY,
                    recommendation_id TEXT NOT NULL,
                    assessment_id TEXT NOT NULL,
                    environment TEXT NOT NULL,
                    status TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_remediation_recommendation_time
                ON remediation_executions(recommendation_id, started_at);
                CREATE INDEX IF NOT EXISTS idx_remediation_status_time
                ON remediation_executions(status, started_at);

                CREATE TABLE IF NOT EXISTS experiments (
                    experiment_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_experiments_status_updated
                ON experiments(status, updated_at);

                CREATE TABLE IF NOT EXISTS experiment_trials (
                    trial_id TEXT PRIMARY KEY,
                    experiment_id TEXT NOT NULL,
                    scenario_id TEXT NOT NULL,
                    repetition INTEGER NOT NULL,
                    seed INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_experiment_trials_experiment_scenario
                ON experiment_trials(experiment_id, scenario_id, repetition);
                CREATE INDEX IF NOT EXISTS idx_experiment_trials_status_time
                ON experiment_trials(status, finished_at);
                """
            )
            self._migrate_capture_fingerprints(conn)

    @staticmethod
    def _capture_dedupe_key(target: str, source: str, sha256: str) -> str:
        if not sha256:
            return ""
        payload = f"{target}\0{source}\0{sha256}".encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def _migrate_capture_fingerprints(self, conn: sqlite3.Connection) -> None:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(capture_sessions)")}
        if "sha256" not in columns:
            conn.execute("ALTER TABLE capture_sessions ADD COLUMN sha256 TEXT NOT NULL DEFAULT ''")
        if "dedupe_key" not in columns:
            conn.execute("ALTER TABLE capture_sessions ADD COLUMN dedupe_key TEXT NOT NULL DEFAULT ''")

        rows = conn.execute(
            "SELECT capture_id, target, source, sha256, dedupe_key, payload "
            "FROM capture_sessions ORDER BY finished_at, capture_id"
        ).fetchall()
        used: set[str] = set()
        for row in rows:
            try:
                session = CaptureSession.from_dict(loads(row["payload"]))
            except (TypeError, ValueError):
                continue
            digest = row["sha256"] or session.sha256
            base = self._capture_dedupe_key(session.target, session.source, digest)
            key = row["dedupe_key"]
            if not key:
                key = base if base and base not in used else (f"legacy:{session.capture_id}" if base else "")
            if key:
                used.add(key)
            conn.execute(
                "UPDATE capture_sessions SET sha256=?, dedupe_key=? WHERE capture_id=?",
                (digest, key, session.capture_id),
            )
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_capture_sessions_dedupe "
            "ON capture_sessions(dedupe_key) WHERE dedupe_key <> ''"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_capture_sessions_fingerprint "
            "ON capture_sessions(target, source, sha256)"
        )

    def add_observation(self, obs: Observation) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO observations
                (observation_id, timestamp, target, source, domain, metric, value, unit, method, payload)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    obs.observation_id, obs.timestamp, obs.target, obs.source, obs.domain,
                    obs.metric, obs.value, obs.unit, obs.method, dumps(obs.to_dict()),
                ),
            )

    def add_observations(self, observations: Iterable[Observation]) -> int:
        items = list(observations)
        if not items:
            return 0
        rows = [
            (
                obs.observation_id, obs.timestamp, obs.target, obs.source, obs.domain,
                obs.metric, obs.value, obs.unit, obs.method, dumps(obs.to_dict()),
            )
            for obs in items
        ]
        with self.connect() as conn:
            conn.executemany(
                """
                INSERT OR REPLACE INTO observations
                (observation_id, timestamp, target, source, domain, metric, value, unit, method, payload)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
        return len(items)

    def latest_observations(self, target: str, limit: int = 50) -> List[Observation]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT payload FROM observations WHERE target = ? ORDER BY timestamp DESC LIMIT ?",
                (target, limit),
            ).fetchall()
        return [Observation.from_dict(loads(row["payload"])) for row in reversed(rows)]

    def list_observations(
        self,
        limit: int = 50,
        target: Optional[str] = None,
        metric: Optional[str] = None,
    ) -> List[Observation]:
        clauses: List[str] = []
        values: List[object] = []
        if target:
            clauses.append("target = ?")
            values.append(target)
        if metric:
            clauses.append("metric = ?")
            values.append(metric)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        values.append(limit)
        with self.connect() as conn:
            rows = conn.execute(
                f"SELECT payload FROM observations {where} ORDER BY timestamp DESC LIMIT ?",
                values,
            ).fetchall()
        return [Observation.from_dict(loads(row["payload"])) for row in rows]

    def list_targets(self, limit: int = 100) -> List[str]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT target, MAX(timestamp) AS latest
                FROM observations GROUP BY target ORDER BY latest DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [str(row["target"]) for row in rows]

    def add_collection_run(self, run: CollectionRun) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO collection_runs
                (run_id, started_at, finished_at, agent, target, source, returncode, payload)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run.run_id, run.started_at, run.finished_at, run.agent,
                    run.target, run.source, run.returncode, dumps(run.to_dict()),
                ),
            )

    def get_collection_run(self, run_id: str) -> Optional[CollectionRun]:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT payload FROM collection_runs WHERE run_id = ?", (run_id,)
            ).fetchone()
        return CollectionRun.from_dict(loads(row["payload"])) if row else None

    def list_collection_runs(self, limit: int = 50, target: Optional[str] = None) -> List[CollectionRun]:
        with self.connect() as conn:
            if target:
                rows = conn.execute(
                    "SELECT payload FROM collection_runs WHERE target = ? ORDER BY started_at DESC LIMIT ?",
                    (target, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT payload FROM collection_runs ORDER BY started_at DESC LIMIT ?", (limit,)
                ).fetchall()
        return [CollectionRun.from_dict(loads(row["payload"])) for row in rows]

    def add_state(self, state: StateEstimate) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO states
                (state_id, timestamp, target, state, control_mode, confidence, payload)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    state.state_id, state.timestamp, state.target, state.state,
                    state.control_mode, state.confidence, dumps(state.to_dict()),
                ),
            )

    def latest_state(self, target: str) -> Optional[StateEstimate]:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT payload FROM states WHERE target = ? ORDER BY timestamp DESC LIMIT 1",
                (target,),
            ).fetchone()
        return StateEstimate.from_dict(loads(row["payload"])) if row else None

    def get_state(self, state_id: str) -> Optional[StateEstimate]:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT payload FROM states WHERE state_id = ?", (state_id,)
            ).fetchone()
        return StateEstimate.from_dict(loads(row["payload"])) if row else None

    def list_states(self, limit: int = 50, target: Optional[str] = None) -> List[StateEstimate]:
        with self.connect() as conn:
            if target:
                rows = conn.execute(
                    "SELECT payload FROM states WHERE target = ? ORDER BY timestamp DESC LIMIT ?",
                    (target, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT payload FROM states ORDER BY timestamp DESC LIMIT ?", (limit,)
                ).fetchall()
        return [StateEstimate.from_dict(loads(row["payload"])) for row in rows]

    def add_proposal(self, proposal: ActionProposal) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO proposals
                (proposal_id, timestamp, target, action, risk_level, payload)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    proposal.proposal_id, proposal.timestamp, proposal.target,
                    proposal.action, proposal.risk_level, dumps(proposal.to_dict()),
                ),
            )

    def get_proposal(self, proposal_id: str) -> Optional[ActionProposal]:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT payload FROM proposals WHERE proposal_id = ?", (proposal_id,)
            ).fetchone()
        return ActionProposal.from_dict(loads(row["payload"])) if row else None

    def latest_proposal(self, target: str) -> Optional[ActionProposal]:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT payload FROM proposals WHERE target = ? ORDER BY timestamp DESC LIMIT 1",
                (target,),
            ).fetchone()
        return ActionProposal.from_dict(loads(row["payload"])) if row else None

    def list_proposals(self, limit: int = 50, target: Optional[str] = None) -> List[ActionProposal]:
        with self.connect() as conn:
            if target:
                rows = conn.execute(
                    "SELECT payload FROM proposals WHERE target = ? ORDER BY timestamp DESC LIMIT ?",
                    (target, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT payload FROM proposals ORDER BY timestamp DESC LIMIT ?", (limit,)
                ).fetchall()
        return [ActionProposal.from_dict(loads(row["payload"])) for row in rows]

    def add_guard_decision(self, decision: GuardDecision) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO guard_decisions
                (decision_id, timestamp, proposal_id, status, payload)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    decision.decision_id, decision.timestamp, decision.proposal_id,
                    decision.status, dumps(decision.to_dict()),
                ),
            )

    def get_guard_decision(self, decision_id: str) -> Optional[GuardDecision]:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT payload FROM guard_decisions WHERE decision_id = ?", (decision_id,)
            ).fetchone()
        return GuardDecision.from_dict(loads(row["payload"])) if row else None

    def latest_guard_decision(self, proposal_id: str) -> Optional[GuardDecision]:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT payload FROM guard_decisions WHERE proposal_id = ? ORDER BY timestamp DESC LIMIT 1",
                (proposal_id,),
            ).fetchone()
        return GuardDecision.from_dict(loads(row["payload"])) if row else None

    def list_guard_decisions(
        self, limit: int = 50, proposal_id: Optional[str] = None
    ) -> List[GuardDecision]:
        with self.connect() as conn:
            if proposal_id:
                rows = conn.execute(
                    "SELECT payload FROM guard_decisions WHERE proposal_id = ? ORDER BY timestamp DESC LIMIT ?",
                    (proposal_id, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT payload FROM guard_decisions ORDER BY timestamp DESC LIMIT ?",
                    (limit,),
                ).fetchall()
        return [GuardDecision.from_dict(loads(row["payload"])) for row in rows]

    def add_action_result(self, result: ActionResult) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO action_results
                (result_id, timestamp, proposal_id, status, returncode, payload)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    result.result_id, result.timestamp, result.proposal_id,
                    result.status, result.returncode, dumps(result.to_dict()),
                ),
            )

    def get_action_result(self, result_id: str) -> Optional[ActionResult]:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT payload FROM action_results WHERE result_id = ?", (result_id,)
            ).fetchone()
        return ActionResult.from_dict(loads(row["payload"])) if row else None

    def latest_action_result(self, proposal_id: str) -> Optional[ActionResult]:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT payload FROM action_results WHERE proposal_id = ? ORDER BY timestamp DESC LIMIT 1",
                (proposal_id,),
            ).fetchone()
        return ActionResult.from_dict(loads(row["payload"])) if row else None

    def list_action_results(
        self, limit: int = 50, proposal_id: Optional[str] = None
    ) -> List[ActionResult]:
        with self.connect() as conn:
            if proposal_id:
                rows = conn.execute(
                    "SELECT payload FROM action_results WHERE proposal_id = ? ORDER BY timestamp DESC LIMIT ?",
                    (proposal_id, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT payload FROM action_results ORDER BY timestamp DESC LIMIT ?", (limit,)
                ).fetchall()
        return [ActionResult.from_dict(loads(row["payload"])) for row in rows]

    def set_target_profile(self, profile: TargetProfile) -> None:
        profile.validate()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO target_profiles (target, updated_at, payload)
                VALUES (?, ?, ?)
                """,
                (profile.target, profile.updated_at, dumps(profile.to_dict())),
            )

    def get_target_profile(self, target: str) -> Optional[TargetProfile]:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT payload FROM target_profiles WHERE target = ?", (target,)
            ).fetchone()
        return TargetProfile.from_dict(loads(row["payload"])) if row else None

    def list_target_profiles(self, limit: int = 100) -> List[TargetProfile]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT payload FROM target_profiles ORDER BY updated_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [TargetProfile.from_dict(loads(row["payload"])) for row in rows]

    def delete_target_profile(self, target: str) -> bool:
        with self.connect() as conn:
            cursor = conn.execute("DELETE FROM target_profiles WHERE target = ?", (target,))
        return cursor.rowcount > 0

    def set_observation_plan(self, plan: ObservationPlan) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO observation_plans
                (target, updated_at, interval_sec, mode, payload)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    plan.target, plan.updated_at, plan.interval_sec, plan.mode,
                    dumps(plan.to_dict()),
                ),
            )

    def get_observation_plan(self, target: str) -> Optional[ObservationPlan]:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT payload FROM observation_plans WHERE target = ?", (target,)
            ).fetchone()
        return ObservationPlan.from_dict(loads(row["payload"])) if row else None
    def set_safety_policy(self, policy: SafetyPolicy) -> None:
        policy.validate()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO safety_policies
                (target, updated_at, policy_id, payload)
                VALUES (?, ?, ?, ?)
                """,
                (policy.target, policy.updated_at, policy.policy_id, dumps(policy.to_dict())),
            )

    def get_safety_policy(self, target: str) -> Optional[SafetyPolicy]:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT payload FROM safety_policies WHERE target = ?", (target,)
            ).fetchone()
            if not row and target != "*":
                row = conn.execute(
                    "SELECT payload FROM safety_policies WHERE target = '*'"
                ).fetchone()
        return SafetyPolicy.from_dict(loads(row["payload"])) if row else None

    def list_safety_policies(self, limit: int = 100) -> List[SafetyPolicy]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT payload FROM safety_policies ORDER BY updated_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [SafetyPolicy.from_dict(loads(row["payload"])) for row in rows]

    def delete_safety_policy(self, target: str) -> bool:
        with self.connect() as conn:
            cursor = conn.execute("DELETE FROM safety_policies WHERE target = ?", (target,))
        return cursor.rowcount > 0

    def add_approval(self, approval: ApprovalRecord) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO approvals
                (approval_id, timestamp, proposal_id, status, actor, payload)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    approval.approval_id, approval.timestamp, approval.proposal_id,
                    approval.status, approval.actor, dumps(approval.to_dict()),
                ),
            )

    def get_approval(self, approval_id: str) -> Optional[ApprovalRecord]:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT payload FROM approvals WHERE approval_id = ?", (approval_id,)
            ).fetchone()
        return ApprovalRecord.from_dict(loads(row["payload"])) if row else None

    def latest_approval(self, proposal_id: str) -> Optional[ApprovalRecord]:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT payload FROM approvals WHERE proposal_id = ? ORDER BY timestamp DESC LIMIT 1",
                (proposal_id,),
            ).fetchone()
        return ApprovalRecord.from_dict(loads(row["payload"])) if row else None

    def list_approvals(self, limit: int = 50, proposal_id: Optional[str] = None) -> List[ApprovalRecord]:
        with self.connect() as conn:
            if proposal_id:
                rows = conn.execute(
                    "SELECT payload FROM approvals WHERE proposal_id = ? ORDER BY timestamp DESC LIMIT ?",
                    (proposal_id, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT payload FROM approvals ORDER BY timestamp DESC LIMIT ?", (limit,)
                ).fetchall()
        return [ApprovalRecord.from_dict(loads(row["payload"])) for row in rows]

    def add_verification(self, verification: VerificationResult) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO verifications
                (verification_id, timestamp, proposal_id, action_result_id, status, payload)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    verification.verification_id, verification.timestamp,
                    verification.proposal_id, verification.action_result_id,
                    verification.status, dumps(verification.to_dict()),
                ),
            )

    def get_verification(self, verification_id: str) -> Optional[VerificationResult]:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT payload FROM verifications WHERE verification_id = ?",
                (verification_id,),
            ).fetchone()
        return VerificationResult.from_dict(loads(row["payload"])) if row else None

    def latest_verification(self, proposal_id: str) -> Optional[VerificationResult]:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT payload FROM verifications WHERE proposal_id = ? ORDER BY timestamp DESC LIMIT 1",
                (proposal_id,),
            ).fetchone()
        return VerificationResult.from_dict(loads(row["payload"])) if row else None

    def list_verifications(self, limit: int = 50, proposal_id: Optional[str] = None) -> List[VerificationResult]:
        with self.connect() as conn:
            if proposal_id:
                rows = conn.execute(
                    "SELECT payload FROM verifications WHERE proposal_id = ? ORDER BY timestamp DESC LIMIT ?",
                    (proposal_id, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT payload FROM verifications ORDER BY timestamp DESC LIMIT ?", (limit,)
                ).fetchall()
        return [VerificationResult.from_dict(loads(row["payload"])) for row in rows]

    def add_control_transaction(self, transaction: ControlTransaction) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO control_transactions
                (transaction_id, timestamp, target, proposal_id, outcome, payload)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    transaction.transaction_id, transaction.timestamp, transaction.target,
                    transaction.proposal_id, transaction.outcome, dumps(transaction.to_dict()),
                ),
            )

    def latest_control_transaction(self, target: str) -> Optional[ControlTransaction]:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT payload FROM control_transactions WHERE target = ? ORDER BY timestamp DESC LIMIT 1",
                (target,),
            ).fetchone()
        return ControlTransaction.from_dict(loads(row["payload"])) if row else None

    def list_control_transactions(
        self, limit: int = 50, target: Optional[str] = None
    ) -> List[ControlTransaction]:
        with self.connect() as conn:
            if target:
                rows = conn.execute(
                    "SELECT payload FROM control_transactions WHERE target = ? ORDER BY timestamp DESC LIMIT ?",
                    (target, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT payload FROM control_transactions ORDER BY timestamp DESC LIMIT ?",
                    (limit,),
                ).fetchall()
        return [ControlTransaction.from_dict(loads(row["payload"])) for row in rows]

    # v0.5 managed target inventory and persistent observation service
    def set_managed_target(self, target: ManagedTarget) -> None:
        target.validate()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO managed_targets
                (target, target_id, enabled, updated_at, payload)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    target.target,
                    target.target_id,
                    1 if target.enabled else 0,
                    target.updated_at,
                    dumps(target.to_dict()),
                ),
            )

    def get_managed_target(self, target: str) -> Optional[ManagedTarget]:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT payload FROM managed_targets WHERE target = ?", (target,)
            ).fetchone()
        return ManagedTarget.from_dict(loads(row["payload"])) if row else None

    def list_managed_targets(
        self, limit: int = 100, enabled_only: bool = False
    ) -> List[ManagedTarget]:
        with self.connect() as conn:
            if enabled_only:
                rows = conn.execute(
                    "SELECT payload FROM managed_targets WHERE enabled = 1 "
                    "ORDER BY updated_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT payload FROM managed_targets ORDER BY updated_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
        return [ManagedTarget.from_dict(loads(row["payload"])) for row in rows]

    def delete_managed_target(self, target: str) -> bool:
        with self.connect() as conn:
            cursor = conn.execute("DELETE FROM managed_targets WHERE target = ?", (target,))
        return cursor.rowcount > 0

    def add_scheduler_cycle(self, cycle: SchedulerCycle) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO scheduler_cycles
                (cycle_id, target, owner_id, status, started_at, finished_at, payload)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    cycle.cycle_id,
                    cycle.target,
                    cycle.owner_id,
                    cycle.status,
                    cycle.started_at,
                    cycle.finished_at,
                    dumps(cycle.to_dict()),
                ),
            )

    def get_scheduler_cycle(self, cycle_id: str) -> Optional[SchedulerCycle]:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT payload FROM scheduler_cycles WHERE cycle_id = ?", (cycle_id,)
            ).fetchone()
        return SchedulerCycle.from_dict(loads(row["payload"])) if row else None

    def latest_scheduler_cycle(self, target: str) -> Optional[SchedulerCycle]:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT payload FROM scheduler_cycles WHERE target = ? "
                "ORDER BY finished_at DESC LIMIT 1",
                (target,),
            ).fetchone()
        return SchedulerCycle.from_dict(loads(row["payload"])) if row else None

    def list_scheduler_cycles(
        self, limit: int = 50, target: Optional[str] = None
    ) -> List[SchedulerCycle]:
        with self.connect() as conn:
            if target:
                rows = conn.execute(
                    "SELECT payload FROM scheduler_cycles WHERE target = ? "
                    "ORDER BY finished_at DESC LIMIT ?",
                    (target, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT payload FROM scheduler_cycles ORDER BY finished_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
        return [SchedulerCycle.from_dict(loads(row["payload"])) for row in rows]

    def count_scheduler_cycles(self, target: str) -> int:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS count FROM scheduler_cycles WHERE target = ?",
                (target,),
            ).fetchone()
        return int(row["count"])

    def acquire_scheduler_lease(self, name: str, owner_id: str, ttl_sec: int = 120) -> bool:
        if ttl_sec < 1:
            raise ValueError("ttl_sec must be >= 1")
        now = datetime.now(timezone.utc)
        expires = now + timedelta(seconds=ttl_sec)
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT payload FROM scheduler_leases WHERE name = ?", (name,)
            ).fetchone()
            if row:
                existing = SchedulerLease.from_dict(loads(row["payload"]))
                expiry = parse_time(existing.expires_at)
                if existing.owner_id != owner_id and expiry and expiry > now:
                    conn.rollback()
                    return False
            lease = SchedulerLease(
                name=name,
                owner_id=owner_id,
                acquired_at=now.isoformat(),
                expires_at=expires.isoformat(),
            )
            conn.execute(
                """
                INSERT OR REPLACE INTO scheduler_leases
                (name, owner_id, acquired_at, expires_at, payload)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    lease.name,
                    lease.owner_id,
                    lease.acquired_at,
                    lease.expires_at,
                    dumps(lease.to_dict()),
                ),
            )
            conn.commit()
        return True

    def get_scheduler_lease(self, name: str) -> Optional[SchedulerLease]:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT payload FROM scheduler_leases WHERE name = ?", (name,)
            ).fetchone()
        return SchedulerLease.from_dict(loads(row["payload"])) if row else None

    def release_scheduler_lease(self, name: str, owner_id: str, force: bool = False) -> bool:
        with self.connect() as conn:
            if force:
                cursor = conn.execute(
                    "DELETE FROM scheduler_leases WHERE name = ?", (name,)
                )
            else:
                cursor = conn.execute(
                    "DELETE FROM scheduler_leases WHERE name = ? AND owner_id = ?",
                    (name, owner_id),
                )
        return cursor.rowcount > 0

    def find_capture_session_by_fingerprint(
        self, *, target: str, source: str, sha256: str
    ) -> Optional[CaptureSession]:
        if not sha256:
            return None
        base_key = self._capture_dedupe_key(target, source, sha256)
        with self.connect() as conn:
            row = conn.execute(
                "SELECT payload FROM capture_sessions WHERE dedupe_key=? LIMIT 1",
                (base_key,),
            ).fetchone()
            if not row:
                row = conn.execute(
                    "SELECT payload FROM capture_sessions "
                    "WHERE target=? AND source=? AND sha256=? "
                    "ORDER BY finished_at, capture_id LIMIT 1",
                    (target, source, sha256),
                ).fetchone()
        return CaptureSession.from_dict(loads(row["payload"])) if row else None

    def add_capture_session(
        self, session: CaptureSession, *, force_reimport: bool = False
    ) -> bool:
        session.validate()
        base_key = self._capture_dedupe_key(session.target, session.source, session.sha256)
        with self.connect() as conn:
            current = conn.execute(
                "SELECT dedupe_key FROM capture_sessions WHERE capture_id=?",
                (session.capture_id,),
            ).fetchone()
            if current:
                dedupe_key = current["dedupe_key"] or base_key
            else:
                dedupe_key = (
                    f"{base_key}:force:{session.capture_id}"
                    if force_reimport and base_key
                    else base_key
                )
                if base_key and not force_reimport:
                    existing = conn.execute(
                        "SELECT capture_id FROM capture_sessions "
                        "WHERE dedupe_key=? LIMIT 1",
                        (base_key,),
                    ).fetchone()
                    if existing:
                        return False
            conn.execute(
                """INSERT OR REPLACE INTO capture_sessions
                (capture_id, target, source, started_at, finished_at, status, packet_count,
                 flow_count, file_size, storage_scope, sha256, dedupe_key, payload)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (session.capture_id, session.target, session.source, session.started_at,
                 session.finished_at, session.status, session.packet_count, session.flow_count,
                 session.file_size, session.storage_scope, session.sha256, dedupe_key,
                 dumps(session.to_dict())),
            )
        return True

    def get_capture_session(self, capture_id: str) -> Optional[CaptureSession]:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT payload FROM capture_sessions WHERE capture_id=?", (capture_id,)
            ).fetchone()
        return CaptureSession.from_dict(loads(row["payload"])) if row else None

    def list_capture_sessions(
        self, limit: int = 100, target: Optional[str] = None
    ) -> List[CaptureSession]:
        sql = "SELECT payload FROM capture_sessions"
        params: list[object] = []
        if target:
            sql += " WHERE target=?"
            params.append(target)
        sql += " ORDER BY finished_at DESC LIMIT ?"
        params.append(limit)
        with self.connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [CaptureSession.from_dict(loads(row["payload"])) for row in rows]

    def delete_capture_session(self, capture_id: str, *, delete_flows: bool = True) -> bool:
        with self.connect() as conn:
            if delete_flows:
                conn.execute("DELETE FROM flow_records WHERE capture_id=?", (capture_id,))
            cur = conn.execute("DELETE FROM capture_sessions WHERE capture_id=?", (capture_id,))
        return bool(cur.rowcount)

    def add_flow_records(self, flows: Iterable[FlowRecord]) -> int:
        items = list(flows)
        if not items:
            return 0
        with self.connect() as conn:
            conn.executemany(
                """INSERT OR REPLACE INTO flow_records
                (flow_id, capture_id, target, protocol, src_ip, dst_ip, wire_bytes, packets,
                 first_seen, last_seen, payload)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [(item.flow_id, item.capture_id, item.target, item.protocol, item.src_ip,
                  item.dst_ip, item.wire_bytes, item.packets, item.first_seen, item.last_seen,
                  dumps(item.to_dict())) for item in items],
            )
        return len(items)

    def list_flow_records(
        self, limit: int = 100, *, target: Optional[str] = None, capture_id: Optional[str] = None
    ) -> List[FlowRecord]:
        clauses: list[str] = []
        params: list[object] = []
        if target:
            clauses.append("target=?")
            params.append(target)
        if capture_id:
            clauses.append("capture_id=?")
            params.append(capture_id)
        sql = "SELECT payload FROM flow_records"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY wire_bytes DESC, packets DESC LIMIT ?"
        params.append(limit)
        with self.connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [FlowRecord.from_dict(loads(row["payload"])) for row in rows]

    def get_flow_record(self, flow_id: str) -> Optional[FlowRecord]:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT payload FROM flow_records WHERE flow_id=?", (flow_id,)
            ).fetchone()
        return FlowRecord.from_dict(loads(row["payload"])) if row else None

    def set_remote_agent(self, agent: RemoteAgentRegistration) -> None:
        agent.validate()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO remote_agents
                (agent_id, name, enabled, token_fingerprint, created_at, updated_at, last_seen_at, payload)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(agent_id) DO UPDATE SET
                    name=excluded.name, enabled=excluded.enabled,
                    token_fingerprint=excluded.token_fingerprint,
                    updated_at=excluded.updated_at, last_seen_at=excluded.last_seen_at,
                    payload=excluded.payload
                """,
                (
                    agent.agent_id, agent.name, int(agent.enabled), agent.token_fingerprint,
                    agent.created_at, agent.updated_at, agent.last_seen_at,
                    dumps(agent.to_storage_dict()),
                ),
            )

    def get_remote_agent(self, agent_id: str) -> Optional[RemoteAgentRegistration]:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT payload FROM remote_agents WHERE agent_id = ?", (agent_id,)
            ).fetchone()
        return RemoteAgentRegistration.from_storage_dict(loads(row["payload"])) if row else None

    def list_remote_agents(self, limit: int = 100, enabled_only: bool = False) -> List[RemoteAgentRegistration]:
        sql = "SELECT payload FROM remote_agents"
        params: list[object] = []
        if enabled_only:
            sql += " WHERE enabled = 1"
        sql += " ORDER BY updated_at DESC LIMIT ?"
        params.append(limit)
        with self.connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [RemoteAgentRegistration.from_storage_dict(loads(row["payload"])) for row in rows]

    def delete_remote_agent(self, agent_id: str) -> bool:
        with self.connect() as conn:
            cur = conn.execute("DELETE FROM remote_agents WHERE agent_id = ?", (agent_id,))
        return bool(cur.rowcount)

    def add_agent_heartbeat(self, heartbeat: AgentHeartbeat) -> None:
        heartbeat.validate()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO agent_heartbeats
                (heartbeat_id, timestamp, agent_id, status, queue_depth, payload)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (heartbeat.heartbeat_id, heartbeat.timestamp, heartbeat.agent_id,
                 heartbeat.status, heartbeat.queue_depth, dumps(heartbeat.to_dict())),
            )
            row = conn.execute(
                "SELECT payload FROM remote_agents WHERE agent_id = ?",
                (heartbeat.agent_id,),
            ).fetchone()
            if row:
                agent = RemoteAgentRegistration.from_storage_dict(loads(row["payload"]))
                agent = agent.updated(last_seen_at=heartbeat.timestamp)
                conn.execute(
                    """
                    UPDATE remote_agents SET updated_at=?, last_seen_at=?, payload=?
                    WHERE agent_id=?
                    """,
                    (agent.updated_at, agent.last_seen_at, dumps(agent.to_storage_dict()), agent.agent_id),
                )

    def latest_agent_heartbeat(self, agent_id: str) -> Optional[AgentHeartbeat]:
        with self.connect() as conn:
            row = conn.execute(
                """SELECT payload FROM agent_heartbeats
                WHERE agent_id=? ORDER BY timestamp DESC LIMIT 1""",
                (agent_id,),
            ).fetchone()
        return AgentHeartbeat.from_dict(loads(row["payload"])) if row else None

    def list_agent_heartbeats(self, limit: int = 100, agent_id: Optional[str] = None) -> List[AgentHeartbeat]:
        sql = "SELECT payload FROM agent_heartbeats"
        params: list[object] = []
        if agent_id:
            sql += " WHERE agent_id=?"
            params.append(agent_id)
        sql += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        with self.connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [AgentHeartbeat.from_dict(loads(row["payload"])) for row in rows]

    def get_ingest_receipt(self, batch_id: str) -> Optional[IngestReceipt]:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT payload FROM ingest_batches WHERE batch_id=?", (batch_id,)
            ).fetchone()
        return IngestReceipt.from_dict(loads(row["payload"])) if row else None

    def list_ingest_receipts(self, limit: int = 100, agent_id: Optional[str] = None) -> List[IngestReceipt]:
        sql = "SELECT payload FROM ingest_batches"
        params: list[object] = []
        if agent_id:
            sql += " WHERE agent_id=?"
            params.append(agent_id)
        sql += " ORDER BY received_at DESC LIMIT ?"
        params.append(limit)
        with self.connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [IngestReceipt.from_dict(loads(row["payload"])) for row in rows]

    def ingest_remote_batch(self, batch: IngestBatch) -> IngestReceipt:
        batch.validate()
        observations = batch.parsed_observations()
        runs = batch.parsed_runs()
        captures = batch.parsed_captures()
        flows = batch.parsed_flows()
        for obs in observations:
            obs.labels = {**obs.labels, "remote_agent_id": batch.agent_id, "batch_id": batch.batch_id}
        for run in runs:
            run.metadata = {**run.metadata, "remote_agent_id": batch.agent_id, "batch_id": batch.batch_id}
        for capture in captures:
            capture.metadata = {**capture.metadata, "remote_agent_id": batch.agent_id, "batch_id": batch.batch_id}
            capture.storage_scope = "edge"
        for flow in flows:
            flow.metadata = {**flow.metadata, "remote_agent_id": batch.agent_id, "batch_id": batch.batch_id}
        targets = batch.targets()
        with self.connect() as conn:
            existing = conn.execute(
                "SELECT payload FROM ingest_batches WHERE batch_id=?", (batch.batch_id,)
            ).fetchone()
            if existing:
                prior = IngestReceipt.from_dict(loads(existing["payload"]))
                return IngestReceipt(
                    batch_id=prior.batch_id, agent_id=prior.agent_id, status="DUPLICATE",
                    observation_count=prior.observation_count, run_count=prior.run_count,
                    capture_count=prior.capture_count, flow_count=prior.flow_count,
                    targets=prior.targets, duplicate=True, message="batch was already accepted",
                    received_at=prior.received_at, receipt_id=prior.receipt_id,
                )
            duplicate_capture_ids: set[str] = set()
            accepted_captures: list[CaptureSession] = []
            for capture in captures:
                existing_capture = conn.execute(
                    "SELECT capture_id FROM capture_sessions "
                    "WHERE target=? AND source=? AND sha256=? LIMIT 1",
                    (capture.target, capture.source, capture.sha256),
                ).fetchone() if capture.sha256 else None
                if existing_capture and existing_capture["capture_id"] != capture.capture_id:
                    duplicate_capture_ids.add(capture.capture_id)
                else:
                    accepted_captures.append(capture)

            accepted_observations = [
                obs for obs in observations
                if str(obs.labels.get("capture_id", "")) not in duplicate_capture_ids
            ]
            accepted_flows = [
                flow for flow in flows if flow.capture_id not in duplicate_capture_ids
            ]

            for run in runs:
                conn.execute(
                    """INSERT OR IGNORE INTO collection_runs
                    (run_id, started_at, finished_at, agent, target, source, returncode, payload)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (run.run_id, run.started_at, run.finished_at, run.agent, run.target,
                     run.source, run.returncode, dumps(run.to_dict())),
                )
            for obs in accepted_observations:
                conn.execute(
                    """INSERT OR IGNORE INTO observations
                    (observation_id, timestamp, target, source, domain, metric, value, unit, method, payload)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (obs.observation_id, obs.timestamp, obs.target, obs.source, obs.domain,
                     obs.metric, obs.value, obs.unit, obs.method, dumps(obs.to_dict())),
                )
            for capture in accepted_captures:
                dedupe_key = self._capture_dedupe_key(
                    capture.target, capture.source, capture.sha256
                )
                conn.execute(
                    """INSERT OR IGNORE INTO capture_sessions
                    (capture_id, target, source, started_at, finished_at, status, packet_count,
                     flow_count, file_size, storage_scope, sha256, dedupe_key, payload)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (capture.capture_id, capture.target, capture.source, capture.started_at,
                     capture.finished_at, capture.status, capture.packet_count, capture.flow_count,
                     capture.file_size, capture.storage_scope, capture.sha256, dedupe_key,
                     dumps(capture.to_dict())),
                )
            for flow in accepted_flows:
                conn.execute(
                    """INSERT OR IGNORE INTO flow_records
                    (flow_id, capture_id, target, protocol, src_ip, dst_ip, wire_bytes, packets,
                     first_seen, last_seen, payload)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (flow.flow_id, flow.capture_id, flow.target, flow.protocol, flow.src_ip,
                     flow.dst_ip, flow.wire_bytes, flow.packets, flow.first_seen, flow.last_seen,
                     dumps(flow.to_dict())),
                )
            duplicate_count = len(duplicate_capture_ids)
            receipt = IngestReceipt(
                batch_id=batch.batch_id, agent_id=batch.agent_id, status="ACCEPTED",
                observation_count=len(accepted_observations), run_count=len(runs),
                capture_count=len(accepted_captures), flow_count=len(accepted_flows), targets=targets,
                message=(
                    f"remote observation batch accepted; skipped {duplicate_count} duplicate capture(s)"
                    if duplicate_count
                    else "remote observation batch accepted"
                ),
            )
            conn.execute(
                """INSERT INTO ingest_batches
                (batch_id, receipt_id, received_at, agent_id, status, observation_count, run_count, payload)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (receipt.batch_id, receipt.receipt_id, receipt.received_at, receipt.agent_id,
                 receipt.status, receipt.observation_count, receipt.run_count, dumps(receipt.to_dict())),
            )
            row = conn.execute(
                "SELECT payload FROM remote_agents WHERE agent_id=?", (batch.agent_id,)
            ).fetchone()
            if row:
                agent = RemoteAgentRegistration.from_storage_dict(loads(row["payload"]))
                agent = agent.updated(last_seen_at=receipt.received_at)
                conn.execute(
                    "UPDATE remote_agents SET updated_at=?, last_seen_at=?, payload=? WHERE agent_id=?",
                    (agent.updated_at, agent.last_seen_at, dumps(agent.to_storage_dict()), agent.agent_id),
                )
        return receipt

    # v0.8 network-state model -------------------------------------------------
    def set_network_device(self, device: NetworkDevice) -> None:
        device.validate()
        with self.connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO network_devices
                (device_id, name, device_type, platform, enabled, updated_at, payload)
                VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (device.device_id, device.name, device.device_type, device.platform,
                 int(device.enabled), device.updated_at, dumps(device.to_dict())),
            )

    def get_network_device(self, device_id: str) -> Optional[NetworkDevice]:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT payload FROM network_devices WHERE device_id=?", (device_id,)
            ).fetchone()
        return NetworkDevice.from_dict(loads(row["payload"])) if row else None

    def list_network_devices(self, limit: int = 200, enabled_only: bool = False) -> List[NetworkDevice]:
        where = "WHERE enabled=1" if enabled_only else ""
        with self.connect() as conn:
            rows = conn.execute(
                f"SELECT payload FROM network_devices {where} ORDER BY name LIMIT ?", (limit,)
            ).fetchall()
        return [NetworkDevice.from_dict(loads(row["payload"])) for row in rows]

    def delete_network_device(self, device_id: str) -> bool:
        with self.connect() as conn:
            result = conn.execute("DELETE FROM network_devices WHERE device_id=?", (device_id,))
        return result.rowcount > 0

    def add_network_snapshot(
        self, snapshot: NetworkSnapshot, *, interfaces: Iterable[NetworkInterface] = (),
        vlans: Iterable[VlanRecord] = (), links: Iterable[L2Link] = (),
        routes: Iterable[RouteEntry] = (), policies: Iterable[PolicyRule] = (),
    ) -> None:
        interfaces, vlans, links, routes, policies = map(list, (interfaces, vlans, links, routes, policies))
        with self.connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO network_snapshots
                (snapshot_id, device_id, collector, source, status, finished_at, raw_sha256, payload)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (snapshot.snapshot_id, snapshot.device_id, snapshot.collector, snapshot.source,
                 snapshot.status, snapshot.finished_at, snapshot.raw_sha256, dumps(snapshot.to_dict())),
            )
            for item in interfaces:
                conn.execute(
                    """INSERT OR REPLACE INTO network_interfaces
                    (interface_id, snapshot_id, device_id, name, oper_up, observed_at, payload)
                    VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (item.interface_id, snapshot.snapshot_id, item.device_id, item.name,
                     int(item.oper_up), item.observed_at, dumps(item.to_dict())),
                )
            for item in vlans:
                conn.execute(
                    """INSERT OR REPLACE INTO network_vlans
                    (record_id, snapshot_id, device_id, vlan_id, observed_at, payload)
                    VALUES (?, ?, ?, ?, ?, ?)""",
                    (item.record_id, snapshot.snapshot_id, item.device_id, item.vlan_id,
                     item.observed_at, dumps(item.to_dict())),
                )
            for item in links:
                conn.execute(
                    """INSERT OR REPLACE INTO network_links
                    (link_id, snapshot_id, device_a, device_b, status, observed_at, payload)
                    VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (item.link_id, snapshot.snapshot_id, item.device_a, item.device_b, item.status,
                     item.observed_at, dumps(item.to_dict())),
                )
            for item in routes:
                conn.execute(
                    """INSERT OR REPLACE INTO network_routes
                    (route_id, snapshot_id, device_id, prefix, protocol, installed, observed_at, payload)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (item.route_id, snapshot.snapshot_id, item.device_id, item.prefix, item.protocol,
                     int(item.installed), item.observed_at, dumps(item.to_dict())),
                )
            for item in policies:
                conn.execute(
                    """INSERT OR REPLACE INTO network_policy_rules
                    (rule_id, snapshot_id, device_id, policy_type, action, priority, observed_at, payload)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (item.rule_id, snapshot.snapshot_id, item.device_id, item.policy_type, item.action,
                     item.priority, item.observed_at, dumps(item.to_dict())),
                )

    def list_network_snapshots(self, limit: int = 100, device_id: Optional[str] = None) -> List[NetworkSnapshot]:
        where, values = ("WHERE device_id=?", [device_id]) if device_id else ("", [])
        values.append(limit)
        with self.connect() as conn:
            rows = conn.execute(
                f"SELECT payload FROM network_snapshots {where} ORDER BY finished_at DESC LIMIT ?", values
            ).fetchall()
        return [NetworkSnapshot.from_dict(loads(row["payload"])) for row in rows]

    def get_network_snapshot(self, snapshot_id: str) -> Optional[NetworkSnapshot]:
        with self.connect() as conn:
            row = conn.execute("SELECT payload FROM network_snapshots WHERE snapshot_id=?", (snapshot_id,)).fetchone()
        return NetworkSnapshot.from_dict(loads(row["payload"])) if row else None

    def _list_network_entities(self, table: str, cls, *, device_id: Optional[str] = None, snapshot_id: Optional[str] = None, limit: int = 1000):
        clauses, values = [], []
        if device_id:
            clauses.append("device_id=?"); values.append(device_id)
        if snapshot_id:
            clauses.append("snapshot_id=?"); values.append(snapshot_id)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        values.append(limit)
        with self.connect() as conn:
            rows = conn.execute(f"SELECT payload FROM {table} {where} ORDER BY rowid DESC LIMIT ?", values).fetchall()
        return [cls.from_dict(loads(row["payload"])) for row in rows]

    def list_network_interfaces(self, *, device_id: Optional[str] = None, snapshot_id: Optional[str] = None, limit: int = 1000) -> List[NetworkInterface]:
        return self._list_network_entities("network_interfaces", NetworkInterface, device_id=device_id, snapshot_id=snapshot_id, limit=limit)

    def list_network_vlans(self, *, device_id: Optional[str] = None, snapshot_id: Optional[str] = None, limit: int = 1000) -> List[VlanRecord]:
        return self._list_network_entities("network_vlans", VlanRecord, device_id=device_id, snapshot_id=snapshot_id, limit=limit)

    def list_network_links(self, *, device_id: Optional[str] = None, snapshot_id: Optional[str] = None, limit: int = 1000) -> List[L2Link]:
        if device_id and not snapshot_id:
            with self.connect() as conn:
                rows = conn.execute(
                    "SELECT payload FROM network_links WHERE device_a=? OR device_b=? ORDER BY rowid DESC LIMIT ?",
                    (device_id, device_id, limit),
                ).fetchall()
            return [L2Link.from_dict(loads(row["payload"])) for row in rows]
        return self._list_network_entities("network_links", L2Link, device_id=None, snapshot_id=snapshot_id, limit=limit)

    def list_network_routes(self, *, device_id: Optional[str] = None, snapshot_id: Optional[str] = None, limit: int = 5000) -> List[RouteEntry]:
        return self._list_network_entities("network_routes", RouteEntry, device_id=device_id, snapshot_id=snapshot_id, limit=limit)

    def list_network_policies(self, *, device_id: Optional[str] = None, snapshot_id: Optional[str] = None, limit: int = 5000) -> List[PolicyRule]:
        return self._list_network_entities("network_policy_rules", PolicyRule, device_id=device_id, snapshot_id=snapshot_id, limit=limit)

    def add_flow_assessments(self, assessments: Iterable[FlowAssessment]) -> int:
        items = list(assessments)
        with self.connect() as conn:
            for item in items:
                conn.execute(
                    """INSERT OR REPLACE INTO flow_assessments
                    (assessment_id, flow_id, capture_id, target, ingress_device_id, verdict, timestamp, payload)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (item.assessment_id, item.flow_id, item.capture_id, item.target,
                     item.ingress_device_id, item.verdict, item.timestamp, dumps(item.to_dict())),
                )
        return len(items)

    def list_flow_assessments(self, *, target: Optional[str] = None, capture_id: Optional[str] = None, ingress_device_id: Optional[str] = None, limit: int = 500) -> List[FlowAssessment]:
        clauses, values = [], []
        for column, value in (("target", target), ("capture_id", capture_id), ("ingress_device_id", ingress_device_id)):
            if value:
                clauses.append(f"{column}=?"); values.append(value)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        values.append(limit)
        with self.connect() as conn:
            rows = conn.execute(
                f"SELECT payload FROM flow_assessments {where} ORDER BY timestamp DESC LIMIT ?", values
            ).fetchall()
        return [FlowAssessment.from_dict(loads(row["payload"])) for row in rows]

    def get_flow_assessment(self, assessment_id: str) -> Optional[FlowAssessment]:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT payload FROM flow_assessments WHERE assessment_id=?",
                (assessment_id,),
            ).fetchone()
        return FlowAssessment.from_dict(loads(row["payload"])) if row else None

    # v0.9 configuration recommendations -------------------------------------
    def add_configuration_recommendations(
        self, recommendations: Iterable[ConfigurationRecommendation]
    ) -> int:
        items = list(recommendations)
        with self.connect() as conn:
            for item in items:
                item.validate()
                conn.execute(
                    """INSERT OR REPLACE INTO configuration_recommendations
                    (recommendation_id, assessment_id, flow_id, capture_id, target,
                     device_id, category, status, simulation_status, generated_at, payload)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        item.recommendation_id, item.assessment_id, item.flow_id,
                        item.capture_id, item.target, item.device_id, item.category,
                        item.status, item.simulation_status, item.generated_at,
                        dumps(item.to_dict()),
                    ),
                )
        return len(items)

    def get_configuration_recommendation(
        self, recommendation_id: str
    ) -> Optional[ConfigurationRecommendation]:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT payload FROM configuration_recommendations WHERE recommendation_id=?",
                (recommendation_id,),
            ).fetchone()
        return ConfigurationRecommendation.from_dict(loads(row["payload"])) if row else None

    def list_configuration_recommendations(
        self, *, target: Optional[str] = None, assessment_id: Optional[str] = None,
        category: Optional[str] = None, status: Optional[str] = None, limit: int = 500,
    ) -> List[ConfigurationRecommendation]:
        clauses: list[str] = []
        values: list[object] = []
        for column, value in (("target", target), ("assessment_id", assessment_id),
                              ("category", category), ("status", status)):
            if value:
                clauses.append(f"{column}=?")
                values.append(value)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        values.append(limit)
        with self.connect() as conn:
            rows = conn.execute(
                f"SELECT payload FROM configuration_recommendations {where} "
                "ORDER BY generated_at DESC LIMIT ?",
                values,
            ).fetchall()
        return [ConfigurationRecommendation.from_dict(loads(row["payload"])) for row in rows]

    def set_configuration_recommendation_status(
        self,
        recommendation_id: str,
        status: str,
        *,
        reviewed_by: str,
        note: str = "",
    ) -> ConfigurationRecommendation:
        item = self.get_configuration_recommendation(recommendation_id)
        if item is None:
            raise ValueError(f"configuration recommendation not found: {recommendation_id}")
        if status not in {"REVIEWED", "REJECTED", "APPROVED"}:
            raise ValueError(f"unsupported review status: {status}")
        if not reviewed_by.strip():
            raise ValueError("reviewed_by is required")
        if status == "APPROVED":
            require_approval_eligible(item)
        item.status = status
        history = list(item.metadata.get("review_history") or [])
        history.append({
            "status": status,
            "reviewed_by": reviewed_by,
            "note": note,
            "timestamp": utc_now(),
        })
        item.metadata = {**item.metadata, "review_history": history}
        item.validate()
        self.add_configuration_recommendations([item])
        return item

    # v0.10 evidence graphs and virtual-lab remediation ----------------------
    def add_evidence_graphs(self, graphs: Iterable[EvidenceGraph]) -> int:
        items = list(graphs)
        with self.connect() as conn:
            for item in items:
                item.validate()
                conn.execute(
                    """INSERT OR REPLACE INTO evidence_graphs
                    (graph_id, assessment_id, flow_id, generated_at, payload)
                    VALUES (?, ?, ?, ?, ?)""",
                    (
                        item.graph_id, item.assessment_id, item.flow_id,
                        item.generated_at, dumps(item.to_dict()),
                    ),
                )
        return len(items)

    def get_evidence_graph(self, graph_id: str) -> Optional[EvidenceGraph]:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT payload FROM evidence_graphs WHERE graph_id=?", (graph_id,),
            ).fetchone()
        return EvidenceGraph.from_dict(loads(row["payload"])) if row else None

    def list_evidence_graphs(
        self, *, assessment_id: Optional[str] = None, limit: int = 200,
    ) -> List[EvidenceGraph]:
        values: list[object] = []
        where = ""
        if assessment_id:
            where = "WHERE assessment_id=?"
            values.append(assessment_id)
        values.append(limit)
        with self.connect() as conn:
            rows = conn.execute(
                f"SELECT payload FROM evidence_graphs {where} "
                "ORDER BY generated_at DESC LIMIT ?", values,
            ).fetchall()
        return [EvidenceGraph.from_dict(loads(row["payload"])) for row in rows]

    def add_remediation_executions(
        self, executions: Iterable[RemediationExecution]
    ) -> int:
        items = list(executions)
        with self.connect() as conn:
            for item in items:
                item.validate()
                conn.execute(
                    """INSERT OR REPLACE INTO remediation_executions
                    (execution_id, recommendation_id, assessment_id, environment,
                     status, started_at, finished_at, payload)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        item.execution_id, item.recommendation_id, item.assessment_id,
                        item.environment, item.status, item.started_at, item.finished_at,
                        dumps(item.to_dict()),
                    ),
                )
        return len(items)

    def get_remediation_execution(self, execution_id: str) -> Optional[RemediationExecution]:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT payload FROM remediation_executions WHERE execution_id=?",
                (execution_id,),
            ).fetchone()
        return RemediationExecution.from_dict(loads(row["payload"])) if row else None

    def list_remediation_executions(
        self, *, recommendation_id: Optional[str] = None,
        status: Optional[str] = None, limit: int = 200,
    ) -> List[RemediationExecution]:
        clauses: list[str] = []
        values: list[object] = []
        for column, value in (("recommendation_id", recommendation_id), ("status", status)):
            if value:
                clauses.append(f"{column}=?")
                values.append(value)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        values.append(limit)
        with self.connect() as conn:
            rows = conn.execute(
                f"SELECT payload FROM remediation_executions {where} "
                "ORDER BY started_at DESC LIMIT ?", values,
            ).fetchall()
        return [RemediationExecution.from_dict(loads(row["payload"])) for row in rows]

    # v0.9.1 reproducible experiments ----------------------------------------
    def add_experiments(self, experiments: Iterable[ExperimentDefinition]) -> int:
        items = list(experiments)
        with self.connect() as conn:
            for item in items:
                item.validate()
                conn.execute(
                    """INSERT OR REPLACE INTO experiments
                    (experiment_id, name, status, created_at, updated_at, payload)
                    VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        item.experiment_id, item.name, item.status,
                        item.created_at, item.updated_at, dumps(item.to_dict()),
                    ),
                )
        return len(items)

    def get_experiment(self, experiment_id: str) -> Optional[ExperimentDefinition]:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT payload FROM experiments WHERE experiment_id=?",
                (experiment_id,),
            ).fetchone()
        return ExperimentDefinition.from_dict(loads(row["payload"])) if row else None

    def list_experiments(
        self, *, status: Optional[str] = None, limit: int = 200,
    ) -> List[ExperimentDefinition]:
        values: list[object] = []
        where = ""
        if status:
            where = "WHERE status=?"
            values.append(status)
        values.append(limit)
        with self.connect() as conn:
            rows = conn.execute(
                f"SELECT payload FROM experiments {where} ORDER BY updated_at DESC LIMIT ?",
                values,
            ).fetchall()
        return [ExperimentDefinition.from_dict(loads(row["payload"])) for row in rows]

    def set_experiment_status(
        self, experiment_id: str, status: str,
    ) -> ExperimentDefinition:
        item = self.get_experiment(experiment_id)
        if item is None:
            raise ValueError(f"experiment not found: {experiment_id}")
        updated = item.with_status(status)
        self.add_experiments([updated])
        return updated

    def add_experiment_trials(self, trials: Iterable[ExperimentTrial]) -> int:
        items = list(trials)
        with self.connect() as conn:
            for item in items:
                item.validate()
                exists = conn.execute(
                    "SELECT 1 FROM experiments WHERE experiment_id=?",
                    (item.experiment_id,),
                ).fetchone()
                if not exists:
                    raise ValueError(f"experiment not found: {item.experiment_id}")
                conn.execute(
                    """INSERT OR REPLACE INTO experiment_trials
                    (trial_id, experiment_id, scenario_id, repetition, seed, status,
                     started_at, finished_at, payload)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        item.trial_id, item.experiment_id, item.scenario_id,
                        item.repetition, item.seed, item.status,
                        item.started_at, item.finished_at, dumps(item.to_dict()),
                    ),
                )
        return len(items)

    def get_experiment_trial(self, trial_id: str) -> Optional[ExperimentTrial]:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT payload FROM experiment_trials WHERE trial_id=?",
                (trial_id,),
            ).fetchone()
        return ExperimentTrial.from_dict(loads(row["payload"])) if row else None

    def list_experiment_trials(
        self, *, experiment_id: Optional[str] = None,
        scenario_id: Optional[str] = None, status: Optional[str] = None,
        limit: int = 10000,
    ) -> List[ExperimentTrial]:
        clauses: list[str] = []
        values: list[object] = []
        for column, value in (
            ("experiment_id", experiment_id),
            ("scenario_id", scenario_id),
            ("status", status),
        ):
            if value:
                clauses.append(f"{column}=?")
                values.append(value)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        values.append(limit)
        with self.connect() as conn:
            rows = conn.execute(
                f"SELECT payload FROM experiment_trials {where} "
                "ORDER BY scenario_id, repetition, finished_at LIMIT ?",
                values,
            ).fetchall()
        return [ExperimentTrial.from_dict(loads(row["payload"])) for row in rows]

