from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import socket
import time
from typing import Optional

from .act import ActEngine
from .agent import AgentCommandError, Iperf3Agent, PingAgent, SimulatedNetworkAgent
from .artifacts import save_collection_run
from .controller import SafeController
from .capture import (
    CaptureRetentionManager, TcpdumpCaptureAgent, summarize_pcap,
)
from .dashboard import serve_dashboard
from .guard import GuardEngine
from .hub import Hub
from .inventory import ManagedTarget
from .network_state import (
    NetworkDevice, OpenSourceNetworkCollector, correlate_flow, filter_network_import,
    parse_frr_json, parse_nft_json, parse_ovs_json,
)
from .recommendation import (
    RecommendationEngine, export_recommendation, require_approval_eligible,
)
from .evidence import build_evidence_graph, export_evidence_graph
from .remediation import EXECUTION_STATUSES, RecommendationRanker, VirtualLabExecutor
from .experiment import (
    EXPERIMENT_STATUSES, TRIAL_STATUSES, ExperimentDefinition, ExperimentTrial,
    capture_environment, export_experiment, import_lab_summary, load_scenario_catalog,
    summarize_trials, write_environment_manifest,
)
from .ingest import serve_ingest
from .models import ApprovalRecord, ApprovalStatus
from .remote import (
    AgentHeartbeat, IngestBatch, RemoteAgentRegistration, RemoteDeliveryError,
    RemoteHubClient, SpoolQueue, parse_labels,
)
from .profiles import ObservationPlan, TargetProfile, learn_throughput_baseline
from .replay import CsvReplay
from .safety import SafetyPolicy, parse_action_list
from .service import ObservationService
from .state import RuleBasedStateEngine
from .view import render_timeline
from .workflow import apply_low_risk_observation_action, evaluate_and_persist


def cmd_init(args: argparse.Namespace) -> int:
    hub = Hub(args.db)
    print(f"initialized KANSOKU Hub: {hub.db_path}")
    return 0


def _print_auto_evaluation(hub: Hub, target: str, *, limit: int = 100) -> None:
    outcome = evaluate_and_persist(hub, target, limit=limit)
    state = outcome.state
    print(
        f"auto-state={state.state} confidence={state.confidence:.2f} "
        f"profile_mode={state.features.get('profile_mode')}"
    )
    print(f"reason: {state.reason}")
    if outcome.proposal:
        print(
            f"proposal={outcome.proposal.action} risk={outcome.proposal.risk_level} "
            f"proposal_id={outcome.proposal.proposal_id}"
        )


def cmd_agent_simulate(args: argparse.Namespace) -> int:
    hub = Hub(args.db)
    observations = SimulatedNetworkAgent().observe(args.target, profile=args.profile, count=args.count)
    inserted = hub.add_observations(observations)
    print(f"inserted {inserted} simulated observations for target={args.target}, profile={args.profile}")
    if not args.no_auto_evaluate:
        _print_auto_evaluation(hub, args.target)
    return 0


def _persist_collection(hub: Hub, result, raw_dir: str) -> Path:
    hub.add_collection_run(result.run)
    hub.add_observations(result.observations)
    return save_collection_run(result.run, raw_dir)


def cmd_agent_ping(args: argparse.Namespace) -> int:
    hub = Hub(args.db)
    try:
        result = PingAgent().collect(args.target, count=args.count, timeout=args.timeout)
    except AgentCommandError as exc:
        print(f"error: {exc}")
        return 2
    artifact = _persist_collection(hub, result, args.raw_dir)
    print(f"run_id={result.run.run_id} returncode={result.run.returncode}")
    print(f"inserted {len(result.observations)} ping observations for target={args.target}")
    print(f"raw artifact: {artifact}")
    for obs in result.observations:
        print(json.dumps(obs.to_dict(), ensure_ascii=False))
    if result.observations and not args.no_auto_evaluate:
        _print_auto_evaluation(hub, args.target)
    return 0 if result.observations else 1


def cmd_agent_iperf3(args: argparse.Namespace) -> int:
    hub = Hub(args.db)
    try:
        result = Iperf3Agent().collect(
            args.target,
            port=args.port,
            duration=args.duration,
            reverse=args.reverse,
            udp=args.udp,
            bitrate=args.bitrate,
            parallel=args.parallel,
            connect_timeout_ms=args.connect_timeout_ms,
        )
    except AgentCommandError as exc:
        print(f"error: {exc}")
        return 2
    artifact = _persist_collection(hub, result, args.raw_dir)
    print(f"run_id={result.run.run_id} returncode={result.run.returncode}")
    print(f"inserted {len(result.observations)} iperf3 observations for target={args.target}")
    print(f"raw artifact: {artifact}")
    if result.run.metadata.get("parse_error"):
        print(f"iperf3 error: {result.run.metadata['parse_error']}")
    for obs in result.observations:
        print(json.dumps(obs.to_dict(), ensure_ascii=False))
    if result.observations and not args.no_auto_evaluate:
        _print_auto_evaluation(hub, args.target)
    return 0 if result.run.returncode == 0 and result.observations else 1


def cmd_agent_watch(args: argparse.Namespace) -> int:
    """Run a conservative observation loop that follows the persisted plan."""

    hub = Hub(args.db)
    ping_agent = PingAgent()
    iperf_agent = Iperf3Agent() if args.iperf3_every > 0 else None
    cycle = 0
    try:
        while args.iterations == 0 or cycle < args.iterations:
            cycle += 1
            print(f"\nwatch cycle={cycle} target={args.target}")
            try:
                ping_result = ping_agent.collect(args.target, count=args.count, timeout=args.timeout)
                ping_artifact = _persist_collection(hub, ping_result, args.raw_dir)
                print(
                    f"ping run_id={ping_result.run.run_id} rc={ping_result.run.returncode} "
                    f"observations={len(ping_result.observations)} artifact={ping_artifact}"
                )
            except AgentCommandError as exc:
                print(f"ping error: {exc}")

            if iperf_agent and cycle % args.iperf3_every == 0:
                try:
                    iperf_result = iperf_agent.collect(
                        args.target,
                        port=args.port,
                        duration=args.duration,
                        parallel=args.parallel,
                        connect_timeout_ms=args.connect_timeout_ms,
                    )
                    iperf_artifact = _persist_collection(hub, iperf_result, args.raw_dir)
                    print(
                        f"iperf3 run_id={iperf_result.run.run_id} rc={iperf_result.run.returncode} "
                        f"observations={len(iperf_result.observations)} artifact={iperf_artifact}"
                    )
                except AgentCommandError as exc:
                    print(f"iperf3 error: {exc}")

            outcome = evaluate_and_persist(hub, args.target, limit=args.limit)
            print(f"state={outcome.state.state} reason={outcome.state.reason}")
            if outcome.proposal:
                print(
                    f"proposal={outcome.proposal.action} risk={outcome.proposal.risk_level} "
                    f"proposal_id={outcome.proposal.proposal_id}"
                )
                if args.auto_apply_low_risk and outcome.proposal.risk_level == "low":
                    decision, result, plan = apply_low_risk_observation_action(
                        hub, outcome.proposal, execute=True
                    )
                    print(f"guard={decision.status} act={result.status}")
                    if plan:
                        print(f"observation interval updated to {plan.interval_sec}s")

            if args.iterations and cycle >= args.iterations:
                break
            profile = hub.get_target_profile(args.target)
            plan = hub.get_observation_plan(args.target)
            interval = (
                plan.interval_sec
                if plan
                else args.interval
                or (profile.normal_interval_sec if profile else 30)
            )
            print(f"sleeping {interval}s")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("watch stopped")
    return 0


def _persist_capture_summary(hub: Hub, summary, *, force_reimport: bool = False) -> bool:
    stored = hub.add_capture_session(summary.session, force_reimport=force_reimport)
    if not stored:
        return False
    hub.add_flow_records(summary.flows)
    hub.add_observations(summary.observations)
    return True


def _capture_payload(
    summary, *, flow_limit: int = 20, import_status: str = "IMPORTED", duplicate_of: str | None = None
) -> dict:
    payload = {
        "import_status": import_status,
        "capture": summary.session.to_dict(),
        "observations": [item.to_dict() for item in summary.observations],
        "top_flows": [item.to_dict() for item in summary.flows[: max(0, flow_limit)]],
    }
    if duplicate_of:
        payload["duplicate_of"] = duplicate_of
    return payload


def cmd_capture_interfaces(args: argparse.Namespace) -> int:
    try:
        rows = TcpdumpCaptureAgent(tcpdump_bin=args.tcpdump_bin).list_interfaces()
    except (RuntimeError, FileNotFoundError) as exc:
        print(f"error: {exc}")
        return 2
    print("\n".join(rows))
    return 0


def cmd_capture_summarize(args: argparse.Namespace) -> int:
    hub = Hub(args.db)
    try:
        summary = summarize_pcap(
            args.pcap,
            target=args.target,
            source=args.source,
            interface=args.interface,
            bpf_filter=args.filter or "",
            snaplen=args.snaplen,
            privacy_mode="offline",
            retention_days=args.retention_days,
            max_flows=args.max_flows,
        )
    except (OSError, ValueError) as exc:
        print(f"error: {exc}")
        return 2
    import_status = "NOT_STORED" if args.no_store else "IMPORTED"
    duplicate_of = None
    if not args.no_store:
        existing = hub.find_capture_session_by_fingerprint(
            target=summary.session.target,
            source=summary.session.source,
            sha256=summary.session.sha256,
        )
        if existing and not args.force_reimport:
            duplicate_of = existing.capture_id
            summary.session = existing
            summary.flows = hub.list_flow_records(capture_id=existing.capture_id, limit=args.max_flows)
            summary.observations = []
            import_status = "DUPLICATE"
        else:
            _persist_capture_summary(hub, summary, force_reimport=args.force_reimport)
            import_status = "FORCE_IMPORTED" if args.force_reimport else "IMPORTED"
    print(
        json.dumps(
            _capture_payload(
                summary,
                flow_limit=args.flow_limit,
                import_status=import_status,
                duplicate_of=duplicate_of,
            ),
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


def cmd_capture_run(args: argparse.Namespace) -> int:
    hub = Hub(args.db)
    try:
        result = TcpdumpCaptureAgent(
            source=args.source, tcpdump_bin=args.tcpdump_bin
        ).capture(
            args.target,
            interface=args.interface,
            duration_sec=args.duration,
            packet_limit=args.packet_limit,
            bpf_filter=args.filter or "",
            snaplen=args.snaplen,
            output_dir=args.output_dir,
            full_packet=args.full_packet,
            retention_days=args.retention_days,
            max_flows=args.max_flows,
            use_sudo=args.use_sudo,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"error: {exc}")
        return 2
    hub.add_collection_run(result.run)
    _persist_capture_summary(hub, result.summary)
    artifact = save_collection_run(result.run, args.raw_dir)
    retention = CaptureRetentionManager(args.output_dir).prune(
        hub.list_capture_sessions(limit=10_000),
        retention_days=args.retention_days,
        quota_bytes=max(0, args.quota_mb) * 1024 * 1024,
    )
    print(f"run_id={result.run.run_id} capture_id={result.summary.session.capture_id}")
    print(f"pcap: {result.summary.session.pcap_path}")
    print(f"raw run artifact: {artifact}")
    print(json.dumps({**_capture_payload(result.summary, flow_limit=args.flow_limit), "retention": retention}, ensure_ascii=False, indent=2))
    if result.summary.observations and not args.no_auto_evaluate:
        print("auto-state skipped: capture metadata does not yet map to state-engine metrics")
    return 0


def cmd_capture_list(args: argparse.Namespace) -> int:
    sessions = Hub(args.db).list_capture_sessions(limit=args.limit, target=args.target)
    print(json.dumps([item.to_dict() for item in sessions], ensure_ascii=False, indent=2))
    return 0


def cmd_capture_show(args: argparse.Namespace) -> int:
    hub = Hub(args.db)
    session = hub.get_capture_session(args.capture_id)
    if not session:
        print("capture session not found")
        return 1
    flows = hub.list_flow_records(capture_id=args.capture_id, limit=args.flow_limit)
    print(json.dumps({"capture": session.to_dict(), "flows": [item.to_dict() for item in flows]}, ensure_ascii=False, indent=2))
    return 0


def cmd_capture_flows(args: argparse.Namespace) -> int:
    flows = Hub(args.db).list_flow_records(
        limit=args.limit, target=args.target, capture_id=args.capture_id
    )
    print(json.dumps([item.to_dict() for item in flows], ensure_ascii=False, indent=2))
    return 0


def cmd_capture_prune(args: argparse.Namespace) -> int:
    hub = Hub(args.db)
    sessions = hub.list_capture_sessions(limit=100_000, target=args.target)
    result = CaptureRetentionManager(args.output_dir).prune(
        sessions,
        retention_days=args.retention_days,
        quota_bytes=max(0, args.quota_mb) * 1024 * 1024,
        dry_run=args.dry_run,
    )
    if not args.dry_run:
        for item in result["deleted"]:
            session = hub.get_capture_session(item["capture_id"])
            if session:
                hub.add_capture_session(
                    session.updated(
                        status="PRUNED",
                        pcap_path="",
                        metadata={**session.metadata, "pruned_reason": item["reason"]},
                    )
                )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def cmd_edge_pcap(args: argparse.Namespace) -> int:
    try:
        summary = summarize_pcap(
            args.pcap,
            target=args.target,
            source=args.source or socket.gethostname(),
            interface=args.interface,
            bpf_filter=args.filter or "",
            snaplen=args.snaplen,
            privacy_mode="offline",
            storage_scope="edge",
            max_flows=args.max_flows,
        )
    except (OSError, ValueError) as exc:
        print(f"error: {exc}")
        return 2
    summary.session = summary.session.updated(storage_scope="edge")
    batch = IngestBatch.from_collection(
        args.agent_id,
        summary.observations,
        captures=[summary.session],
        flows=summary.flows[: args.send_flow_limit],
    )
    return _edge_queue_and_deliver(args, batch)


def cmd_edge_capture(args: argparse.Namespace) -> int:
    try:
        result = TcpdumpCaptureAgent(
            source=args.source, tcpdump_bin=args.tcpdump_bin
        ).capture(
            args.target,
            interface=args.interface,
            duration_sec=args.duration,
            packet_limit=args.packet_limit,
            bpf_filter=args.filter or "",
            snaplen=args.snaplen,
            output_dir=args.output_dir,
            full_packet=args.full_packet,
            retention_days=args.retention_days,
            max_flows=args.max_flows,
            use_sudo=args.use_sudo,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"error: {exc}")
        return 2
    session = result.summary.session.updated(storage_scope="edge")
    batch = IngestBatch.from_collection(
        args.agent_id,
        result.summary.observations,
        [result.run],
        captures=[session],
        flows=result.summary.flows[: args.send_flow_limit],
    )
    delivery = _edge_queue_and_deliver(args, batch)
    CaptureRetentionManager(args.output_dir).prune(
        [session],
        retention_days=args.retention_days,
        quota_bytes=max(0, args.quota_mb) * 1024 * 1024,
    )
    return delivery


def cmd_run_show(args: argparse.Namespace) -> int:
    run = Hub(args.db).get_collection_run(args.run_id)
    if not run:
        print("collection run not found")
        return 1
    print(json.dumps(run.to_dict(), ensure_ascii=False, indent=2))
    return 0


def cmd_replay_csv(args: argparse.Namespace) -> int:
    hub = Hub(args.db)
    observations = CsvReplay().load(args.csv)
    if args.target:
        observations = [obs for obs in observations if obs.target == args.target]
    inserted = hub.add_observations(observations)
    print(f"inserted {inserted} replay observations from {args.csv}")
    targets = sorted({obs.target for obs in observations})
    if not args.no_auto_evaluate:
        for target in targets:
            _print_auto_evaluation(hub, target)
    return 0


def cmd_state_evaluate(args: argparse.Namespace) -> int:
    hub = Hub(args.db)
    outcome = evaluate_and_persist(hub, args.target, limit=args.limit)
    print(json.dumps(outcome.state.to_dict(), ensure_ascii=False, indent=2))
    if outcome.proposal:
        print("\nAction proposal:")
        print(json.dumps(outcome.proposal.to_dict(), ensure_ascii=False, indent=2))
    else:
        print("\nNo new action proposal.")
    return 0


def cmd_profile_set(args: argparse.Namespace) -> int:
    hub = Hub(args.db)
    existing = hub.get_target_profile(args.target)
    if existing:
        profile = existing
    else:
        profile = TargetProfile(target=args.target, name=args.name or args.target)

    changes = {
        "name": args.name,
        "expected_bandwidth_mbps": args.expected_bandwidth,
        "baseline_throughput_mbps": args.baseline_throughput,
        "throughput_normal_ratio": args.normal_ratio,
        "throughput_warning_ratio": args.warning_ratio,
        "throughput_degraded_ratio": args.degraded_ratio,
        "rtt_warning_ms": args.rtt_warning,
        "rtt_degraded_ms": args.rtt_degraded,
        "rtt_critical_ms": args.rtt_critical,
        "loss_warning_pct": args.loss_warning,
        "loss_degraded_pct": args.loss_degraded,
        "loss_critical_pct": args.loss_critical,
        "normal_interval_sec": args.normal_interval,
        "warning_interval_sec": args.warning_interval,
    }
    changes = {key: value for key, value in changes.items() if value is not None}
    if changes:
        profile = profile.updated(**changes)
    profile.validate()
    hub.set_target_profile(profile)
    if not hub.get_observation_plan(args.target):
        hub.set_observation_plan(
            ObservationPlan(target=args.target, interval_sec=profile.normal_interval_sec)
        )
    print(json.dumps(profile.to_dict(), ensure_ascii=False, indent=2))
    return 0


def cmd_profile_show(args: argparse.Namespace) -> int:
    profile = Hub(args.db).get_target_profile(args.target)
    if not profile:
        print("target profile not found")
        return 1
    print(json.dumps(profile.to_dict(), ensure_ascii=False, indent=2))
    return 0


def cmd_profile_list(args: argparse.Namespace) -> int:
    profiles = Hub(args.db).list_target_profiles(limit=args.limit)
    print(json.dumps([p.to_dict() for p in profiles], ensure_ascii=False, indent=2))
    return 0


def cmd_profile_delete(args: argparse.Namespace) -> int:
    deleted = Hub(args.db).delete_target_profile(args.target)
    print("deleted" if deleted else "target profile not found")
    return 0 if deleted else 1


def cmd_profile_learn(args: argparse.Namespace) -> int:
    hub = Hub(args.db)
    observations = hub.list_observations(
        limit=args.limit, target=args.target, metric="throughput_mbps"
    )
    baseline = learn_throughput_baseline(
        args.target, observations, minimum_samples=args.minimum_samples
    )
    profile = hub.get_target_profile(args.target) or TargetProfile(
        target=args.target, name=args.target
    )
    profile = profile.updated(baseline_throughput_mbps=baseline, source="learned")
    hub.set_target_profile(profile)
    print(json.dumps(profile.to_dict(), ensure_ascii=False, indent=2))
    return 0


def cmd_plan_show(args: argparse.Namespace) -> int:
    hub = Hub(args.db)
    plan = hub.get_observation_plan(args.target)
    if not plan:
        profile = hub.get_target_profile(args.target)
        interval = profile.normal_interval_sec if profile else 30
        plan = ObservationPlan(target=args.target, interval_sec=interval)
    print(json.dumps(plan.to_dict(), ensure_ascii=False, indent=2))
    return 0


def _resolve_proposal(hub: Hub, proposal_id: Optional[str], target: Optional[str]):
    if proposal_id:
        return hub.get_proposal(proposal_id)
    if target:
        return hub.latest_proposal(target)
    return None


def cmd_policy_set(args: argparse.Namespace) -> int:
    hub = Hub(args.db)
    existing = hub.get_safety_policy(args.target)
    if existing and existing.target == args.target:
        policy = existing
    else:
        policy = SafetyPolicy(target=args.target, name=args.name or f"policy for {args.target}")

    changes = {
        "name": args.name,
        "allowed_actions": parse_action_list(args.allowed_actions) if args.allowed_actions is not None else None,
        "auto_approve_actions": parse_action_list(args.auto_approve_actions) if args.auto_approve_actions is not None else None,
        "approval_required_actions": parse_action_list(args.approval_required_actions) if args.approval_required_actions is not None else None,
        "rollback_required_actions": parse_action_list(args.rollback_required_actions) if args.rollback_required_actions is not None else None,
        "blocked_actions": parse_action_list(args.blocked_actions) if args.blocked_actions is not None else None,
        "blocked_targets": parse_action_list(args.blocked_targets) if args.blocked_targets is not None else None,
        "minimum_observation_interval_sec": args.minimum_interval,
        "allow_system_changes": args.allow_system_changes,
        "rollback_on_verification_failure": args.rollback_on_failure,
    }
    changes = {key: value for key, value in changes.items() if value is not None}
    if changes:
        policy = policy.updated(**changes)
    policy.validate()
    hub.set_safety_policy(policy)
    print(json.dumps(policy.to_dict(), ensure_ascii=False, indent=2))
    return 0


def cmd_policy_show(args: argparse.Namespace) -> int:
    policy = Hub(args.db).get_safety_policy(args.target)
    if not policy:
        print("safety policy not found; the built-in default policy will be used")
        return 1
    print(json.dumps(policy.to_dict(), ensure_ascii=False, indent=2))
    return 0


def cmd_policy_list(args: argparse.Namespace) -> int:
    policies = Hub(args.db).list_safety_policies(limit=args.limit)
    print(json.dumps([policy.to_dict() for policy in policies], ensure_ascii=False, indent=2))
    return 0


def cmd_policy_delete(args: argparse.Namespace) -> int:
    deleted = Hub(args.db).delete_safety_policy(args.target)
    print("deleted" if deleted else "safety policy not found")
    return 0 if deleted else 1


def cmd_approval_set(args: argparse.Namespace) -> int:
    hub = Hub(args.db)
    proposal = hub.get_proposal(args.proposal_id)
    if not proposal:
        print("action proposal not found")
        return 1
    status = (
        ApprovalStatus.APPROVED.value
        if args.decision == "approve"
        else ApprovalStatus.REJECTED.value
    )
    approval = ApprovalRecord(
        proposal_id=proposal.proposal_id,
        status=status,
        actor=args.actor,
        comment=args.comment or "",
    )
    hub.add_approval(approval)
    print(json.dumps(approval.to_dict(), ensure_ascii=False, indent=2))
    return 0


def cmd_approval_show(args: argparse.Namespace) -> int:
    approval = Hub(args.db).latest_approval(args.proposal_id)
    if not approval:
        print("approval record not found")
        return 1
    print(json.dumps(approval.to_dict(), ensure_ascii=False, indent=2))
    return 0


def cmd_controller_process(args: argparse.Namespace) -> int:
    hub = Hub(args.db)
    proposal = _resolve_proposal(hub, args.proposal_id, args.target)
    if not proposal:
        print("no action proposal found")
        return 1
    outcome = SafeController(hub).process(
        proposal,
        execute=args.execute,
        allow_system_changes=args.allow_system_changes,
    )
    payload = {
        "proposal": outcome.proposal.to_dict(),
        "policy": outcome.policy.to_dict(),
        "guard_decision": outcome.decision.to_dict(),
        "approval": outcome.approval.to_dict() if outcome.approval else None,
        "action_result": outcome.result.to_dict() if outcome.result else None,
        "verification": outcome.verification.to_dict() if outcome.verification else None,
        "rollback_result": outcome.rollback_result.to_dict() if outcome.rollback_result else None,
        "transaction": outcome.transaction.to_dict(),
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 1 if outcome.transaction.outcome in {"REJECTED", "FAILED"} else 0


def cmd_controller_status(args: argparse.Namespace) -> int:
    hub = Hub(args.db)
    transactions = hub.list_control_transactions(limit=args.limit, target=args.target)
    print(json.dumps([item.to_dict() for item in transactions], ensure_ascii=False, indent=2))
    return 0


def cmd_guard_validate(args: argparse.Namespace) -> int:
    hub = Hub(args.db)
    proposal = _resolve_proposal(hub, args.proposal_id, args.target)
    if not proposal:
        print("no action proposal found")
        return 1
    policy = hub.get_safety_policy(proposal.target) or SafetyPolicy()
    approval = hub.latest_approval(proposal.proposal_id)
    decision = GuardEngine(policy).validate(proposal, approval=approval)
    hub.add_guard_decision(decision)
    print(json.dumps(decision.to_dict(), ensure_ascii=False, indent=2))
    return 0


def cmd_act_execute(args: argparse.Namespace) -> int:
    hub = Hub(args.db)
    proposal = _resolve_proposal(hub, args.proposal_id, args.target)
    if not proposal:
        print("no action proposal found")
        return 1
    outcome = SafeController(hub).process(
        proposal,
        execute=args.execute,
        allow_system_changes=args.allow_system_changes,
    )
    print(json.dumps(outcome.transaction.to_dict(), ensure_ascii=False, indent=2))
    if outcome.result:
        print(json.dumps(outcome.result.to_dict(), ensure_ascii=False, indent=2))
    if outcome.verification:
        print(json.dumps(outcome.verification.to_dict(), ensure_ascii=False, indent=2))
    return 1 if outcome.transaction.outcome in {"REJECTED", "FAILED"} else 0


def cmd_target_set(args: argparse.Namespace) -> int:
    hub = Hub(args.db)
    target = hub.get_managed_target(args.target) or ManagedTarget(
        target=args.target,
        name=args.name or args.target,
    )
    changes = {
        "name": args.name,
        "enabled": args.enabled,
        "ping_enabled": args.ping_enabled,
        "ping_count": args.ping_count,
        "ping_timeout_sec": args.ping_timeout,
        "iperf3_enabled": args.iperf3_enabled,
        "iperf3_port": args.iperf3_port,
        "iperf3_duration_sec": args.iperf3_duration,
        "iperf3_parallel": args.iperf3_parallel,
        "iperf3_every_n_cycles": args.iperf3_every,
        "auto_process_low_risk": args.auto_process_low_risk,
        "raw_dir": args.raw_dir,
    }
    changes = {key: value for key, value in changes.items() if value is not None}
    if changes.get("iperf3_enabled") is True and "iperf3_every_n_cycles" not in changes:
        if target.iperf3_every_n_cycles == 0:
            changes["iperf3_every_n_cycles"] = 1
    target = target.updated(**changes) if changes else target
    target.validate()
    hub.set_managed_target(target)
    print(json.dumps(target.to_dict(), ensure_ascii=False, indent=2))
    return 0


def cmd_target_show(args: argparse.Namespace) -> int:
    target = Hub(args.db).get_managed_target(args.target)
    if not target:
        print("managed target not found")
        return 1
    print(json.dumps(target.to_dict(), ensure_ascii=False, indent=2))
    return 0


def cmd_target_list(args: argparse.Namespace) -> int:
    targets = Hub(args.db).list_managed_targets(
        limit=args.limit, enabled_only=args.enabled_only
    )
    print(json.dumps([item.to_dict() for item in targets], ensure_ascii=False, indent=2))
    return 0


def cmd_target_delete(args: argparse.Namespace) -> int:
    deleted = Hub(args.db).delete_managed_target(args.target)
    print("deleted" if deleted else "managed target not found")
    return 0 if deleted else 1


def cmd_target_enable(args: argparse.Namespace) -> int:
    hub = Hub(args.db)
    target = hub.get_managed_target(args.target)
    if not target:
        print("managed target not found")
        return 1
    target = target.updated(enabled=args.enabled)
    hub.set_managed_target(target)
    print(json.dumps(target.to_dict(), ensure_ascii=False, indent=2))
    return 0


def _service(args: argparse.Namespace) -> ObservationService:
    return ObservationService(Hub(args.db), owner_id=getattr(args, "owner_id", None))


def cmd_service_once(args: argparse.Namespace) -> int:
    try:
        cycles = _service(args).run_once(
            target_name=args.target,
            force=args.force,
            auto_control=not args.no_auto_control,
            simulate_profile=args.simulate_profile,
            lease_ttl_sec=args.lease_ttl,
        )
    except (RuntimeError, ValueError) as exc:
        print(f"service error: {exc}")
        return 1
    if not cycles:
        print("no managed targets are due")
        return 0
    print(json.dumps([cycle.to_dict() for cycle in cycles], ensure_ascii=False, indent=2))
    return 1 if any(cycle.status == "FAILED" for cycle in cycles) else 0


def cmd_service_run(args: argparse.Namespace) -> int:
    try:
        cycles = _service(args).run_loop(
            iterations=args.iterations,
            poll_interval_sec=args.poll_interval,
            target_name=args.target,
            force_first=args.force_first,
            auto_control=not args.no_auto_control,
            simulate_profile=args.simulate_profile,
        )
    except (RuntimeError, ValueError) as exc:
        print(f"service error: {exc}")
        return 1
    for cycle in cycles:
        print(
            f"cycle={cycle.cycle_id} target={cycle.target} status={cycle.status} "
            f"observations={cycle.observation_count} state={cycle.state_id or '—'}"
        )
    return 1 if any(cycle.status == "FAILED" for cycle in cycles) else 0


def cmd_service_status(args: argparse.Namespace) -> int:
    hub = Hub(args.db)
    service = ObservationService(hub, owner_id=args.owner_id)
    fleet = service.fleet_status()
    if args.target:
        fleet = [item for item in fleet if item["target"]["target"] == args.target]
    lease = hub.get_scheduler_lease(ObservationService.LEASE_NAME)
    print(
        json.dumps(
            {
                "lease": lease.to_dict() if lease else None,
                "fleet": fleet,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


def cmd_service_cycles(args: argparse.Namespace) -> int:
    cycles = Hub(args.db).list_scheduler_cycles(limit=args.limit, target=args.target)
    print(json.dumps([cycle.to_dict() for cycle in cycles], ensure_ascii=False, indent=2))
    return 0


def cmd_service_lease_show(args: argparse.Namespace) -> int:
    lease = Hub(args.db).get_scheduler_lease(ObservationService.LEASE_NAME)
    if not lease:
        print("no scheduler lease")
        return 1
    print(json.dumps(lease.to_dict(), ensure_ascii=False, indent=2))
    return 0


def cmd_service_lease_release(args: argparse.Namespace) -> int:
    released = Hub(args.db).release_scheduler_lease(
        ObservationService.LEASE_NAME,
        args.owner_id or "",
        force=args.force,
    )
    print("released" if released else "lease not released")
    return 0 if released else 1


def cmd_view(args: argparse.Namespace) -> int:
    print(render_timeline(Hub(args.db), args.target, limit=args.limit))
    return 0


def cmd_web(args: argparse.Namespace) -> int:
    serve_dashboard(Hub(args.db), host=args.host, port=args.port)
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    hub = Hub(args.db)
    agent = SimulatedNetworkAgent()
    if not hub.get_target_profile(args.target):
        hub.set_target_profile(
            TargetProfile(
                target=args.target,
                name="demo-1g-path",
                expected_bandwidth_mbps=1000,
            )
        )
    if not hub.get_safety_policy(args.target):
        hub.set_safety_policy(SafetyPolicy(target=args.target, name="demo safe policy"))
    hub.add_observations(agent.observe(args.target, profile="normal", count=2))
    hub.add_observations(agent.observe(args.target, profile=args.profile, count=3))
    outcome = evaluate_and_persist(hub, args.target, limit=30)
    print("State estimate")
    print(json.dumps(outcome.state.to_dict(), ensure_ascii=False, indent=2))

    proposal = outcome.proposal
    if not proposal:
        print("No action proposal generated.")
        return 0
    print("\nAction proposal")
    print(json.dumps(proposal.to_dict(), ensure_ascii=False, indent=2))

    controlled = SafeController(hub).process(proposal, execute=args.execute)
    print("\nController transaction")
    print(json.dumps(controlled.transaction.to_dict(), ensure_ascii=False, indent=2))
    print("\nGuard decision")
    print(json.dumps(controlled.decision.to_dict(), ensure_ascii=False, indent=2))
    if controlled.result:
        print("\nAction result")
        print(json.dumps(controlled.result.to_dict(), ensure_ascii=False, indent=2))
    if controlled.verification:
        print("\nVerification")
        print(json.dumps(controlled.verification.to_dict(), ensure_ascii=False, indent=2))
    if controlled.transaction.outcome == "WAITING_APPROVAL":
        print(
            "\nThe proposal requires approval. Use: "
            f"kansoku --db {args.db} approval set --proposal-id {proposal.proposal_id} "
            "--decision approve --actor <name>"
        )
    print("\n" + render_timeline(hub, args.target, limit=10))
    return 0


def _add_auto_evaluate_flag(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--no-auto-evaluate",
        action="store_true",
        help="store observations without automatically creating a state estimate",
    )



def _split_csv(value: Optional[str]) -> list[str]:
    return [item.strip() for item in (value or "").split(",") if item.strip()]


def _write_secret_file(path: str, token: str) -> Path:
    output = Path(path).expanduser()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(token + "\n", encoding="utf-8")
    try:
        output.chmod(0o600)
    except OSError:
        pass
    return output


def _resolve_agent_token(args: argparse.Namespace) -> str:
    token_file = getattr(args, "token_file", None)
    token_env = getattr(args, "token_env", "KANSOKU_AGENT_TOKEN")
    if token_file:
        token = Path(token_file).expanduser().read_text(encoding="utf-8").strip()
    else:
        token = os.environ.get(token_env, "").strip()
    if not token:
        source = f"file {token_file}" if token_file else f"environment variable {token_env}"
        raise ValueError(f"remote agent token was not found in {source}")
    return token


def _remote_client(args: argparse.Namespace) -> RemoteHubClient:
    return RemoteHubClient(
        args.hub_url, args.agent_id, _resolve_agent_token(args), timeout=args.http_timeout
    )


def _remote_agent_payload(agent: RemoteAgentRegistration, token: Optional[str] = None, token_file: Optional[Path] = None) -> dict:
    payload = {"agent": agent.to_dict()}
    if token is not None:
        payload["token"] = token
        payload["warning"] = "This token is shown once. Store it securely."
    if token_file is not None:
        payload["token_file"] = str(token_file)
        payload["warning"] = "The token file was written with owner-only permissions where supported."
    return payload


def cmd_remote_agent_create(args: argparse.Namespace) -> int:
    hub = Hub(args.db)
    if args.agent_id and hub.get_remote_agent(args.agent_id):
        raise ValueError(f"remote agent already exists: {args.agent_id}")
    agent, token = RemoteAgentRegistration.create(
        args.name, agent_id=args.agent_id, capabilities=_split_csv(args.capabilities),
        labels=parse_labels(args.label),
    )
    hub.set_remote_agent(agent)
    token_path = _write_secret_file(args.token_file, token) if args.token_file else None
    print(json.dumps(_remote_agent_payload(agent, None if token_path else token, token_path), ensure_ascii=False, indent=2))
    return 0


def cmd_remote_agent_show(args: argparse.Namespace) -> int:
    agent = Hub(args.db).get_remote_agent(args.agent_id)
    if not agent:
        print("remote agent not found")
        return 1
    heartbeat = Hub(args.db).latest_agent_heartbeat(args.agent_id)
    print(json.dumps({"agent": agent.to_dict(), "latest_heartbeat": heartbeat.to_dict() if heartbeat else None}, ensure_ascii=False, indent=2))
    return 0


def cmd_remote_agent_list(args: argparse.Namespace) -> int:
    hub = Hub(args.db)
    rows = []
    for agent in hub.list_remote_agents(limit=args.limit, enabled_only=args.enabled_only):
        heartbeat = hub.latest_agent_heartbeat(agent.agent_id)
        rows.append({"agent": agent.to_dict(), "latest_heartbeat": heartbeat.to_dict() if heartbeat else None})
    print(json.dumps(rows, ensure_ascii=False, indent=2))
    return 0


def cmd_remote_agent_enable(args: argparse.Namespace) -> int:
    hub = Hub(args.db)
    agent = hub.get_remote_agent(args.agent_id)
    if not agent:
        print("remote agent not found")
        return 1
    agent = agent.updated(enabled=args.enabled)
    hub.set_remote_agent(agent)
    print(json.dumps(agent.to_dict(), ensure_ascii=False, indent=2))
    return 0


def cmd_remote_agent_rotate(args: argparse.Namespace) -> int:
    hub = Hub(args.db)
    agent = hub.get_remote_agent(args.agent_id)
    if not agent:
        print("remote agent not found")
        return 1
    agent, token = agent.rotate_token()
    hub.set_remote_agent(agent)
    token_path = _write_secret_file(args.token_file, token) if args.token_file else None
    print(json.dumps(_remote_agent_payload(agent, None if token_path else token, token_path), ensure_ascii=False, indent=2))
    return 0


def cmd_remote_agent_delete(args: argparse.Namespace) -> int:
    deleted = Hub(args.db).delete_remote_agent(args.agent_id)
    print("deleted" if deleted else "remote agent not found")
    return 0 if deleted else 1


def cmd_ingest_serve(args: argparse.Namespace) -> int:
    serve_ingest(
        Hub(args.db), args.host, args.port, max_body_bytes=args.max_body_bytes,
        auto_evaluate=not args.no_auto_evaluate,
    )
    return 0


def _edge_queue_and_deliver(args: argparse.Namespace, batch: IngestBatch) -> int:
    spool = SpoolQueue(args.spool_dir)
    path = spool.enqueue(batch)
    result = {"batch_id": batch.batch_id, "spooled": str(path), "queue_depth": spool.count()}
    if args.spool_only:
        result["delivery"] = "queued"
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    try:
        flush = spool.flush(_remote_client(args), limit=args.flush_limit)
        result["flush"] = flush
        result["delivery"] = "delivered" if batch.batch_id in flush["delivered"] else "queued"
    except RemoteDeliveryError as exc:
        result["delivery"] = "queued"
        result["error"] = str(exc)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def cmd_edge_simulate(args: argparse.Namespace) -> int:
    observations = SimulatedNetworkAgent().observe(args.target, profile=args.profile, count=args.count)
    return _edge_queue_and_deliver(args, IngestBatch.from_collection(args.agent_id, observations))


def cmd_edge_ping(args: argparse.Namespace) -> int:
    try:
        result = PingAgent().collect(args.target, count=args.count, timeout=args.timeout)
    except AgentCommandError as exc:
        print(f"error: {exc}")
        return 2
    batch = IngestBatch.from_collection(args.agent_id, result.observations, [result.run])
    return _edge_queue_and_deliver(args, batch)


def cmd_edge_iperf3(args: argparse.Namespace) -> int:
    try:
        result = Iperf3Agent().collect(
            args.target, port=args.port, duration=args.duration, parallel=args.parallel,
            reverse=args.reverse, udp=args.udp, bitrate=args.bitrate,
            connect_timeout_ms=args.connect_timeout_ms,
        )
    except AgentCommandError as exc:
        print(f"error: {exc}")
        return 2
    batch = IngestBatch.from_collection(args.agent_id, result.observations, [result.run])
    return _edge_queue_and_deliver(args, batch)


def cmd_edge_flush(args: argparse.Namespace) -> int:
    result = SpoolQueue(args.spool_dir).flush(_remote_client(args), limit=args.flush_limit)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if not result["failed"] else 1


def cmd_edge_status(args: argparse.Namespace) -> int:
    spool = SpoolQueue(args.spool_dir)
    print(json.dumps({"spool_dir": str(spool.directory), "queue_depth": spool.count(), "files": [str(path) for path in spool.list_paths()]}, ensure_ascii=False, indent=2))
    return 0


def cmd_edge_heartbeat(args: argparse.Namespace) -> int:
    spool = SpoolQueue(args.spool_dir)
    heartbeat = AgentHeartbeat(
        agent_id=args.agent_id, hostname=socket.gethostname(), version="0.10.0",
        queue_depth=spool.count(), metadata={"platform": os.uname().sysname if hasattr(os, "uname") else os.name},
    )
    try:
        response = _remote_client(args).heartbeat(heartbeat)
    except RemoteDeliveryError as exc:
        print(json.dumps({"status": "failed", "error": str(exc), "heartbeat": heartbeat.to_dict()}, ensure_ascii=False, indent=2))
        return 1
    print(json.dumps(response, ensure_ascii=False, indent=2))
    return 0



def _device_defaults(kind: str) -> tuple[str, str]:
    return {
        "frr": ("router", "frr"),
        "ovs": ("l2_switch", "openvswitch"),
        "nft": ("firewall", "nftables"),
    }[kind]


def cmd_network_device_set(args: argparse.Namespace) -> int:
    hub = Hub(args.db)
    existing = hub.get_network_device(args.device_id)
    labels = parse_labels(args.label or [])
    if existing:
        changes = {
            "name": args.name or existing.name,
            "device_type": args.device_type or existing.device_type,
            "platform": args.platform or existing.platform,
            "management_address": args.management_address if args.management_address is not None else existing.management_address,
            "enabled": args.enabled if args.enabled is not None else existing.enabled,
            "labels": {**existing.labels, **labels},
        }
        device = existing.updated(**changes)
    else:
        device = NetworkDevice(
            device_id=args.device_id,
            name=args.name or args.device_id,
            device_type=args.device_type or "generic",
            platform=args.platform or "generic",
            management_address=args.management_address or "",
            enabled=True if args.enabled is None else args.enabled,
            labels=labels,
        )
    hub.set_network_device(device)
    print(json.dumps(device.to_dict(), ensure_ascii=False, indent=2))
    return 0


def cmd_network_device_show(args: argparse.Namespace) -> int:
    hub = Hub(args.db)
    device = hub.get_network_device(args.device_id)
    if not device:
        print("network device not found")
        return 1
    snapshots = hub.list_network_snapshots(limit=20, device_id=args.device_id)
    payload = {
        "device": device.to_dict(),
        "snapshots": [item.to_dict() for item in snapshots],
        "counts": {
            "interfaces": len(hub.list_network_interfaces(device_id=args.device_id, limit=10_000)),
            "vlans": len(hub.list_network_vlans(device_id=args.device_id, limit=10_000)),
            "links": len(hub.list_network_links(device_id=args.device_id, limit=10_000)),
            "routes": len(hub.list_network_routes(device_id=args.device_id, limit=10_000)),
            "policies": len(hub.list_network_policies(device_id=args.device_id, limit=10_000)),
        },
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


def cmd_network_device_list(args: argparse.Namespace) -> int:
    rows = Hub(args.db).list_network_devices(limit=args.limit, enabled_only=args.enabled_only)
    print(json.dumps([item.to_dict() for item in rows], ensure_ascii=False, indent=2))
    return 0


def cmd_network_device_delete(args: argparse.Namespace) -> int:
    deleted = Hub(args.db).delete_network_device(args.device_id)
    print("deleted" if deleted else "network device not found")
    return 0 if deleted else 1


def _persist_network_import(hub: Hub, result, *, device_name: str | None = None, device_type: str | None = None, platform: str | None = None) -> None:
    device = hub.get_network_device(result.snapshot.device_id)
    if not device:
        device = NetworkDevice(
            device_id=result.snapshot.device_id,
            name=device_name or result.snapshot.device_id,
            device_type=device_type or "generic",
            platform=platform or result.snapshot.collector,
            metadata={"auto_registered_by": result.snapshot.collector},
        )
        hub.set_network_device(device)
    hub.add_network_snapshot(
        result.snapshot,
        interfaces=result.interfaces,
        vlans=result.vlans,
        links=result.links,
        routes=result.routes,
        policies=result.policies,
    )


def cmd_network_import(args: argparse.Namespace) -> int:
    hub = Hub(args.db)
    parser = {"frr": parse_frr_json, "ovs": parse_ovs_json, "nft": parse_nft_json}[args.kind]
    try:
        result = parser(args.file, device_id=args.device_id, source_name=args.source)
        if args.kind == "frr":
            result = filter_network_import(
                result,
                exclude_interfaces=args.exclude_interface or [],
                exclude_prefixes=args.exclude_prefix or [],
            )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}")
        return 2
    device_type, platform = _device_defaults(args.kind)
    _persist_network_import(
        hub, result, device_name=args.device_name, device_type=args.device_type or device_type,
        platform=args.platform or platform,
    )
    print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
    return 0


def cmd_network_collect(args: argparse.Namespace) -> int:
    kind_map = {
        "frr-routes": ("frr", parse_frr_json),
        "frr-interfaces": ("frr", parse_frr_json),
        "ovs-ports": ("ovs", parse_ovs_json),
        "nft-ruleset": ("nft", parse_nft_json),
    }
    collector_kind, parser = kind_map[args.kind]
    try:
        raw, run = OpenSourceNetworkCollector().collect(
            args.kind,
            timeout=args.timeout,
            container=args.container,
            runtime=args.runtime,
        )
        source_name = f"live-{args.runtime}-container" if args.container else "live-command"
        result = parser(raw, device_id=args.device_id, source_name=source_name)
        if collector_kind == "frr":
            result = filter_network_import(
                result,
                exclude_interfaces=args.exclude_interface or [],
                exclude_prefixes=args.exclude_prefix or [],
            )
    except (RuntimeError, ValueError) as exc:
        print(f"error: {exc}")
        return 2
    hub = Hub(args.db)
    hub.add_collection_run(run)
    device_type, platform = _device_defaults(collector_kind)
    _persist_network_import(hub, result, device_type=device_type, platform=platform)
    print(json.dumps({"run": run.to_dict(), **result.to_dict()}, ensure_ascii=False, indent=2))
    return 0


def cmd_network_snapshot_list(args: argparse.Namespace) -> int:
    rows = Hub(args.db).list_network_snapshots(limit=args.limit, device_id=args.device_id)
    print(json.dumps([item.to_dict() for item in rows], ensure_ascii=False, indent=2))
    return 0


def cmd_network_snapshot_show(args: argparse.Namespace) -> int:
    hub = Hub(args.db)
    snapshot = hub.get_network_snapshot(args.snapshot_id)
    if not snapshot:
        print("network snapshot not found")
        return 1
    payload = {
        "snapshot": snapshot.to_dict(),
        "interfaces": [x.to_dict() for x in hub.list_network_interfaces(snapshot_id=args.snapshot_id)],
        "vlans": [x.to_dict() for x in hub.list_network_vlans(snapshot_id=args.snapshot_id)],
        "links": [x.to_dict() for x in hub.list_network_links(snapshot_id=args.snapshot_id)],
        "routes": [x.to_dict() for x in hub.list_network_routes(snapshot_id=args.snapshot_id)],
        "policies": [x.to_dict() for x in hub.list_network_policies(snapshot_id=args.snapshot_id)],
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


def _network_entity_output(args: argparse.Namespace, kind: str) -> int:
    hub = Hub(args.db)
    method = {
        "interfaces": hub.list_network_interfaces,
        "vlans": hub.list_network_vlans,
        "links": hub.list_network_links,
        "routes": hub.list_network_routes,
        "policies": hub.list_network_policies,
    }[kind]
    rows = method(device_id=args.device_id, snapshot_id=args.snapshot_id, limit=args.limit)
    print(json.dumps([item.to_dict() for item in rows], ensure_ascii=False, indent=2))
    return 0


def cmd_network_interfaces(args: argparse.Namespace) -> int:
    return _network_entity_output(args, "interfaces")


def cmd_network_vlans(args: argparse.Namespace) -> int:
    return _network_entity_output(args, "vlans")


def cmd_network_links(args: argparse.Namespace) -> int:
    return _network_entity_output(args, "links")


def cmd_network_routes(args: argparse.Namespace) -> int:
    return _network_entity_output(args, "routes")


def cmd_network_policies(args: argparse.Namespace) -> int:
    return _network_entity_output(args, "policies")


def cmd_network_topology(args: argparse.Namespace) -> int:
    hub = Hub(args.db)
    devices = hub.list_network_devices(limit=args.limit)
    interfaces = hub.list_network_interfaces(limit=10_000)
    links = hub.list_network_links(limit=10_000)
    vlans = hub.list_network_vlans(limit=10_000)
    payload = {
        "devices": [item.to_dict() for item in devices],
        "interfaces": [item.to_dict() for item in interfaces],
        "links": [item.to_dict() for item in links],
        "vlans": [item.to_dict() for item in vlans],
        "summary": {
            "devices": len(devices), "interfaces": len(interfaces),
            "links": len(links), "vlans": len(vlans),
        },
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


def _latest_snapshot_id(hub: Hub, device_id: str, collector: str | None = None) -> str | None:
    rows = hub.list_network_snapshots(limit=100, device_id=device_id)
    for row in rows:
        if collector is None or row.collector == collector:
            return row.snapshot_id
    return None


def cmd_network_correlate(args: argparse.Namespace) -> int:
    hub = Hub(args.db)
    flows = hub.list_flow_records(limit=args.limit, target=args.target, capture_id=args.capture_id)
    route_device = args.route_device or args.ingress_device
    policy_device = args.policy_device or args.ingress_device
    vlan_device = args.vlan_device or args.ingress_device
    route_snapshot = _latest_snapshot_id(hub, route_device, "frr")
    policy_snapshot = _latest_snapshot_id(hub, policy_device, "nftables")
    vlan_snapshot = _latest_snapshot_id(hub, vlan_device, "ovs")
    routes = hub.list_network_routes(device_id=route_device, snapshot_id=route_snapshot, limit=20_000)
    policies = hub.list_network_policies(device_id=policy_device, snapshot_id=policy_snapshot, limit=20_000)
    vlans = hub.list_network_vlans(device_id=vlan_device, snapshot_id=vlan_snapshot, limit=10_000)
    assessments = [
        correlate_flow(
            flow,
            ingress_device_id=args.ingress_device,
            routes=routes,
            rules=policies,
            vlans=vlans,
            vrf=args.vrf,
            in_interface=args.in_interface or "",
        )
        for flow in flows
    ]
    for assessment in assessments:
        assessment.evidence.update({
            "route_device": route_device,
            "policy_device": policy_device,
            "vlan_device": vlan_device,
            "route_snapshot": route_snapshot,
            "policy_snapshot": policy_snapshot,
            "vlan_snapshot": vlan_snapshot,
            "in_interface": args.in_interface or "",
        })
    if not args.no_store:
        hub.add_flow_assessments(assessments)
    counts: dict[str, int] = {}
    for item in assessments:
        counts[item.verdict] = counts.get(item.verdict, 0) + 1
    print(json.dumps({
        "summary": {
            "flows": len(flows), "verdicts": counts,
            "route_device": route_device, "policy_device": policy_device,
            "vlan_device": vlan_device,
        },
        "assessments": [item.to_dict() for item in assessments],
    }, ensure_ascii=False, indent=2))
    return 0


def cmd_network_assessments(args: argparse.Namespace) -> int:
    rows = Hub(args.db).list_flow_assessments(
        target=args.target, capture_id=args.capture_id,
        ingress_device_id=args.ingress_device, limit=args.limit,
    )
    print(json.dumps([item.to_dict() for item in rows], ensure_ascii=False, indent=2))
    return 0


def _latest_snapshot_for_device(hub: Hub, device_id: str, collector: str):
    snapshot_id = _latest_snapshot_id(hub, device_id, collector)
    return snapshot_id


def cmd_recommend_generate(args: argparse.Namespace) -> int:
    hub = Hub(args.db)
    assessment = hub.get_flow_assessment(args.assessment_id)
    if not assessment:
        raise ValueError(f"flow assessment not found: {args.assessment_id}")
    flow = hub.get_flow_record(assessment.flow_id)
    if not flow:
        raise ValueError(f"flow record not found: {assessment.flow_id}")

    route_device = args.route_device or str(assessment.evidence.get("route_device") or assessment.ingress_device_id)
    policy_device = args.policy_device or str(assessment.evidence.get("policy_device") or assessment.ingress_device_id)
    vlan_device = args.vlan_device or str(assessment.evidence.get("vlan_device") or assessment.ingress_device_id)

    route_snapshot = _latest_snapshot_for_device(hub, route_device, "frr")
    policy_snapshot = _latest_snapshot_for_device(hub, policy_device, "nftables")
    vlan_snapshot = _latest_snapshot_for_device(hub, vlan_device, "ovs")
    routes = hub.list_network_routes(device_id=route_device, snapshot_id=route_snapshot, limit=20_000)
    policies = hub.list_network_policies(device_id=policy_device, snapshot_id=policy_snapshot, limit=20_000)
    vlans = hub.list_network_vlans(device_id=vlan_device, snapshot_id=vlan_snapshot, limit=10_000)
    interfaces = hub.list_network_interfaces(device_id=vlan_device, snapshot_id=vlan_snapshot, limit=10_000)

    recommendation = RecommendationEngine().generate(
        assessment,
        flow,
        routes=routes,
        policies=policies,
        vlans=vlans,
        interfaces=interfaces,
        route_device_id=route_device,
        policy_device_id=policy_device,
        vlan_device_id=vlan_device,
        destination_prefix=args.destination_prefix or "",
        next_hop=args.next_hop or "",
        out_interface=args.out_interface or "",
        access_interface=args.access_interface or "",
        trunk_interface=args.trunk_interface or "",
    )
    recommendation.metadata = {
        **recommendation.metadata,
        "source_devices": {
            "route_device": route_device,
            "policy_device": policy_device,
            "vlan_device": vlan_device,
        },
        "source_snapshots": {
            "route_snapshot": route_snapshot,
            "policy_snapshot": policy_snapshot,
            "vlan_snapshot": vlan_snapshot,
        },
        "execution_boundary": "review-only; no configuration was applied",
    }
    if not args.no_store:
        hub.add_configuration_recommendations([recommendation])
    print(json.dumps(recommendation.to_dict(), ensure_ascii=False, indent=2))
    return 0



def _recommendation_context(hub: Hub, assessment_id: str, args: argparse.Namespace) -> dict:
    assessment = hub.get_flow_assessment(assessment_id)
    if not assessment:
        raise ValueError(f"flow assessment not found: {assessment_id}")
    flow = hub.get_flow_record(assessment.flow_id)
    if not flow:
        raise ValueError(f"flow record not found: {assessment.flow_id}")
    route_device = getattr(args, "route_device", None) or str(
        assessment.evidence.get("route_device") or assessment.ingress_device_id
    )
    policy_device = getattr(args, "policy_device", None) or str(
        assessment.evidence.get("policy_device") or assessment.ingress_device_id
    )
    vlan_device = getattr(args, "vlan_device", None) or str(
        assessment.evidence.get("vlan_device") or assessment.ingress_device_id
    )
    route_snapshot = _latest_snapshot_for_device(hub, route_device, "frr")
    policy_snapshot = _latest_snapshot_for_device(hub, policy_device, "nftables")
    vlan_snapshot = _latest_snapshot_for_device(hub, vlan_device, "ovs")
    return {
        "assessment": assessment,
        "flow": flow,
        "route_device": route_device,
        "policy_device": policy_device,
        "vlan_device": vlan_device,
        "route_snapshot": route_snapshot,
        "policy_snapshot": policy_snapshot,
        "vlan_snapshot": vlan_snapshot,
        "routes": hub.list_network_routes(device_id=route_device, snapshot_id=route_snapshot, limit=20_000),
        "policies": hub.list_network_policies(device_id=policy_device, snapshot_id=policy_snapshot, limit=20_000),
        "vlans": hub.list_network_vlans(device_id=vlan_device, snapshot_id=vlan_snapshot, limit=10_000),
        "interfaces": hub.list_network_interfaces(device_id=vlan_device, snapshot_id=vlan_snapshot, limit=10_000),
    }


def cmd_recommend_candidates(args: argparse.Namespace) -> int:
    hub = Hub(args.db)
    context = _recommendation_context(hub, args.assessment_id, args)
    graph = build_evidence_graph(
        context["assessment"], context["flow"],
        routes=context["routes"], policies=context["policies"],
        vlans=context["vlans"], interfaces=context["interfaces"],
    )
    candidates = RecommendationEngine().generate_candidates(
        context["assessment"], context["flow"],
        routes=context["routes"], policies=context["policies"],
        vlans=context["vlans"], interfaces=context["interfaces"],
        route_device_id=context["route_device"],
        policy_device_id=context["policy_device"],
        vlan_device_id=context["vlan_device"],
        destination_prefix=args.destination_prefix or "",
        next_hop=args.next_hop or "",
        out_interface=args.out_interface or "",
        access_interface=args.access_interface or "",
        trunk_interface=args.trunk_interface or "",
    )
    source_metadata = {
        "source_devices": {
            "route_device": context["route_device"],
            "policy_device": context["policy_device"],
            "vlan_device": context["vlan_device"],
        },
        "source_snapshots": {
            "route_snapshot": context["route_snapshot"],
            "policy_snapshot": context["policy_snapshot"],
            "vlan_snapshot": context["vlan_snapshot"],
        },
        "evidence_graph_id": graph.graph_id,
        "execution_boundary": "review-only until explicit virtual-lab approval",
    }
    for item in candidates:
        item.metadata = {**item.metadata, **source_metadata}
    ranked = RecommendationRanker().rank(candidates, evidence_graph=graph)
    if not args.no_store:
        hub.add_evidence_graphs([graph])
        hub.add_configuration_recommendations([item.recommendation for item in ranked])
    print(json.dumps({
        "evidence_graph": graph.to_dict(),
        "ranked_candidates": [item.to_dict() for item in ranked],
        "execution_boundary": "no configuration was applied",
    }, ensure_ascii=False, indent=2))
    return 0


def cmd_recommend_evidence(args: argparse.Namespace) -> int:
    hub = Hub(args.db)
    context = _recommendation_context(hub, args.assessment_id, args)
    graph = build_evidence_graph(
        context["assessment"], context["flow"],
        routes=context["routes"], policies=context["policies"],
        vlans=context["vlans"], interfaces=context["interfaces"],
    )
    if not args.no_store:
        hub.add_evidence_graphs([graph])
    if args.output:
        path = export_evidence_graph(graph, output=args.output, format_name=args.format)
        print(path)
    else:
        if args.format == "dot":
            print(graph.to_dot(), end="")
        else:
            print(json.dumps(graph.to_dict(), ensure_ascii=False, indent=2))
    return 0


def cmd_recommend_review(args: argparse.Namespace) -> int:
    hub = Hub(args.db)
    item = hub.get_configuration_recommendation(args.recommendation_id)
    if not item:
        raise ValueError(f"configuration recommendation not found: {args.recommendation_id}")
    if args.status == "APPROVED":
        require_approval_eligible(item)
    updated = hub.set_configuration_recommendation_status(
        args.recommendation_id, args.status,
        reviewed_by=args.reviewed_by, note=args.note or "",
    )
    print(json.dumps(updated.to_dict(), ensure_ascii=False, indent=2))
    return 0


def cmd_recommend_apply_lab(args: argparse.Namespace) -> int:
    hub = Hub(args.db)
    item = hub.get_configuration_recommendation(args.recommendation_id)
    if not item:
        raise ValueError(f"configuration recommendation not found: {args.recommendation_id}")
    execution = VirtualLabExecutor(
        runtime=args.runtime, lab_name=args.lab_name, timeout=args.timeout,
    ).execute(
        item,
        approved_by=args.approved_by,
        environment=args.environment,
        client_node=args.client_node,
        verify_url=args.verify_url,
        rollback_after_verify=not args.keep_change,
    )
    hub.add_remediation_executions([execution])
    print(json.dumps(execution.to_dict(), ensure_ascii=False, indent=2))
    return 0 if execution.status in {"VERIFIED", "ROLLED_BACK"} else 1


def cmd_recommend_executions(args: argparse.Namespace) -> int:
    rows = Hub(args.db).list_remediation_executions(
        recommendation_id=args.recommendation_id,
        status=args.status,
        limit=args.limit,
    )
    print(json.dumps([item.to_dict() for item in rows], ensure_ascii=False, indent=2))
    return 0


def cmd_recommend_execution_show(args: argparse.Namespace) -> int:
    item = Hub(args.db).get_remediation_execution(args.execution_id)
    if not item:
        raise ValueError(f"remediation execution not found: {args.execution_id}")
    print(json.dumps(item.to_dict(), ensure_ascii=False, indent=2))
    return 0

def cmd_recommend_list(args: argparse.Namespace) -> int:
    rows = Hub(args.db).list_configuration_recommendations(
        target=args.target,
        assessment_id=args.assessment_id,
        category=args.category,
        status=args.status,
        limit=args.limit,
    )
    print(json.dumps([item.to_dict() for item in rows], ensure_ascii=False, indent=2))
    return 0


def cmd_recommend_show(args: argparse.Namespace) -> int:
    item = Hub(args.db).get_configuration_recommendation(args.recommendation_id)
    if not item:
        raise ValueError(f"configuration recommendation not found: {args.recommendation_id}")
    print(json.dumps(item.to_dict(), ensure_ascii=False, indent=2))
    return 0


def cmd_recommend_export(args: argparse.Namespace) -> int:
    item = Hub(args.db).get_configuration_recommendation(args.recommendation_id)
    if not item:
        raise ValueError(f"configuration recommendation not found: {args.recommendation_id}")
    path = export_recommendation(item, output=args.output, format_name=args.format)
    print(path)
    return 0


def cmd_recommend_validate(args: argparse.Namespace) -> int:
    item = Hub(args.db).get_configuration_recommendation(args.recommendation_id)
    if not item:
        raise ValueError(f"configuration recommendation not found: {args.recommendation_id}")
    issues = []
    try:
        item.validate()
    except ValueError as exc:
        issues.append(str(exc))
    if item.category != "MANUAL_REVIEW" and item.simulation_status != "PASSED":
        issues.append(f"model-level what-if did not pass: {item.simulation_status} / {item.simulated_verdict}")
    if any("<" in command and ">" in command for command in item.commands):
        issues.append("command templates still contain unresolved placeholders")
    payload = {
        "recommendation_id": item.recommendation_id,
        "valid": not issues,
        "issues": issues,
        "simulation_status": item.simulation_status,
        "simulated_verdict": item.simulated_verdict,
        "execution_boundary": "validation only; no configuration was applied",
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0 if not issues else 1



def _parse_numeric_labels(values: list[str] | None, *, kind: str) -> dict[str, float]:
    raw = parse_labels(values)
    result: dict[str, float] = {}
    for key, value in raw.items():
        try:
            result[key] = float(value)
        except ValueError as exc:
            raise ValueError(f"{kind} value must be numeric: {key}={value}") from exc
    return result


def _load_json_object(path: str | None) -> dict:
    if not path:
        return {}
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"JSON file must contain an object: {path}")
    return payload


def cmd_experiment_create(args: argparse.Namespace) -> int:
    item = ExperimentDefinition(
        name=args.name,
        description=args.description or "",
        scenarios=args.scenario,
        repetitions=args.repetitions,
        base_seed=args.base_seed,
        baselines=args.baseline or [],
        metrics=args.metric or [],
        tags=parse_labels(args.tag),
        metadata=parse_labels(args.metadata),
    )
    if not item.metrics:
        from .experiment import DEFAULT_METRICS
        item.metrics = list(DEFAULT_METRICS)
    Hub(args.db).add_experiments([item])
    print(json.dumps(item.to_dict(), ensure_ascii=False, indent=2))
    return 0


def cmd_experiment_list(args: argparse.Namespace) -> int:
    rows = Hub(args.db).list_experiments(status=args.status, limit=args.limit)
    print(json.dumps([item.to_dict() for item in rows], ensure_ascii=False, indent=2))
    return 0


def cmd_experiment_show(args: argparse.Namespace) -> int:
    hub = Hub(args.db)
    item = hub.get_experiment(args.experiment_id)
    if item is None:
        raise ValueError(f"experiment not found: {args.experiment_id}")
    trials = hub.list_experiment_trials(experiment_id=item.experiment_id, limit=args.trial_limit)
    payload = item.to_dict()
    payload["trial_count"] = len(trials)
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


def cmd_experiment_status(args: argparse.Namespace) -> int:
    item = Hub(args.db).set_experiment_status(args.experiment_id, args.status)
    print(json.dumps(item.to_dict(), ensure_ascii=False, indent=2))
    return 0


def cmd_experiment_record(args: argparse.Namespace) -> int:
    environment = _load_json_object(args.environment_manifest)
    if args.capture_environment:
        environment = {**capture_environment(labels=parse_labels(args.environment_label)), **environment}
    item = ExperimentTrial(
        experiment_id=args.experiment_id,
        scenario_id=args.scenario_id,
        repetition=args.repetition,
        seed=args.seed,
        status=args.status,
        expected_verdict=args.expected_verdict or "",
        observed_verdict=args.observed_verdict or "",
        expected_category=args.expected_category or "",
        observed_category=args.observed_category or "",
        expected_recovery=args.expected_recovery,
        recovered=args.recovered,
        timings_ms=_parse_numeric_labels(args.timing, kind="timing"),
        counters=_parse_numeric_labels(args.counter, kind="counter"),
        artifacts=parse_labels(args.artifact),
        environment=environment,
        error=args.error or "",
        metadata=parse_labels(args.metadata),
    )
    Hub(args.db).add_experiment_trials([item])
    print(json.dumps(item.to_dict(), ensure_ascii=False, indent=2))
    return 0


def cmd_experiment_trials(args: argparse.Namespace) -> int:
    rows = Hub(args.db).list_experiment_trials(
        experiment_id=args.experiment_id,
        scenario_id=args.scenario_id,
        status=args.status,
        limit=args.limit,
    )
    print(json.dumps([item.to_dict() for item in rows], ensure_ascii=False, indent=2))
    return 0


def cmd_experiment_import_lab(args: argparse.Namespace) -> int:
    hub = Hub(args.db)
    experiment = hub.get_experiment(args.experiment_id)
    if experiment is None:
        raise ValueError(f"experiment not found: {args.experiment_id}")
    environment = _load_json_object(args.environment_manifest)
    if args.capture_environment:
        environment = {**capture_environment(labels=parse_labels(args.environment_label)), **environment}
    rows = import_lab_summary(
        args.summary,
        experiment_id=experiment.experiment_id,
        repetition=args.repetition,
        seed=args.seed,
        environment=environment,
    )
    inserted = hub.add_experiment_trials(rows)
    print(json.dumps({
        "experiment_id": experiment.experiment_id,
        "summary": str(Path(args.summary)),
        "imported_trials": inserted,
        "trial_ids": [item.trial_id for item in rows],
    }, ensure_ascii=False, indent=2))
    return 0


def cmd_experiment_summarize(args: argparse.Namespace) -> int:
    hub = Hub(args.db)
    experiment = hub.get_experiment(args.experiment_id)
    if experiment is None:
        raise ValueError(f"experiment not found: {args.experiment_id}")
    trials = hub.list_experiment_trials(experiment_id=experiment.experiment_id, limit=args.limit)
    payload = summarize_trials(experiment, trials)
    content = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output:
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        print(str(path))
    else:
        print(content, end="")
    return 0


def cmd_experiment_export(args: argparse.Namespace) -> int:
    hub = Hub(args.db)
    experiment = hub.get_experiment(args.experiment_id)
    if experiment is None:
        raise ValueError(f"experiment not found: {args.experiment_id}")
    trials = hub.list_experiment_trials(experiment_id=experiment.experiment_id, limit=args.limit)
    paths = export_experiment(experiment, trials, output_dir=args.output_dir)
    print(json.dumps({key: str(value) for key, value in paths.items()}, indent=2))
    return 0


def cmd_experiment_manifest(args: argparse.Namespace) -> int:
    path = write_environment_manifest(args.output, labels=parse_labels(args.label))
    print(str(path))
    return 0


def cmd_experiment_catalog_validate(args: argparse.Namespace) -> int:
    rows = load_scenario_catalog(args.file)
    payload = {
        "file": str(Path(args.file)),
        "scenario_count": len(rows),
        "implemented": sum(item.implemented for item in rows),
        "planned": sum(not item.implemented for item in rows),
        "layers": sorted({item.layer for item in rows}),
        "scenario_ids": [item.scenario_id for item in rows],
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="kansoku", description="KANSOKU v0.10.0 CLI")
    parser.add_argument("--db", default="./kansoku.db", help="SQLite database path")
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="initialize or migrate the local hub database")
    p_init.set_defaults(func=cmd_init)

    p_agent = sub.add_parser("agent", help="collect observations")
    agent_sub = p_agent.add_subparsers(dest="agent_command", required=True)
    p_sim = agent_sub.add_parser("simulate", help="insert simulated observations")
    p_sim.add_argument("--target", required=True)
    p_sim.add_argument("--profile", choices=["normal", "warning", "degraded", "critical"], default="normal")
    p_sim.add_argument("--count", type=int, default=5)
    _add_auto_evaluate_flag(p_sim)
    p_sim.set_defaults(func=cmd_agent_simulate)

    p_ping = agent_sub.add_parser("ping", help="collect platform-aware ping observations")
    p_ping.add_argument("--target", required=True)
    p_ping.add_argument("--count", type=int, default=4)
    p_ping.add_argument("--timeout", type=float, default=5.0, help="per-packet timeout in seconds")
    p_ping.add_argument("--raw-dir", default="./artifacts/raw")
    _add_auto_evaluate_flag(p_ping)
    p_ping.set_defaults(func=cmd_agent_ping)

    p_iperf = agent_sub.add_parser("iperf3", help="collect iperf3 JSON measurements")
    p_iperf.add_argument("--target", required=True, help="iperf3 server hostname or address")
    p_iperf.add_argument("--port", type=int, default=5201)
    p_iperf.add_argument("--duration", type=int, default=10)
    p_iperf.add_argument("--parallel", type=int, default=1)
    p_iperf.add_argument("--reverse", action="store_true")
    p_iperf.add_argument("--udp", action="store_true")
    p_iperf.add_argument("--bitrate", help="UDP target bitrate, e.g. 100M")
    p_iperf.add_argument("--connect-timeout-ms", type=int, default=5000)
    p_iperf.add_argument("--raw-dir", default="./artifacts/raw")
    _add_auto_evaluate_flag(p_iperf)
    p_iperf.set_defaults(func=cmd_agent_iperf3)

    p_watch = agent_sub.add_parser("watch", help="continuously observe a target using the active plan")
    p_watch.add_argument("--target", required=True)
    p_watch.add_argument("--count", type=int, default=3)
    p_watch.add_argument("--timeout", type=float, default=5.0)
    p_watch.add_argument("--interval", type=int, help="fallback interval if no plan/profile exists")
    p_watch.add_argument("--iterations", type=int, default=0, help="0 means run until Ctrl+C")
    p_watch.add_argument("--limit", type=int, default=100)
    p_watch.add_argument("--raw-dir", default="./artifacts/raw")
    p_watch.add_argument("--iperf3-every", type=int, default=0, help="run iperf3 every N cycles; 0 disables it")
    p_watch.add_argument("--port", type=int, default=5201)
    p_watch.add_argument("--duration", type=int, default=10)
    p_watch.add_argument("--parallel", type=int, default=1)
    p_watch.add_argument("--connect-timeout-ms", type=int, default=5000)
    p_watch.add_argument(
        "--auto-apply-low-risk",
        action="store_true",
        help="Guard and apply low-risk observation-rate proposals",
    )
    p_watch.set_defaults(func=cmd_agent_watch)

    p_run = sub.add_parser("run", help="inspect raw collection runs")
    run_sub = p_run.add_subparsers(dest="run_command", required=True)
    p_run_show = run_sub.add_parser("show", help="show a collection run including raw output")
    p_run_show.add_argument("--run-id", required=True)
    p_run_show.set_defaults(func=cmd_run_show)

    p_replay = sub.add_parser("replay", help="replay observation traces")
    replay_sub = p_replay.add_subparsers(dest="replay_command", required=True)
    p_csv = replay_sub.add_parser("csv", help="load observations from CSV")
    p_csv.add_argument("--csv", required=True)
    p_csv.add_argument("--target")
    _add_auto_evaluate_flag(p_csv)
    p_csv.set_defaults(func=cmd_replay_csv)

    p_state = sub.add_parser("state", help="state estimation")
    state_sub = p_state.add_subparsers(dest="state_command", required=True)
    p_eval = state_sub.add_parser("evaluate", help="evaluate target state")
    p_eval.add_argument("--target", required=True)
    p_eval.add_argument("--limit", type=int, default=100)
    p_eval.set_defaults(func=cmd_state_evaluate)

    p_profile = sub.add_parser("profile", help="manage target-specific evaluation profiles")
    profile_sub = p_profile.add_subparsers(dest="profile_command", required=True)
    p_profile_set = profile_sub.add_parser("set", help="create or update a target profile")
    p_profile_set.add_argument("--target", required=True)
    p_profile_set.add_argument("--name")
    p_profile_set.add_argument("--expected-bandwidth", type=float)
    p_profile_set.add_argument("--baseline-throughput", type=float)
    p_profile_set.add_argument("--normal-ratio", type=float)
    p_profile_set.add_argument("--warning-ratio", type=float)
    p_profile_set.add_argument("--degraded-ratio", type=float)
    p_profile_set.add_argument("--rtt-warning", type=float)
    p_profile_set.add_argument("--rtt-degraded", type=float)
    p_profile_set.add_argument("--rtt-critical", type=float)
    p_profile_set.add_argument("--loss-warning", type=float)
    p_profile_set.add_argument("--loss-degraded", type=float)
    p_profile_set.add_argument("--loss-critical", type=float)
    p_profile_set.add_argument("--normal-interval", type=int)
    p_profile_set.add_argument("--warning-interval", type=int)
    p_profile_set.set_defaults(func=cmd_profile_set)

    p_profile_show = profile_sub.add_parser("show", help="show a target profile")
    p_profile_show.add_argument("--target", required=True)
    p_profile_show.set_defaults(func=cmd_profile_show)
    p_profile_list = profile_sub.add_parser("list", help="list target profiles")
    p_profile_list.add_argument("--limit", type=int, default=100)
    p_profile_list.set_defaults(func=cmd_profile_list)
    p_profile_delete = profile_sub.add_parser("delete", help="delete a target profile")
    p_profile_delete.add_argument("--target", required=True)
    p_profile_delete.set_defaults(func=cmd_profile_delete)
    p_profile_learn = profile_sub.add_parser("learn-baseline", help="learn median throughput baseline")
    p_profile_learn.add_argument("--target", required=True)
    p_profile_learn.add_argument("--limit", type=int, default=20)
    p_profile_learn.add_argument("--minimum-samples", type=int, default=1)
    p_profile_learn.set_defaults(func=cmd_profile_learn)

    p_plan = sub.add_parser("plan", help="inspect the active observation plan")
    plan_sub = p_plan.add_subparsers(dest="plan_command", required=True)
    p_plan_show = plan_sub.add_parser("show", help="show the target observation plan")
    p_plan_show.add_argument("--target", required=True)
    p_plan_show.set_defaults(func=cmd_plan_show)

    p_policy = sub.add_parser("policy", help="manage target-scoped safety policies")
    policy_sub = p_policy.add_subparsers(dest="policy_command", required=True)
    p_policy_set = policy_sub.add_parser("set", help="create or update a safety policy")
    p_policy_set.add_argument("--target", required=True, help="target or * for the default policy")
    p_policy_set.add_argument("--name")
    p_policy_set.add_argument("--allowed-actions", help="comma-separated action names")
    p_policy_set.add_argument("--auto-approve-actions", help="comma-separated action names")
    p_policy_set.add_argument("--approval-required-actions", help="comma-separated action names")
    p_policy_set.add_argument("--rollback-required-actions", help="comma-separated action names")
    p_policy_set.add_argument("--blocked-actions", help="comma-separated action names")
    p_policy_set.add_argument("--blocked-targets", help="comma-separated target names")
    p_policy_set.add_argument("--minimum-interval", type=int)
    p_policy_set.add_argument(
        "--allow-system-changes", action=argparse.BooleanOptionalAction, default=None
    )
    p_policy_set.add_argument(
        "--rollback-on-failure", action=argparse.BooleanOptionalAction, default=None
    )
    p_policy_set.set_defaults(func=cmd_policy_set)
    p_policy_show = policy_sub.add_parser("show", help="show the effective safety policy")
    p_policy_show.add_argument("--target", required=True)
    p_policy_show.set_defaults(func=cmd_policy_show)
    p_policy_list = policy_sub.add_parser("list", help="list persisted safety policies")
    p_policy_list.add_argument("--limit", type=int, default=100)
    p_policy_list.set_defaults(func=cmd_policy_list)
    p_policy_delete = policy_sub.add_parser("delete", help="delete a safety policy")
    p_policy_delete.add_argument("--target", required=True)
    p_policy_delete.set_defaults(func=cmd_policy_delete)

    p_approval = sub.add_parser("approval", help="record explicit human approvals")
    approval_sub = p_approval.add_subparsers(dest="approval_command", required=True)
    p_approval_set = approval_sub.add_parser("set", help="approve or reject a proposal")
    p_approval_set.add_argument("--proposal-id", required=True)
    p_approval_set.add_argument("--decision", choices=["approve", "reject"], required=True)
    p_approval_set.add_argument("--actor", required=True)
    p_approval_set.add_argument("--comment")
    p_approval_set.set_defaults(func=cmd_approval_set)
    p_approval_show = approval_sub.add_parser("show", help="show latest approval record")
    p_approval_show.add_argument("--proposal-id", required=True)
    p_approval_show.set_defaults(func=cmd_approval_show)

    p_controller = sub.add_parser("controller", help="run the safe action lifecycle")
    controller_sub = p_controller.add_subparsers(dest="controller_command", required=True)
    p_controller_process = controller_sub.add_parser(
        "process", help="Guard, execute, verify, and optionally rollback a proposal"
    )
    p_controller_process.add_argument("--target")
    p_controller_process.add_argument("--proposal-id")
    p_controller_process.add_argument("--execute", action="store_true")
    p_controller_process.add_argument(
        "--allow-system-changes", action="store_true",
        help="permit system adapters only when the persisted policy also allows them",
    )
    p_controller_process.set_defaults(func=cmd_controller_process)
    p_controller_status = controller_sub.add_parser("status", help="show controller transactions")
    p_controller_status.add_argument("--target")
    p_controller_status.add_argument("--limit", type=int, default=20)
    p_controller_status.set_defaults(func=cmd_controller_status)

    p_guard = sub.add_parser("guard", help="guard action proposals")
    guard_sub = p_guard.add_subparsers(dest="guard_command", required=True)
    p_val = guard_sub.add_parser("validate", help="validate latest or specified proposal")
    p_val.add_argument("--target")
    p_val.add_argument("--proposal-id")
    p_val.set_defaults(func=cmd_guard_validate)

    p_act = sub.add_parser("act", help="execute approved actions")
    act_sub = p_act.add_subparsers(dest="act_command", required=True)
    p_exec = act_sub.add_parser("execute", help="execute latest or specified approved proposal")
    p_exec.add_argument("--target")
    p_exec.add_argument("--proposal-id")
    p_exec.add_argument("--execute", action="store_true", help="actually execute; default is dry-run")
    p_exec.add_argument("--allow-system-changes", action="store_true")
    p_exec.set_defaults(func=cmd_act_execute)

    p_capture = sub.add_parser("capture", help="capture packets and aggregate privacy-aware flow metadata")
    capture_sub = p_capture.add_subparsers(dest="capture_command", required=True)
    p_cap_if = capture_sub.add_parser("interfaces", help="list tcpdump capture interfaces")
    p_cap_if.add_argument("--tcpdump-bin", default="tcpdump")
    p_cap_if.set_defaults(func=cmd_capture_interfaces)
    p_cap_summary = capture_sub.add_parser("summarize", help="parse a classic pcap file without live capture")
    p_cap_summary.add_argument("--pcap", required=True)
    p_cap_summary.add_argument("--target", required=True)
    p_cap_summary.add_argument("--source")
    p_cap_summary.add_argument("--interface", default="offline")
    p_cap_summary.add_argument("--filter", default="")
    p_cap_summary.add_argument("--snaplen", type=int, default=0)
    p_cap_summary.add_argument("--retention-days", type=int, default=7)
    p_cap_summary.add_argument("--max-flows", type=int, default=10_000)
    p_cap_summary.add_argument("--flow-limit", type=int, default=20)
    p_cap_summary.add_argument("--no-store", action="store_true")
    p_cap_summary.add_argument(
        "--force-reimport",
        action="store_true",
        help="store another capture session even when target, source, and SHA-256 match",
    )
    p_cap_summary.set_defaults(func=cmd_capture_summarize)
    p_cap_run = capture_sub.add_parser("run", help="capture with tcpdump, store pcap locally, and persist metadata")
    p_cap_run.add_argument("--target", required=True)
    p_cap_run.add_argument("--interface", required=True)
    p_cap_run.add_argument("--duration", type=float, default=10.0)
    p_cap_run.add_argument("--packet-limit", type=int, default=0)
    p_cap_run.add_argument("--filter", default="")
    p_cap_run.add_argument("--snaplen", type=int, default=96, help="header-only default; use --full-packet explicitly for complete packets")
    p_cap_run.add_argument("--full-packet", action="store_true")
    p_cap_run.add_argument("--source")
    p_cap_run.add_argument("--tcpdump-bin", default="tcpdump")
    p_cap_run.add_argument("--use-sudo", action="store_true")
    p_cap_run.add_argument("--output-dir", default="~/.kansoku/pcap")
    p_cap_run.add_argument("--raw-dir", default="artifacts/raw")
    p_cap_run.add_argument("--retention-days", type=int, default=7)
    p_cap_run.add_argument("--quota-mb", type=int, default=512)
    p_cap_run.add_argument("--max-flows", type=int, default=10_000)
    p_cap_run.add_argument("--flow-limit", type=int, default=20)
    _add_auto_evaluate_flag(p_cap_run)
    p_cap_run.set_defaults(func=cmd_capture_run)
    p_cap_list = capture_sub.add_parser("list", help="list persisted capture sessions")
    p_cap_list.add_argument("--target")
    p_cap_list.add_argument("--limit", type=int, default=100)
    p_cap_list.set_defaults(func=cmd_capture_list)
    p_cap_show = capture_sub.add_parser("show", help="show a capture session and top flows")
    p_cap_show.add_argument("--capture-id", required=True)
    p_cap_show.add_argument("--flow-limit", type=int, default=100)
    p_cap_show.set_defaults(func=cmd_capture_show)
    p_cap_flows = capture_sub.add_parser("flows", help="list aggregated flow records")
    p_cap_flows.add_argument("--target")
    p_cap_flows.add_argument("--capture-id")
    p_cap_flows.add_argument("--limit", type=int, default=100)
    p_cap_flows.set_defaults(func=cmd_capture_flows)
    p_cap_prune = capture_sub.add_parser("prune", help="apply pcap retention and storage quota")
    p_cap_prune.add_argument("--target")
    p_cap_prune.add_argument("--output-dir", default="~/.kansoku/pcap")
    p_cap_prune.add_argument("--retention-days", type=int, default=7)
    p_cap_prune.add_argument("--quota-mb", type=int, default=512)
    p_cap_prune.add_argument("--dry-run", action="store_true")
    p_cap_prune.set_defaults(func=cmd_capture_prune)

    p_target = sub.add_parser("target", help="manage the persistent target inventory")
    target_sub = p_target.add_subparsers(dest="target_command", required=True)
    p_target_set = target_sub.add_parser("set", help="register or update a managed target")
    p_target_set.add_argument("--target", required=True)
    p_target_set.add_argument("--name")
    p_target_set.add_argument("--enabled", action=argparse.BooleanOptionalAction, default=None)
    p_target_set.add_argument("--ping-enabled", action=argparse.BooleanOptionalAction, default=None)
    p_target_set.add_argument("--ping-count", type=int)
    p_target_set.add_argument("--ping-timeout", type=float)
    p_target_set.add_argument("--iperf3-enabled", action=argparse.BooleanOptionalAction, default=None)
    p_target_set.add_argument("--iperf3-port", type=int)
    p_target_set.add_argument("--iperf3-duration", type=int)
    p_target_set.add_argument("--iperf3-parallel", type=int)
    p_target_set.add_argument("--iperf3-every", type=int, help="run iperf3 every N service cycles")
    p_target_set.add_argument("--auto-process-low-risk", action=argparse.BooleanOptionalAction, default=None)
    p_target_set.add_argument("--raw-dir")
    p_target_set.set_defaults(func=cmd_target_set)
    p_target_show = target_sub.add_parser("show", help="show a managed target")
    p_target_show.add_argument("--target", required=True)
    p_target_show.set_defaults(func=cmd_target_show)
    p_target_list = target_sub.add_parser("list", help="list managed targets")
    p_target_list.add_argument("--limit", type=int, default=100)
    p_target_list.add_argument("--enabled-only", action="store_true")
    p_target_list.set_defaults(func=cmd_target_list)
    p_target_delete = target_sub.add_parser("delete", help="remove a target from the service inventory")
    p_target_delete.add_argument("--target", required=True)
    p_target_delete.set_defaults(func=cmd_target_delete)
    p_target_enable = target_sub.add_parser("enable", help="enable service scheduling for a target")
    p_target_enable.add_argument("--target", required=True)
    p_target_enable.set_defaults(func=cmd_target_enable, enabled=True)
    p_target_disable = target_sub.add_parser("disable", help="disable service scheduling for a target")
    p_target_disable.add_argument("--target", required=True)
    p_target_disable.set_defaults(func=cmd_target_enable, enabled=False)

    p_service = sub.add_parser("service", help="run the persistent multi-target observation service")
    service_sub = p_service.add_subparsers(dest="service_command", required=True)
    p_service_once = service_sub.add_parser("once", help="run one due observation cycle")
    p_service_once.add_argument("--target")
    p_service_once.add_argument("--force", action="store_true")
    p_service_once.add_argument("--no-auto-control", action="store_true")
    p_service_once.add_argument("--simulate-profile", choices=["normal", "warning", "degraded", "critical"])
    p_service_once.add_argument("--owner-id")
    p_service_once.add_argument("--lease-ttl", type=int, default=120)
    p_service_once.set_defaults(func=cmd_service_once)
    p_service_run = service_sub.add_parser("run", help="poll the fleet and run targets when due")
    p_service_run.add_argument("--target")
    p_service_run.add_argument("--iterations", type=int, default=0, help="0 means run until Ctrl+C")
    p_service_run.add_argument("--poll-interval", type=float, default=1.0)
    p_service_run.add_argument("--force-first", action="store_true")
    p_service_run.add_argument("--no-auto-control", action="store_true")
    p_service_run.add_argument("--simulate-profile", choices=["normal", "warning", "degraded", "critical"])
    p_service_run.add_argument("--owner-id")
    p_service_run.set_defaults(func=cmd_service_run)
    p_service_status = service_sub.add_parser("status", help="show fleet due state and scheduler health")
    p_service_status.add_argument("--target")
    p_service_status.add_argument("--owner-id")
    p_service_status.set_defaults(func=cmd_service_status)
    p_service_cycles = service_sub.add_parser("cycles", help="show persisted scheduler cycles")
    p_service_cycles.add_argument("--target")
    p_service_cycles.add_argument("--limit", type=int, default=50)
    p_service_cycles.set_defaults(func=cmd_service_cycles)
    p_service_lease = service_sub.add_parser("lease", help="inspect or recover the scheduler lease")
    lease_sub = p_service_lease.add_subparsers(dest="lease_command", required=True)
    p_lease_show = lease_sub.add_parser("show")
    p_lease_show.set_defaults(func=cmd_service_lease_show)
    p_lease_release = lease_sub.add_parser("release")
    p_lease_release.add_argument("--owner-id")
    p_lease_release.add_argument("--force", action="store_true")
    p_lease_release.set_defaults(func=cmd_service_lease_release)

    p_network = sub.add_parser("network", help="manage vendor-neutral network configuration and state")
    network_sub = p_network.add_subparsers(dest="network_command", required=True)

    p_ndev = network_sub.add_parser("device", help="manage network-device inventory")
    ndev_sub = p_ndev.add_subparsers(dest="network_device_command", required=True)
    p_ndev_set = ndev_sub.add_parser("set")
    p_ndev_set.add_argument("--device-id", required=True)
    p_ndev_set.add_argument("--name")
    p_ndev_set.add_argument("--device-type", choices=["router", "l2_switch", "l3_switch", "firewall", "host", "generic"])
    p_ndev_set.add_argument("--platform")
    p_ndev_set.add_argument("--management-address")
    p_ndev_set.add_argument("--enabled", action=argparse.BooleanOptionalAction, default=None)
    p_ndev_set.add_argument("--label", action="append", default=[])
    p_ndev_set.set_defaults(func=cmd_network_device_set)
    p_ndev_show = ndev_sub.add_parser("show")
    p_ndev_show.add_argument("--device-id", required=True)
    p_ndev_show.set_defaults(func=cmd_network_device_show)
    p_ndev_list = ndev_sub.add_parser("list")
    p_ndev_list.add_argument("--limit", type=int, default=200)
    p_ndev_list.add_argument("--enabled-only", action="store_true")
    p_ndev_list.set_defaults(func=cmd_network_device_list)
    p_ndev_delete = ndev_sub.add_parser("delete")
    p_ndev_delete.add_argument("--device-id", required=True)
    p_ndev_delete.set_defaults(func=cmd_network_device_delete)

    p_nimport = network_sub.add_parser("import", help="import FRR, Open vSwitch, or nftables JSON")
    p_nimport.add_argument("kind", choices=["frr", "ovs", "nft"])
    p_nimport.add_argument("--file", required=True)
    p_nimport.add_argument("--device-id", required=True)
    p_nimport.add_argument("--device-name")
    p_nimport.add_argument("--device-type", choices=["router", "l2_switch", "l3_switch", "firewall", "host", "generic"])
    p_nimport.add_argument("--platform")
    p_nimport.add_argument("--source", default="offline")
    p_nimport.add_argument(
        "--exclude-interface", action="append", default=[],
        help="exclude routes using this interface (repeatable; useful for management interfaces)",
    )
    p_nimport.add_argument(
        "--exclude-prefix", action="append", default=[],
        help="exclude this route prefix after normalization (repeatable)",
    )
    p_nimport.set_defaults(func=cmd_network_import)

    p_ncollect = network_sub.add_parser("collect", help="run a read-only open-source network-state command")
    p_ncollect.add_argument("kind", choices=["frr-routes", "frr-interfaces", "ovs-ports", "nft-ruleset"])
    p_ncollect.add_argument("--device-id", required=True)
    p_ncollect.add_argument("--timeout", type=float, default=15.0)
    p_ncollect.add_argument("--container", help="run the read-only collector inside a container")
    p_ncollect.add_argument("--runtime", choices=["docker", "podman"], default="docker")
    p_ncollect.add_argument(
        "--exclude-interface", action="append", default=[],
        help="exclude routes using this interface (repeatable; useful for management interfaces)",
    )
    p_ncollect.add_argument(
        "--exclude-prefix", action="append", default=[],
        help="exclude this route prefix after normalization (repeatable)",
    )
    p_ncollect.set_defaults(func=cmd_network_collect)

    p_nsnap = network_sub.add_parser("snapshot", help="inspect imported network snapshots")
    nsnap_sub = p_nsnap.add_subparsers(dest="network_snapshot_command", required=True)
    p_nsnap_list = nsnap_sub.add_parser("list")
    p_nsnap_list.add_argument("--device-id")
    p_nsnap_list.add_argument("--limit", type=int, default=100)
    p_nsnap_list.set_defaults(func=cmd_network_snapshot_list)
    p_nsnap_show = nsnap_sub.add_parser("show")
    p_nsnap_show.add_argument("--snapshot-id", required=True)
    p_nsnap_show.set_defaults(func=cmd_network_snapshot_show)

    def add_network_entity_parser(name, func):
        parser = network_sub.add_parser(name)
        parser.add_argument("--device-id")
        parser.add_argument("--snapshot-id")
        parser.add_argument("--limit", type=int, default=1000)
        parser.set_defaults(func=func)

    add_network_entity_parser("interfaces", cmd_network_interfaces)
    add_network_entity_parser("vlans", cmd_network_vlans)
    add_network_entity_parser("links", cmd_network_links)
    add_network_entity_parser("routes", cmd_network_routes)
    add_network_entity_parser("policies", cmd_network_policies)

    p_ntopo = network_sub.add_parser("topology")
    p_ntopo.add_argument("--limit", type=int, default=500)
    p_ntopo.set_defaults(func=cmd_network_topology)

    p_ncorr = network_sub.add_parser("correlate", help="correlate captured flows with routes, VLANs, and firewall rules")
    p_ncorr.add_argument("--ingress-device", required=True)
    p_ncorr.add_argument("--route-device")
    p_ncorr.add_argument("--policy-device")
    p_ncorr.add_argument("--vlan-device")
    p_ncorr.add_argument("--capture-id")
    p_ncorr.add_argument("--target")
    p_ncorr.add_argument("--vrf", default="default")
    p_ncorr.add_argument("--in-interface")
    p_ncorr.add_argument("--limit", type=int, default=500)
    p_ncorr.add_argument("--no-store", action="store_true")
    p_ncorr.set_defaults(func=cmd_network_correlate)

    p_nassess = network_sub.add_parser("assessments")
    p_nassess.add_argument("--target")
    p_nassess.add_argument("--capture-id")
    p_nassess.add_argument("--ingress-device")
    p_nassess.add_argument("--limit", type=int, default=500)
    p_nassess.set_defaults(func=cmd_network_assessments)

    p_recommend = sub.add_parser(
        "recommend",
        help="generate reviewable configuration change plans from flow assessments",
    )
    recommend_sub = p_recommend.add_subparsers(dest="recommend_command", required=True)

    p_rec_generate = recommend_sub.add_parser(
        "generate",
        help="generate a vendor-neutral recommendation and model-level what-if result",
    )
    p_rec_generate.add_argument("--assessment-id", required=True)
    p_rec_generate.add_argument("--route-device")
    p_rec_generate.add_argument("--policy-device")
    p_rec_generate.add_argument("--vlan-device")
    p_rec_generate.add_argument("--destination-prefix")
    p_rec_generate.add_argument("--next-hop")
    p_rec_generate.add_argument("--out-interface")
    p_rec_generate.add_argument("--access-interface")
    p_rec_generate.add_argument("--trunk-interface")
    p_rec_generate.add_argument("--no-store", action="store_true")
    p_rec_generate.set_defaults(func=cmd_recommend_generate)

    p_rec_candidates = recommend_sub.add_parser(
        "candidates",
        help="generate, rank, and persist alternative recommendations with an evidence graph",
    )
    p_rec_candidates.add_argument("--assessment-id", required=True)
    p_rec_candidates.add_argument("--route-device")
    p_rec_candidates.add_argument("--policy-device")
    p_rec_candidates.add_argument("--vlan-device")
    p_rec_candidates.add_argument("--destination-prefix")
    p_rec_candidates.add_argument("--next-hop")
    p_rec_candidates.add_argument("--out-interface")
    p_rec_candidates.add_argument("--access-interface")
    p_rec_candidates.add_argument("--trunk-interface")
    p_rec_candidates.add_argument("--no-store", action="store_true")
    p_rec_candidates.set_defaults(func=cmd_recommend_candidates)

    p_rec_evidence = recommend_sub.add_parser(
        "evidence", help="build a cross-layer evidence graph for an assessment",
    )
    p_rec_evidence.add_argument("--assessment-id", required=True)
    p_rec_evidence.add_argument("--route-device")
    p_rec_evidence.add_argument("--policy-device")
    p_rec_evidence.add_argument("--vlan-device")
    p_rec_evidence.add_argument("--format", choices=["json", "dot"], default="json")
    p_rec_evidence.add_argument("--output")
    p_rec_evidence.add_argument("--no-store", action="store_true")
    p_rec_evidence.set_defaults(func=cmd_recommend_evidence)

    p_rec_review = recommend_sub.add_parser(
        "review", help="record a named human review decision",
    )
    p_rec_review.add_argument("--recommendation-id", required=True)
    p_rec_review.add_argument("--status", choices=["REVIEWED", "APPROVED", "REJECTED"], required=True)
    p_rec_review.add_argument("--reviewed-by", required=True)
    p_rec_review.add_argument("--note")
    p_rec_review.set_defaults(func=cmd_recommend_review)

    p_rec_apply_lab = recommend_sub.add_parser(
        "apply-lab", help="apply and verify an approved recommendation in containerlab only",
    )
    p_rec_apply_lab.add_argument("--recommendation-id", required=True)
    p_rec_apply_lab.add_argument("--environment", choices=["virtual-lab"], required=True)
    p_rec_apply_lab.add_argument("--approved-by", required=True)
    p_rec_apply_lab.add_argument("--lab-name", default="kansoku-v100")
    p_rec_apply_lab.add_argument("--runtime", choices=["docker", "podman"], default="docker")
    p_rec_apply_lab.add_argument("--client-node", default="client-a")
    p_rec_apply_lab.add_argument("--verify-url", default="http://10.20.20.10:443/")
    p_rec_apply_lab.add_argument("--timeout", type=float, default=15.0)
    p_rec_apply_lab.add_argument("--keep-change", action="store_true")
    p_rec_apply_lab.set_defaults(func=cmd_recommend_apply_lab)

    p_rec_execs = recommend_sub.add_parser("executions", help="list virtual-lab remediation executions")
    p_rec_execs.add_argument("--recommendation-id")
    p_rec_execs.add_argument("--status", choices=sorted(EXECUTION_STATUSES))
    p_rec_execs.add_argument("--limit", type=int, default=200)
    p_rec_execs.set_defaults(func=cmd_recommend_executions)

    p_rec_exec_show = recommend_sub.add_parser("execution-show", help="show one remediation execution")
    p_rec_exec_show.add_argument("--execution-id", required=True)
    p_rec_exec_show.set_defaults(func=cmd_recommend_execution_show)

    p_rec_list = recommend_sub.add_parser("list", help="list stored recommendations")
    p_rec_list.add_argument("--target")
    p_rec_list.add_argument("--assessment-id")
    p_rec_list.add_argument("--category", choices=["FIREWALL_POLICY", "ROUTE", "VLAN", "MANUAL_REVIEW"])
    p_rec_list.add_argument("--status", choices=["DRAFT", "REVIEWED", "REJECTED", "APPROVED"])
    p_rec_list.add_argument("--limit", type=int, default=200)
    p_rec_list.set_defaults(func=cmd_recommend_list)

    p_rec_show = recommend_sub.add_parser("show", help="show one stored recommendation")
    p_rec_show.add_argument("--recommendation-id", required=True)
    p_rec_show.set_defaults(func=cmd_recommend_show)

    p_rec_export = recommend_sub.add_parser("export", help="export a review packet")
    p_rec_export.add_argument("--recommendation-id", required=True)
    p_rec_export.add_argument("--format", choices=["json", "markdown"], default="markdown")
    p_rec_export.add_argument("--output", required=True)
    p_rec_export.set_defaults(func=cmd_recommend_export)

    p_rec_validate = recommend_sub.add_parser("validate", help="validate completeness and what-if outcome")
    p_rec_validate.add_argument("--recommendation-id", required=True)
    p_rec_validate.set_defaults(func=cmd_recommend_validate)

    p_experiment = sub.add_parser(
        "experiment",
        help="manage reproducible evaluation definitions, trials, and exports",
    )
    experiment_sub = p_experiment.add_subparsers(dest="experiment_command", required=True)

    p_exp_create = experiment_sub.add_parser("create", help="create a reproducible experiment definition")
    p_exp_create.add_argument("--name", required=True)
    p_exp_create.add_argument("--description")
    p_exp_create.add_argument("--scenario", action="append", required=True)
    p_exp_create.add_argument("--repetitions", type=int, default=1)
    p_exp_create.add_argument("--base-seed", type=int, default=1)
    p_exp_create.add_argument("--baseline", action="append")
    p_exp_create.add_argument("--metric", action="append")
    p_exp_create.add_argument("--tag", action="append", default=[], help="key=value tag")
    p_exp_create.add_argument("--metadata", action="append", default=[], help="key=value metadata")
    p_exp_create.set_defaults(func=cmd_experiment_create)

    p_exp_list = experiment_sub.add_parser("list", help="list experiment definitions")
    p_exp_list.add_argument("--status", choices=sorted(EXPERIMENT_STATUSES))
    p_exp_list.add_argument("--limit", type=int, default=200)
    p_exp_list.set_defaults(func=cmd_experiment_list)

    p_exp_show = experiment_sub.add_parser("show", help="show an experiment definition")
    p_exp_show.add_argument("--experiment-id", required=True)
    p_exp_show.add_argument("--trial-limit", type=int, default=10000)
    p_exp_show.set_defaults(func=cmd_experiment_show)

    p_exp_status = experiment_sub.add_parser("status", help="update experiment lifecycle status")
    p_exp_status.add_argument("--experiment-id", required=True)
    p_exp_status.add_argument("--status", required=True, choices=sorted(EXPERIMENT_STATUSES))
    p_exp_status.set_defaults(func=cmd_experiment_status)

    p_exp_record = experiment_sub.add_parser("record", help="record one experiment trial")
    p_exp_record.add_argument("--experiment-id", required=True)
    p_exp_record.add_argument("--scenario-id", required=True)
    p_exp_record.add_argument("--repetition", type=int, default=1)
    p_exp_record.add_argument("--seed", type=int, default=1)
    p_exp_record.add_argument("--status", required=True, choices=sorted(TRIAL_STATUSES))
    p_exp_record.add_argument("--expected-verdict")
    p_exp_record.add_argument("--observed-verdict")
    p_exp_record.add_argument("--expected-category")
    p_exp_record.add_argument("--observed-category")
    p_exp_record.add_argument("--expected-recovery", action=argparse.BooleanOptionalAction, default=None)
    p_exp_record.add_argument("--recovered", action=argparse.BooleanOptionalAction, default=None)
    p_exp_record.add_argument("--timing", action="append", default=[], help="name=milliseconds")
    p_exp_record.add_argument("--counter", action="append", default=[], help="name=value")
    p_exp_record.add_argument("--artifact", action="append", default=[], help="name=path")
    p_exp_record.add_argument("--metadata", action="append", default=[], help="key=value")
    p_exp_record.add_argument("--environment-manifest")
    p_exp_record.add_argument("--capture-environment", action="store_true")
    p_exp_record.add_argument("--environment-label", action="append", default=[])
    p_exp_record.add_argument("--error")
    p_exp_record.set_defaults(func=cmd_experiment_record)

    p_exp_trials = experiment_sub.add_parser("trials", help="list recorded trials")
    p_exp_trials.add_argument("--experiment-id")
    p_exp_trials.add_argument("--scenario-id")
    p_exp_trials.add_argument("--status", choices=sorted(TRIAL_STATUSES))
    p_exp_trials.add_argument("--limit", type=int, default=10000)
    p_exp_trials.set_defaults(func=cmd_experiment_trials)

    p_exp_import = experiment_sub.add_parser("import-lab", help="import a virtual-lab summary as trials")
    p_exp_import.add_argument("--experiment-id", required=True)
    p_exp_import.add_argument("--summary", required=True)
    p_exp_import.add_argument("--repetition", type=int, default=1)
    p_exp_import.add_argument("--seed", type=int, default=1)
    p_exp_import.add_argument("--environment-manifest")
    p_exp_import.add_argument("--capture-environment", action="store_true")
    p_exp_import.add_argument("--environment-label", action="append", default=[])
    p_exp_import.set_defaults(func=cmd_experiment_import_lab)

    p_exp_summary = experiment_sub.add_parser("summarize", help="calculate evaluation metrics")
    p_exp_summary.add_argument("--experiment-id", required=True)
    p_exp_summary.add_argument("--output")
    p_exp_summary.add_argument("--limit", type=int, default=100000)
    p_exp_summary.set_defaults(func=cmd_experiment_summarize)

    p_exp_export = experiment_sub.add_parser("export", help="export definition, trials CSV/JSON, and summary")
    p_exp_export.add_argument("--experiment-id", required=True)
    p_exp_export.add_argument("--output-dir", required=True)
    p_exp_export.add_argument("--limit", type=int, default=100000)
    p_exp_export.set_defaults(func=cmd_experiment_export)

    p_exp_manifest = experiment_sub.add_parser("manifest", help="capture a reproducibility environment manifest")
    p_exp_manifest.add_argument("--output", required=True)
    p_exp_manifest.add_argument("--label", action="append", default=[])
    p_exp_manifest.set_defaults(func=cmd_experiment_manifest)

    p_exp_catalog = experiment_sub.add_parser("validate-catalog", help="validate a scenario catalog")
    p_exp_catalog.add_argument("--file", required=True)
    p_exp_catalog.set_defaults(func=cmd_experiment_catalog_validate)

    p_remote = sub.add_parser("remote-agent", help="manage authenticated remote observation agents")
    remote_sub = p_remote.add_subparsers(dest="remote_agent_command", required=True)
    p_remote_create = remote_sub.add_parser("create", help="register an agent and issue a one-time token")
    p_remote_create.add_argument("--name", required=True)
    p_remote_create.add_argument("--agent-id")
    p_remote_create.add_argument("--capabilities", help="comma-separated capabilities such as ping,iperf3")
    p_remote_create.add_argument("--label", action="append", default=[], help="agent label in key=value form")
    p_remote_create.add_argument("--token-file", help="write the one-time token to an owner-only file")
    p_remote_create.set_defaults(func=cmd_remote_agent_create)
    p_remote_show = remote_sub.add_parser("show", help="show registration and latest heartbeat")
    p_remote_show.add_argument("--agent-id", required=True)
    p_remote_show.set_defaults(func=cmd_remote_agent_show)
    p_remote_list = remote_sub.add_parser("list", help="list registered remote agents")
    p_remote_list.add_argument("--limit", type=int, default=100)
    p_remote_list.add_argument("--enabled-only", action="store_true")
    p_remote_list.set_defaults(func=cmd_remote_agent_list)
    p_remote_enable = remote_sub.add_parser("enable", help="enable a remote agent")
    p_remote_enable.add_argument("--agent-id", required=True)
    p_remote_enable.set_defaults(func=cmd_remote_agent_enable, enabled=True)
    p_remote_disable = remote_sub.add_parser("disable", help="disable a remote agent")
    p_remote_disable.add_argument("--agent-id", required=True)
    p_remote_disable.set_defaults(func=cmd_remote_agent_enable, enabled=False)
    p_remote_rotate = remote_sub.add_parser("rotate-token", help="invalidate the old token and issue a new one")
    p_remote_rotate.add_argument("--agent-id", required=True)
    p_remote_rotate.add_argument("--token-file")
    p_remote_rotate.set_defaults(func=cmd_remote_agent_rotate)
    p_remote_delete = remote_sub.add_parser("delete", help="delete a remote agent registration")
    p_remote_delete.add_argument("--agent-id", required=True)
    p_remote_delete.set_defaults(func=cmd_remote_agent_delete)

    p_ingest = sub.add_parser("ingest", help="serve the authenticated remote observation API")
    ingest_sub = p_ingest.add_subparsers(dest="ingest_command", required=True)
    p_ingest_serve = ingest_sub.add_parser("serve", help="start the remote ingest HTTP API")
    p_ingest_serve.add_argument("--host", default="127.0.0.1")
    p_ingest_serve.add_argument("--port", type=int, default=8090)
    p_ingest_serve.add_argument("--max-body-bytes", type=int, default=4 * 1024 * 1024)
    p_ingest_serve.add_argument("--no-auto-evaluate", action="store_true")
    p_ingest_serve.set_defaults(func=cmd_ingest_serve)

    p_edge = sub.add_parser("edge", help="collect at an edge node and deliver through a durable spool")
    edge_sub = p_edge.add_subparsers(dest="edge_command", required=True)

    def add_edge_transport(parser):
        parser.add_argument("--hub-url", default="http://127.0.0.1:8090")
        parser.add_argument("--agent-id", required=True)
        parser.add_argument("--token-env", default="KANSOKU_AGENT_TOKEN")
        parser.add_argument("--token-file")
        parser.add_argument("--spool-dir", default="~/.kansoku/spool")
        parser.add_argument("--http-timeout", type=float, default=10.0)
        parser.add_argument("--flush-limit", type=int, default=100)

    def add_edge_collection(parser):
        add_edge_transport(parser)
        parser.add_argument("--spool-only", action="store_true", help="collect and queue without contacting the Hub")

    p_edge_sim = edge_sub.add_parser("simulate", help="queue and deliver simulated observations")
    add_edge_collection(p_edge_sim)
    p_edge_sim.add_argument("--target", required=True)
    p_edge_sim.add_argument("--profile", choices=["normal", "warning", "degraded", "critical"], default="normal")
    p_edge_sim.add_argument("--count", type=int, default=3)
    p_edge_sim.set_defaults(func=cmd_edge_simulate)

    p_edge_ping = edge_sub.add_parser("ping", help="collect ping observations and deliver them remotely")
    add_edge_collection(p_edge_ping)
    p_edge_ping.add_argument("--target", required=True)
    p_edge_ping.add_argument("--count", type=int, default=4)
    p_edge_ping.add_argument("--timeout", type=float, default=5.0)
    p_edge_ping.set_defaults(func=cmd_edge_ping)

    p_edge_iperf = edge_sub.add_parser("iperf3", help="collect iperf3 observations and deliver them remotely")
    add_edge_collection(p_edge_iperf)
    p_edge_iperf.add_argument("--target", required=True)
    p_edge_iperf.add_argument("--port", type=int, default=5201)
    p_edge_iperf.add_argument("--duration", type=int, default=10)
    p_edge_iperf.add_argument("--parallel", type=int, default=1)
    p_edge_iperf.add_argument("--reverse", action="store_true")
    p_edge_iperf.add_argument("--udp", action="store_true")
    p_edge_iperf.add_argument("--bitrate")
    p_edge_iperf.add_argument("--connect-timeout-ms", type=int, default=5000)
    p_edge_iperf.set_defaults(func=cmd_edge_iperf3)

    p_edge_pcap = edge_sub.add_parser("pcap", help="summarize an existing pcap and deliver metadata and flows")
    add_edge_collection(p_edge_pcap)
    p_edge_pcap.add_argument("--pcap", required=True)
    p_edge_pcap.add_argument("--target", required=True)
    p_edge_pcap.add_argument("--source")
    p_edge_pcap.add_argument("--interface", default="offline")
    p_edge_pcap.add_argument("--filter", default="")
    p_edge_pcap.add_argument("--snaplen", type=int, default=0)
    p_edge_pcap.add_argument("--max-flows", type=int, default=2_000)
    p_edge_pcap.add_argument("--send-flow-limit", type=int, default=500)
    p_edge_pcap.set_defaults(func=cmd_edge_pcap)

    p_edge_capture = edge_sub.add_parser("capture", help="capture locally and deliver only metadata and aggregated flows")
    add_edge_collection(p_edge_capture)
    p_edge_capture.add_argument("--target", required=True)
    p_edge_capture.add_argument("--interface", required=True)
    p_edge_capture.add_argument("--duration", type=float, default=10.0)
    p_edge_capture.add_argument("--packet-limit", type=int, default=0)
    p_edge_capture.add_argument("--filter", default="")
    p_edge_capture.add_argument("--snaplen", type=int, default=96)
    p_edge_capture.add_argument("--full-packet", action="store_true")
    p_edge_capture.add_argument("--source")
    p_edge_capture.add_argument("--tcpdump-bin", default="tcpdump")
    p_edge_capture.add_argument("--use-sudo", action="store_true")
    p_edge_capture.add_argument("--output-dir", default="~/.kansoku/pcap")
    p_edge_capture.add_argument("--retention-days", type=int, default=7)
    p_edge_capture.add_argument("--quota-mb", type=int, default=512)
    p_edge_capture.add_argument("--max-flows", type=int, default=2_000)
    p_edge_capture.add_argument("--send-flow-limit", type=int, default=500)
    p_edge_capture.set_defaults(func=cmd_edge_capture)

    p_edge_flush = edge_sub.add_parser("flush", help="deliver queued batches in FIFO order")
    add_edge_transport(p_edge_flush)
    p_edge_flush.set_defaults(func=cmd_edge_flush)

    p_edge_status = edge_sub.add_parser("status", help="show local spool state")
    p_edge_status.add_argument("--spool-dir", default="~/.kansoku/spool")
    p_edge_status.set_defaults(func=cmd_edge_status)

    p_edge_heartbeat = edge_sub.add_parser("heartbeat", help="send agent health and spool depth")
    add_edge_transport(p_edge_heartbeat)
    p_edge_heartbeat.set_defaults(func=cmd_edge_heartbeat)


    p_view = sub.add_parser("view", help="render target timeline")
    p_view.add_argument("--target", required=True)
    p_view.add_argument("--limit", type=int, default=10)
    p_view.set_defaults(func=cmd_view)

    p_web = sub.add_parser("web", help="serve the local read-only dashboard")
    p_web.add_argument("--host", default="127.0.0.1")
    p_web.add_argument("--port", type=int, default=8080)
    p_web.set_defaults(func=cmd_web)

    p_demo = sub.add_parser("demo", help="run minimal closed-loop demo")
    p_demo.add_argument("--target", default="demo-path")
    p_demo.add_argument("--profile", choices=["warning", "degraded", "critical"], default="degraded")
    p_demo.add_argument("--execute", action="store_true", help="actually execute; default is dry-run")
    p_demo.set_defaults(func=cmd_demo)
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except ValueError as exc:
        parser.error(str(exc))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
