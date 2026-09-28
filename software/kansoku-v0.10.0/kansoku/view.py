from __future__ import annotations

from typing import List

from .hub import Hub
from .safety import SafetyPolicy


def render_timeline(hub: Hub, target: str, limit: int = 10) -> str:
    lines: List[str] = []
    lines.append(f"KANSOKU Timeline: {target}")
    lines.append("=" * (18 + len(target)))

    profile = hub.get_target_profile(target)
    plan = hub.get_observation_plan(target)
    policy = hub.get_safety_policy(target) or SafetyPolicy()

    lines.append("\nTarget Profile")
    lines.append("--------------")
    if profile:
        lines.append(
            f"{profile.name} | expected={profile.expected_bandwidth_mbps} Mbps | "
            f"baseline={profile.baseline_throughput_mbps} Mbps | "
            f"normal_ratio={profile.throughput_normal_ratio:.2f}"
        )
    else:
        lines.append("not configured; v0.2 absolute fallback thresholds are active")

    lines.append("\nObservation Plan")
    lines.append("----------------")
    if plan:
        lines.append(f"interval={plan.interval_sec}s | mode={plan.mode} | {plan.reason}")
    else:
        lines.append("not persisted; default interval=30s")

    lines.append("\nSafety Policy")
    lines.append("-------------")
    lines.append(
        f"{policy.name} | scope={policy.target} | min_interval="
        f"{policy.minimum_observation_interval_sec}s | "
        f"system_changes={'allowed' if policy.allow_system_changes else 'disabled'}"
    )

    managed = hub.get_managed_target(target)
    lines.append("\nManaged Target")
    lines.append("--------------")
    if managed:
        lines.append(
            f"{managed.name} | enabled={managed.enabled} | ping={managed.ping_enabled} | "
            f"iperf3={managed.iperf3_enabled} every={managed.iperf3_every_n_cycles} cycles"
        )
    else:
        lines.append("not registered in the persistent service inventory")

    lines.append("\nScheduler Cycles")
    lines.append("----------------")
    cycles = hub.list_scheduler_cycles(limit=limit, target=target)
    if not cycles:
        lines.append("no scheduler cycles")
    for cycle in cycles:
        lines.append(
            f"{cycle.finished_at} | status={cycle.status} | observations={cycle.observation_count} | "
            f"state={cycle.state_id or '—'} | transaction={cycle.transaction_id or '—'} | {cycle.message}"
        )

    lines.append("\nPacket Captures")
    lines.append("---------------")
    captures = hub.list_capture_sessions(limit=limit, target=target)
    if not captures:
        lines.append("no capture sessions")
    for capture in captures:
        lines.append(
            f"{capture.finished_at} | {capture.interface} | status={capture.status} | "
            f"privacy={capture.privacy_mode} | packets={capture.packet_count} | "
            f"flows={capture.flow_count} | scope={capture.storage_scope} | {capture.capture_id}"
        )

    lines.append("\nTop Flows")
    lines.append("---------")
    flows = hub.list_flow_records(limit=limit, target=target)
    if not flows:
        lines.append("no flow records")
    for flow in flows:
        src = f"{flow.src_ip}:{flow.src_port}" if flow.src_port is not None else flow.src_ip
        dst = f"{flow.dst_ip}:{flow.dst_port}" if flow.dst_port is not None else flow.dst_ip
        lines.append(
            f"{flow.protocol} | {src} -> {dst} | vlan={flow.vlan_id if flow.vlan_id is not None else '—'} | "
            f"packets={flow.packets} | wire_bytes={flow.wire_bytes} | {flow.capture_id}"
        )

    lines.append("\nObservations")
    lines.append("------------")
    for obs in hub.list_observations(limit=limit, target=target):
        lines.append(
            f"{obs.timestamp} | {obs.source} | {obs.metric}={obs.value} "
            f"{obs.unit} | {obs.method}"
        )

    lines.append("\nCollection Runs")
    lines.append("---------------")
    for run in hub.list_collection_runs(limit=limit, target=target):
        lines.append(
            f"{run.started_at} | {run.agent} | rc={run.returncode} | "
            f"{' '.join(run.command)} | {run.run_id}"
        )

    lines.append("\nStates")
    lines.append("------")
    for state in hub.list_states(limit=limit, target=target):
        profile_mode = state.features.get("profile_mode", "unknown")
        lines.append(
            f"{state.timestamp} | {state.state} | {state.control_mode} | "
            f"conf={state.confidence:.2f} | mode={profile_mode} | {state.reason}"
        )

    proposals = hub.list_proposals(limit=limit, target=target)
    lines.append("\nProposals")
    lines.append("---------")
    for proposal in proposals:
        lines.append(
            f"{proposal.timestamp} | {proposal.action} | risk={proposal.risk_level} | "
            f"{proposal.expected_effect} | {proposal.proposal_id}"
        )

    lines.append("\nController Transactions")
    lines.append("-----------------------")
    for transaction in hub.list_control_transactions(limit=limit, target=target):
        proposal = hub.get_proposal(transaction.proposal_id)
        action = proposal.action if proposal else "unknown"
        decision = (
            hub.get_guard_decision(transaction.guard_decision_id)
            if transaction.guard_decision_id
            else None
        )
        approval = (
            hub.get_approval(transaction.approval_id)
            if transaction.approval_id
            else None
        )
        verification = (
            hub.get_verification(transaction.verification_id)
            if transaction.verification_id
            else None
        )
        lines.append(
            f"{transaction.timestamp} | {action} | outcome={transaction.outcome} | "
            f"guard={decision.status if decision else '—'} | "
            f"approval={approval.status if approval else '—'} | "
            f"verification={verification.status if verification else '—'} | "
            f"{transaction.message}"
        )

    lines.append("\nAction Results")
    lines.append("--------------")
    proposal_ids = {proposal.proposal_id for proposal in proposals}
    results = [
        result
        for result in hub.list_action_results(limit=max(limit * 3, 30))
        if result.proposal_id in proposal_ids
    ][:limit]
    for result in results:
        kind = "rollback" if result.is_rollback else "action"
        lines.append(
            f"{result.timestamp} | {kind} | {result.status} | adapter={result.adapter} | "
            f"{result.command} | rc={result.returncode}"
        )

    return "\n".join(lines)
