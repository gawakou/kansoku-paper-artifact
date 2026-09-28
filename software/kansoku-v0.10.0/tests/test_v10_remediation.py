from __future__ import annotations

import subprocess
from pathlib import Path

from kansoku.capture import FlowRecord
from kansoku.evidence import EvidenceGraph, build_evidence_graph, export_evidence_graph
from kansoku.hub import Hub
from kansoku.network_state import FlowAssessment, PolicyRule, RouteEntry
from kansoku.recommendation import RecommendationEngine
from kansoku.remediation import RecommendationRanker, VirtualLabExecutor


def _flow() -> FlowRecord:
    return FlowRecord(
        capture_id="capture-v10",
        target="virtual-lab-path",
        source="virtual-lab",
        ip_version=4,
        protocol="TCP",
        src_ip="10.10.10.10",
        dst_ip="10.20.20.10",
        src_port=40000,
        dst_port=443,
        packets=1,
        captured_bytes=54,
        wire_bytes=54,
        first_seen="2026-07-18T00:00:00+00:00",
        last_seen="2026-07-18T00:00:00+00:00",
        vlan_id=None,
        tcp_flags={"syn": 1, "ack": 0},
        flow_id="flow-v10",
    )


def _allow() -> PolicyRule:
    return PolicyRule(
        device_id="fw1", policy_type="firewall", table="filter", chain="forward",
        action="ALLOW", priority=10, protocol="TCP",
        src_network="10.10.10.0/24", dst_network="10.20.20.10/32", dst_port="443",
        rule_id="allow-v10",
    )


def _route_missing_assessment(flow: FlowRecord) -> FlowAssessment:
    return FlowAssessment(
        flow_id=flow.flow_id,
        capture_id=flow.capture_id,
        target=flow.target,
        ingress_device_id="fw1",
        route_status="NO_ROUTE",
        policy_status="ALLOW",
        verdict="UNROUTABLE",
        matched_rule_id="allow-v10",
        evidence={
            "route_device": "r1",
            "policy_device": "fw1",
            "vlan_device": "sw1",
            "out_interface": "",
            "vrf": "default",
        },
        assessment_id="assessment-v10-route",
    )


def test_evidence_graph_represents_observed_rules_and_missing_route(tmp_path: Path):
    flow = _flow()
    assessment = _route_missing_assessment(flow)
    graph = build_evidence_graph(assessment, flow, policies=[_allow()])
    kinds = {item.node_type for item in graph.nodes}
    assert {"FLOW", "ASSESSMENT", "POLICY_RULE", "EVIDENCE_GAP"}.issubset(kinds)
    assert any(item.node_id == "gap:route" for item in graph.nodes)
    assert any(item.relation == "MATCHED_BY" for item in graph.edges)
    assert graph.evidence_coverage == 1.0
    restored = EvidenceGraph.from_dict(graph.to_dict())
    assert restored.to_dict() == graph.to_dict()
    dot = export_evidence_graph(graph, output=tmp_path / "evidence.dot", format_name="dot")
    assert "digraph kansoku_evidence" in dot.read_text()
    assert "MISSING" in dot.read_text()


def test_route_candidate_set_ranks_host_route_above_broader_prefix():
    flow = _flow()
    assessment = _route_missing_assessment(flow)
    engine = RecommendationEngine()
    candidates = engine.generate_candidates(
        assessment,
        flow,
        policies=[_allow()],
        route_device_id="r1",
        destination_prefix="10.20.20.0/24",
        next_hop="172.16.1.2",
        out_interface="eth2",
    )
    assert len(candidates) == 3
    assert {item.category for item in candidates} == {"ROUTE", "MANUAL_REVIEW"}
    graph = build_evidence_graph(assessment, flow, policies=[_allow()])
    ranked = RecommendationRanker().rank(candidates, evidence_graph=graph)
    assert ranked[0].recommendation.metadata["candidate_variant"] == "host-route"
    assert ranked[0].score > ranked[1].score > ranked[-1].score
    assert ranked[0].components["blast_radius_safety"] > ranked[1].components["blast_radius_safety"]


def test_firewall_broader_candidate_is_penalized_for_security_risk():
    flow = _flow()
    route = RouteEntry(
        device_id="r1", prefix="10.20.20.0/24", protocol="static",
        next_hop="172.16.1.2", interface="eth2", route_id="route-v10",
    )
    deny = PolicyRule(
        device_id="fw1", policy_type="firewall", table="filter", chain="forward",
        action="DENY", priority=1, protocol="TCP",
        src_network="10.10.10.0/24", dst_network="10.20.20.10/32", dst_port="443",
        rule_id="deny-v10",
    )
    assessment = FlowAssessment(
        flow_id=flow.flow_id, capture_id=flow.capture_id, target=flow.target,
        ingress_device_id="fw1", route_status="FOUND", policy_status="DENY",
        verdict="DENY", route_id=route.route_id, matched_rule_id=deny.rule_id,
        evidence={"route_device": "r1", "policy_device": "fw1", "vlan_device": "sw1"},
    )
    candidates = RecommendationEngine().generate_candidates(
        assessment, flow, routes=[route], policies=[deny], policy_device_id="fw1",
    )
    graph = build_evidence_graph(assessment, flow, routes=[route], policies=[deny])
    ranked = RecommendationRanker().rank(candidates, evidence_graph=graph)
    narrow = next(item for item in ranked if item.recommendation.metadata.get("candidate_variant") is None)
    broad = next(item for item in ranked if item.recommendation.metadata.get("candidate_variant") == "host-pair-protocol")
    assert narrow.score > broad.score
    assert narrow.components["security_safety"] > broad.components["security_safety"]
    assert broad.recommendation.risk_level == "high"


def test_hub_persists_evidence_review_and_remediation_execution(tmp_path: Path):
    hub = Hub(tmp_path / "hub.db")
    flow = _flow()
    assessment = _route_missing_assessment(flow)
    hub.add_flow_records([flow])
    hub.add_flow_assessments([assessment])
    graph = build_evidence_graph(assessment, flow, policies=[_allow()])
    assert hub.add_evidence_graphs([graph]) == 1
    assert hub.get_evidence_graph(graph.graph_id).to_dict() == graph.to_dict()

    rec = RecommendationEngine().generate(
        assessment, flow, policies=[_allow()], route_device_id="r1",
        destination_prefix="10.20.20.0/24", next_hop="172.16.1.2", out_interface="eth2",
    )
    hub.add_configuration_recommendations([rec])
    approved = hub.set_configuration_recommendation_status(
        rec.recommendation_id, "APPROVED", reviewed_by="operator-a", note="lab only",
    )
    assert approved.status == "APPROVED"
    assert approved.metadata["review_history"][-1]["reviewed_by"] == "operator-a"

    state = {"fixed": False}

    def fake_runner(argv, timeout):
        joined = " ".join(argv)
        if "curl -fsS" in joined:
            rc = 0 if state["fixed"] else 7
            return subprocess.CompletedProcess(argv, rc, "ok" if rc == 0 else "", "" if rc == 0 else "failed")
        if "show ip route json" in joined:
            return subprocess.CompletedProcess(argv, 0, '{"routes": {}}', "")
        if " no ip route " in f" {joined} ":
            state["fixed"] = False
            return subprocess.CompletedProcess(argv, 0, "", "")
        if " ip route " in f" {joined} ":
            state["fixed"] = True
            return subprocess.CompletedProcess(argv, 0, "", "")
        return subprocess.CompletedProcess(argv, 0, "", "")

    execution = VirtualLabExecutor(runner=fake_runner).execute(
        approved, approved_by="operator-a", environment="virtual-lab",
    )
    assert execution.status == "ROLLED_BACK"
    assert execution.verification["passed"] is True
    assert execution.rollback_verification["passed"] is True
    assert state["fixed"] is False
    assert hub.add_remediation_executions([execution]) == 1
    loaded = hub.get_remediation_execution(execution.execution_id)
    assert loaded.to_dict() == execution.to_dict()
    assert hub.list_remediation_executions(status="ROLLED_BACK")[0].execution_id == execution.execution_id


def test_hub_refuses_approval_when_what_if_did_not_pass(tmp_path: Path):
    flow = _flow()
    assessment = _route_missing_assessment(flow)
    rec = RecommendationEngine().generate(
        assessment, flow, policies=[_allow()], route_device_id="r1",
        destination_prefix="10.20.20.0/24", next_hop="", out_interface="",
    )
    assert rec.simulation_status != "PASSED"
    hub = Hub(tmp_path / "approval.db")
    hub.add_configuration_recommendations([rec])
    try:
        hub.set_configuration_recommendation_status(
            rec.recommendation_id, "APPROVED", reviewed_by="operator-a",
        )
    except ValueError as exc:
        assert "approval refused" in str(exc)
    else:
        raise AssertionError("unsafe recommendation was approved")


def test_virtual_lab_executor_refuses_unapproved_recommendation():
    flow = _flow()
    assessment = _route_missing_assessment(flow)
    rec = RecommendationEngine().generate(
        assessment, flow, policies=[_allow()], route_device_id="r1",
        destination_prefix="10.20.20.0/24", next_hop="172.16.1.2", out_interface="eth2",
    )
    execution = VirtualLabExecutor(
        runner=lambda argv, timeout: subprocess.CompletedProcess(argv, 0, "", "")
    ).execute(rec, approved_by="operator-a", environment="virtual-lab")
    assert execution.status == "REFUSED"
    assert "APPROVED" in execution.error
    assert execution.apply_results == []



def test_virtual_lab_executor_preserves_nft_comment_string_literal():
    command = (
        'nft insert rule inet filter forward '
        'ip saddr 10.10.10.10 '
        'ip daddr 10.20.20.10 '
        'tcp dport 443 counter accept '
        'comment "kansoku assessment-v10-firewall"'
    )

    tokens = VirtualLabExecutor._command_tokens(command)
    comment_index = tokens.index("comment")

    assert (
        tokens[comment_index + 1]
        == '"kansoku assessment-v10-firewall"'
    )

    observed = {}

    def fake_runner(argv, timeout):
        observed["argv"] = list(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    result = VirtualLabExecutor(
        runner=fake_runner
    )._execute("fw1", command)

    assert result.returncode == 0

    comment_index = observed["argv"].index("comment")
    assert (
        observed["argv"][comment_index + 1]
        == '"kansoku assessment-v10-firewall"'
    )
