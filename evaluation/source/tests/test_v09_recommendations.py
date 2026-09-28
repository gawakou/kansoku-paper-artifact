from __future__ import annotations

import json
from pathlib import Path

from kansoku.capture import FlowRecord
from kansoku.hub import Hub
from kansoku.network_state import (
    FlowAssessment,
    NetworkInterface,
    PolicyRule,
    RouteEntry,
    VlanRecord,
)
from kansoku.recommendation import RecommendationEngine, export_recommendation


def _flow(*, vlan_id=10) -> FlowRecord:
    return FlowRecord(
        capture_id="capture-v09",
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
        first_seen="2026-07-17T00:00:00+00:00",
        last_seen="2026-07-17T00:00:00+00:00",
        vlan_id=vlan_id,
        tcp_flags={"syn": 1, "ack": 0},
        flow_id="flow-v09",
    )


def _route() -> RouteEntry:
    return RouteEntry(
        device_id="r1",
        prefix="10.20.20.0/24",
        protocol="static",
        next_hop="172.16.1.2",
        interface="eth2",
    )


def _allow() -> PolicyRule:
    return PolicyRule(
        device_id="fw1", policy_type="firewall", table="filter", chain="forward",
        action="ALLOW", priority=10, protocol="TCP",
        src_network="10.10.10.0/24", dst_network="10.20.20.10/32", dst_port="443",
    )


def test_firewall_deny_generates_narrow_allow_and_rollback():
    flow = _flow(vlan_id=None)
    deny = PolicyRule(
        device_id="fw1", policy_type="firewall", table="filter", chain="forward",
        action="DENY", priority=5, protocol="TCP",
        src_network="10.10.10.0/24", dst_network="10.20.20.10/32", dst_port="443",
        rule_id="rule-deny",
    )
    assessment = FlowAssessment(
        flow_id=flow.flow_id, capture_id=flow.capture_id, target=flow.target,
        ingress_device_id="fw1", route_status="FOUND", policy_status="DENY",
        verdict="DENY", route_id="route-present", matched_rule_id=deny.rule_id,
    )
    rec = RecommendationEngine().generate(
        assessment, flow, routes=[_route()], policies=[deny], policy_device_id="fw1",
    )
    assert rec.category == "FIREWALL_POLICY"
    assert rec.platform == "nftables"
    assert rec.simulation_status == "PASSED"
    assert rec.simulated_verdict == "ALLOW"
    assert "10.10.10.10" in rec.commands[0]
    assert "10.20.20.10" in rec.commands[0]
    assert "dport 443" in rec.commands[0]
    assert "<new-rule-handle>" in rec.rollback_commands[0]
    assert rec.status == "DRAFT"
    assert rec.metadata["requires_runtime_handle_capture"] is True


def test_route_missing_with_explicit_next_hop_passes_what_if():
    flow = _flow(vlan_id=None)
    assessment = FlowAssessment(
        flow_id=flow.flow_id, capture_id=flow.capture_id, target=flow.target,
        ingress_device_id="fw1", route_status="NO_ROUTE", policy_status="ALLOW",
        verdict="UNROUTABLE", matched_rule_id="allow-1",
    )
    rec = RecommendationEngine().generate(
        assessment, flow, routes=[], policies=[_allow()], route_device_id="r1",
        destination_prefix="10.20.20.0/24", next_hop="172.16.1.2", out_interface="eth2",
    )
    assert rec.category == "ROUTE"
    assert rec.device_id == "r1"
    assert rec.simulation_status == "PASSED"
    assert rec.simulated_verdict == "ALLOW"
    assert 'ip route 10.20.20.0/24 172.16.1.2 eth2' in rec.commands[0]
    assert 'no ip route 10.20.20.0/24 172.16.1.2 eth2' in rec.rollback_commands[0]


def test_route_missing_without_next_hop_is_reviewable_but_inconclusive():
    flow = _flow(vlan_id=None)
    assessment = FlowAssessment(
        flow_id=flow.flow_id, capture_id=flow.capture_id, target=flow.target,
        ingress_device_id="fw1", route_status="NO_ROUTE", policy_status="ALLOW",
        verdict="UNROUTABLE",
    )
    rec = RecommendationEngine().generate(assessment, flow, policies=[_allow()], route_device_id="r1")
    assert rec.simulation_status == "INCONCLUSIVE"
    assert rec.impact["requires_missing_input_resolution"] is True
    assert "<next-hop-or-interface>" in rec.commands[0]


def test_unknown_vlan_generates_ovs_access_and_trunk_delta():
    flow = _flow(vlan_id=10)
    assessment = FlowAssessment(
        flow_id=flow.flow_id, capture_id=flow.capture_id, target=flow.target,
        ingress_device_id="fw1", route_status="FOUND", policy_status="ALLOW",
        verdict="UNKNOWN", vlan_status="UNKNOWN_VLAN",
    )
    interfaces = [
        NetworkInterface(device_id="sw1", name="eth1", vlan_mode="access", access_vlan=30),
        NetworkInterface(device_id="sw1", name="eth2", vlan_mode="trunk", trunk_vlans=[30]),
    ]
    rec = RecommendationEngine().generate(
        assessment, flow, routes=[_route()], policies=[_allow()], vlans=[],
        interfaces=interfaces, vlan_device_id="sw1",
        access_interface="eth1", trunk_interface="eth2",
    )
    assert rec.category == "VLAN"
    assert rec.platform == "openvswitch"
    assert rec.simulation_status == "PASSED"
    assert rec.simulated_verdict == "ALLOW"
    assert "tag=10" in rec.commands[0]
    assert "trunks=10" in rec.commands[1]
    assert "tag=30" in rec.rollback_commands[0]
    assert "trunks=30" in rec.rollback_commands[1]


def test_hub_migrates_and_persists_recommendations(tmp_path: Path):
    hub = Hub(tmp_path / "hub.db")
    flow = _flow(vlan_id=None)
    hub.add_flow_records([flow])
    assessment = FlowAssessment(
        flow_id=flow.flow_id, capture_id=flow.capture_id, target=flow.target,
        ingress_device_id="fw1", route_status="NO_ROUTE", policy_status="ALLOW",
        verdict="UNROUTABLE",
    )
    hub.add_flow_assessments([assessment])
    rec = RecommendationEngine().generate(
        assessment, flow, policies=[_allow()], route_device_id="r1",
        destination_prefix="10.20.20.0/24", next_hop="172.16.1.2", out_interface="eth2",
    )
    assert hub.add_configuration_recommendations([rec]) == 1
    loaded = hub.get_configuration_recommendation(rec.recommendation_id)
    assert loaded is not None
    assert loaded.to_dict() == rec.to_dict()
    assert hub.get_flow_record(flow.flow_id) is not None
    assert hub.get_flow_assessment(assessment.assessment_id) is not None
    assert hub.list_configuration_recommendations(target=flow.target)[0].recommendation_id == rec.recommendation_id
    with hub.connect() as conn:
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "configuration_recommendations" in tables


def test_export_review_packet_contains_commands_and_execution_boundary(tmp_path: Path):
    flow = _flow(vlan_id=None)
    assessment = FlowAssessment(
        flow_id=flow.flow_id, capture_id=flow.capture_id, target=flow.target,
        ingress_device_id="fw1", route_status="NO_ROUTE", policy_status="ALLOW",
        verdict="UNROUTABLE",
    )
    rec = RecommendationEngine().generate(
        assessment, flow, policies=[_allow()], route_device_id="r1",
        destination_prefix="10.20.20.0/24", next_hop="172.16.1.2",
    )
    md = export_recommendation(rec, output=tmp_path / "review.md", format_name="markdown")
    text = md.read_text()
    assert "Candidate commands" in text
    assert "Rollback commands" in text
    assert "never applies changes automatically or to production devices" in text
    js = export_recommendation(rec, output=tmp_path / "review.json", format_name="json")
    assert json.loads(js.read_text())["recommendation_id"] == rec.recommendation_id


def test_manual_review_has_no_executable_commands():
    flow = _flow(vlan_id=None)
    assessment = FlowAssessment(
        flow_id=flow.flow_id, capture_id=flow.capture_id, target=flow.target,
        ingress_device_id="fw1", route_status="FOUND", policy_status="NO_MATCH",
        verdict="UNKNOWN",
    )
    rec = RecommendationEngine().generate(assessment, flow, routes=[_route()])
    assert rec.category == "MANUAL_REVIEW"
    assert rec.commands == []
    assert rec.rollback_commands == []
    assert rec.risk_level == "low"
