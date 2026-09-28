from __future__ import annotations

import pytest

from kansoku.capture import FlowRecord
from kansoku.diagnostic_eval import (
    ConfigStateView,
    EvidenceAblationRunner,
    EvidenceLeakageChecker,
    FlowEvidenceView,
    FlowOnlyDiagnoser,
    ObservedFlowEvidence,
    ProposedDiagnoser,
    TargetFlowSpec,
    ConfigurationOnlyDiagnoser,
    view_checksums,
)
from kansoku.network_state import NetworkInterface, PolicyRule, RouteEntry, VlanRecord


def target() -> TargetFlowSpec:
    return TargetFlowSpec(
        query_id="query-001",
        ip_version=4,
        protocol="TCP",
        src_ip="10.10.10.10",
        dst_ip="10.20.20.10",
        src_port=None,
        dst_port=443,
    )


def raw_flow(*, packets: int = 3, syn: int = 1, ack: int = 1, vlan_id: int | None = 10) -> FlowRecord:
    return FlowRecord(
        capture_id="capture-secret",
        target="lab-firewall-deny",
        source="scenario-route-missing",
        ip_version=4,
        protocol="TCP",
        src_ip="10.10.10.10",
        dst_ip="10.20.20.10",
        src_port=40000,
        dst_port=443,
        packets=packets,
        captured_bytes=162,
        wire_bytes=162,
        first_seen="2026-01-01T00:00:00+00:00",
        last_seen="2026-01-01T00:00:01+00:00",
        vlan_id=vlan_id,
        tcp_flags={"syn": syn, "ack": ack, "rst": 0},
        metadata={"scenario_id": "firewall-deny", "expected_verdict": "DENY"},
    )


def flow_view(**kwargs) -> FlowEvidenceView:
    return FlowEvidenceView(
        query_id=target().query_id,
        flows=(ObservedFlowEvidence.from_flow(raw_flow(**kwargs)),),
    )


def config_view(*, deny: bool = False, route: bool = True, vlan_id: int = 10) -> ConfigStateView:
    policies = []
    if deny:
        policies.append(
            PolicyRule(
                device_id="fw1",
                policy_type="firewall",
                table="filter",
                chain="forward",
                action="DENY",
                priority=1,
                protocol="TCP",
                src_network="10.10.10.0/24",
                dst_network="10.20.20.10/32",
                dst_port="443",
            )
        )
    else:
        policies.append(
            PolicyRule(
                device_id="fw1",
                policy_type="firewall",
                table="filter",
                chain="forward",
                action="ALLOW",
                priority=1,
                protocol="TCP",
                src_network="10.10.10.0/24",
                dst_network="10.20.20.10/32",
                dst_port="443",
            )
        )
    routes = (
        RouteEntry(
            device_id="r1",
            prefix="10.20.20.0/24",
            protocol="static",
            next_hop="172.16.1.2",
            interface="eth2",
            selected=True,
            installed=True,
        ),
    ) if route else ()
    return ConfigStateView(
        query_id=target().query_id,
        ingress_device_id="fw1",
        route_device_id="r1",
        policy_device_id="fw1",
        vlan_device_id="sw1",
        vrf="default",
        in_interface="",
        routes=routes,
        policies=tuple(policies),
        vlans=(VlanRecord(device_id="sw1", vlan_id=vlan_id, interfaces=["eth1", "eth2"]),),
        interfaces=(
            NetworkInterface(device_id="sw1", name="eth1", vlan_mode="access", access_vlan=vlan_id),
            NetworkInterface(device_id="sw1", name="eth2", vlan_mode="trunk", trunk_vlans=[vlan_id]),
        ),
    )


def test_target_spec_validation():
    item = target()
    item.validate()
    with pytest.raises(ValueError):
        TargetFlowSpec("", 4, "TCP", "10.0.0.1", "10.0.0.2").validate()
    with pytest.raises(ValueError):
        TargetFlowSpec("q", 5, "TCP", "10.0.0.1", "10.0.0.2").validate()


def test_flow_evidence_strips_scenario_provenance():
    evidence = ObservedFlowEvidence.from_flow(raw_flow())
    payload = evidence.to_dict()
    text = str(payload)
    assert "capture-secret" not in text
    assert "lab-firewall-deny" not in text
    assert "scenario-route-missing" not in text
    assert "expected_verdict" not in text


def test_flow_only_normal_tcp_is_allow():
    result = FlowOnlyDiagnoser().diagnose(target(), flow_view(packets=3, syn=1, ack=1))
    assert result.verdict == "ALLOW"
    assert result.fault_domain == "NONE"
    assert result.abstained is False


def test_flow_only_failed_syn_abstains_without_causal_attribution():
    result = FlowOnlyDiagnoser().diagnose(target(), flow_view(packets=3, syn=3, ack=0))
    assert result.verdict == "UNKNOWN"
    assert result.fault_domain == "UNKNOWN"
    assert result.affected_element_type == "UNKNOWN"
    assert result.abstained is True


def test_config_only_normal_is_allow():
    result = ConfigurationOnlyDiagnoser().diagnose(target(), config_view())
    assert result.verdict == "ALLOW"
    assert result.fault_domain == "NONE"


def test_config_only_firewall_deny():
    result = ConfigurationOnlyDiagnoser().diagnose(target(), config_view(deny=True))
    assert result.verdict == "DENY"
    assert result.fault_domain == "FIREWALL"
    assert result.affected_device == "fw1"
    assert result.affected_element_type == "POLICY_RULE"
    assert result.affected_element_ref.startswith("policy:")


def test_config_only_route_missing():
    result = ConfigurationOnlyDiagnoser().diagnose(target(), config_view(route=False))
    assert result.verdict == "UNROUTABLE"
    assert result.fault_domain == "ROUTE"
    assert result.affected_device == "r1"
    assert result.affected_element_ref == "route-missing:10.20.20.10"


def test_config_only_does_not_use_observed_vlan():
    # The intended flow carries VLAN 10 in the observed view, but the config-only
    # query has no observed VLAN. A VLAN-30 config therefore remains ALLOW here.
    result = ConfigurationOnlyDiagnoser().diagnose(target(), config_view(vlan_id=30))
    assert result.verdict == "ALLOW"
    assert result.fault_domain == "NONE"


def test_proposed_firewall_deny():
    result = ProposedDiagnoser().diagnose(target(), flow_view(), config_view(deny=True))
    assert result.verdict == "DENY"
    assert result.fault_domain == "FIREWALL"


def test_proposed_route_missing():
    result = ProposedDiagnoser().diagnose(target(), flow_view(packets=3, syn=3, ack=0), config_view(route=False))
    assert result.verdict == "UNROUTABLE"
    assert result.fault_domain == "ROUTE"


def test_proposed_vlan_mismatch_localizes_vlan():
    result = ProposedDiagnoser().diagnose(target(), flow_view(vlan_id=10), config_view(vlan_id=30))
    assert result.verdict == "UNKNOWN"
    assert result.fault_domain == "VLAN"
    assert result.affected_device == "sw1"
    assert result.affected_element_ref == "vlan-missing:10"
    assert result.abstained is False


def test_ablation_runner_returns_all_three_methods():
    result = EvidenceAblationRunner().run(target(), flow_view(packets=3, syn=3, ack=0), config_view(deny=True))
    assert result.flow_only.method == "FLOW_ONLY"
    assert result.config_only.method == "CONFIG_ONLY"
    assert result.proposed.method == "PROPOSED"
    assert result.flow_only.query_id == result.config_only.query_id == result.proposed.query_id


def test_view_checksums_are_deterministic_for_same_trial_views():
    target_spec = target()
    flow = flow_view()
    config = config_view()
    a = view_checksums(target_spec, flow, config)
    b = view_checksums(target_spec, flow, config)
    assert a == b
    assert all(len(value) == 64 for value in a.values())


def test_leakage_checker_rejects_fault_label_in_config_comment():
    leaked_policy = PolicyRule(
        device_id="fw1",
        policy_type="firewall",
        table="filter",
        chain="forward",
        action="DENY",
        priority=1,
        protocol="TCP",
        dst_port="443",
        comment="kansoku fault deny",
    )
    leaked = ConfigStateView(
        query_id=target().query_id,
        ingress_device_id="fw1",
        route_device_id="r1",
        policy_device_id="fw1",
        vlan_device_id="sw1",
        vrf="default",
        in_interface="",
        routes=(),
        policies=(leaked_policy,),
        vlans=(),
        interfaces=(),
    )
    with pytest.raises(ValueError, match="leakage"):
        EvidenceLeakageChecker().validate_views(flow_view(), leaked)
