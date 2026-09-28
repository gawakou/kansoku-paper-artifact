from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from kansoku import __version__
from kansoku.capture import FlowRecord
from kansoku.network_state import (
    OpenSourceNetworkCollector,
    PolicyRule,
    correlate_flow,
    match_policy_rule,
    parse_frr_json, parse_nft_json, filter_network_import,
)


ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT / "lab"
TOPOLOGY = LAB / "containerlab" / "kansoku.clab.yml"


def _syn_flow() -> FlowRecord:
    return FlowRecord(
        capture_id="capture-test",
        target="lab",
        source="test",
        ip_version=4,
        protocol="TCP",
        src_ip="10.10.10.10",
        dst_ip="10.20.20.10",
        src_port=40000,
        dst_port=443,
        packets=1,
        captured_bytes=54,
        wire_bytes=54,
        first_seen="2026-01-01T00:00:00+00:00",
        last_seen="2026-01-01T00:00:00+00:00",
        vlan_id=10,
        tcp_flags={"syn": 1, "ack": 0, "rst": 0},
    )


def test_version_is_v100():
    assert __version__ == "0.10.0"


def test_containerlab_topology_is_json_compatible_yaml_and_complete():
    payload = json.loads(TOPOLOGY.read_text())
    assert payload["name"] == "kansoku-v100"
    nodes = payload["topology"]["nodes"]
    assert set(nodes) == {"client-a", "sw1", "fw1", "r1", "r2", "sw2", "server-a"}
    assert nodes["sw1"]["image"] == "kansoku/lab-node:0.10.0"
    assert nodes["r1"]["image"] == "frrouting/frr:v8.4.0"
    assert nodes["fw1"]["sysctls"]["net.ipv4.ip_forward"] == "1"
    assert "NET_ADMIN" in nodes["fw1"]["cap-add"]
    links = [tuple(item["endpoints"]) for item in payload["topology"]["links"]]
    assert len(links) == 6
    assert len(set(links)) == 6
    assert ("client-a:eth1", "sw1:eth1") in links
    assert ("sw2:eth2", "server-a:eth1") in links


def test_virtual_lab_has_installation_and_fault_scenarios():
    required = [
        LAB / "vm" / "bootstrap-ubuntu.sh",
        LAB / "vm" / "cloud-init.example.yaml",
        LAB / "scripts" / "lab-up.sh",
        LAB / "scripts" / "lab-test.sh",
        LAB / "scripts" / "scenarios" / "normal.sh",
        LAB / "scripts" / "scenarios" / "firewall-deny.sh",
        LAB / "scripts" / "scenarios" / "route-missing.sh",
        LAB / "scripts" / "scenarios" / "vlan-mismatch.sh",
        LAB / "scripts" / "scenarios" / "packet-loss.sh",
    ]
    assert all(path.is_file() for path in required)
    shell_files = list(LAB.rglob("*.sh"))
    assert shell_files
    assert all(path.stat().st_mode & 0o100 for path in shell_files)


def test_container_collector_wraps_read_only_command(monkeypatch):
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=0, stdout='{"routes": {}}', stderr="")

    monkeypatch.setattr("kansoku.network_state.subprocess.run", fake_run)
    payload, run = OpenSourceNetworkCollector().collect(
        "frr-routes",
        container="clab-kansoku-v100-r1",
        runtime="docker",
        timeout=7,
    )
    assert payload == {"routes": {}}
    assert calls[0][0] == [
        "docker", "exec", "clab-kansoku-v100-r1",
        "vtysh", "-c", "show ip route json",
    ]
    assert calls[0][1]["timeout"] == 7
    assert run.source == "docker://clab-kansoku-v100-r1"
    assert run.metadata["read_only"] is True
    assert run.metadata["inner_command"] == ["vtysh", "-c", "show ip route json"]


def test_container_collector_rejects_unknown_runtime():
    with pytest.raises(ValueError, match="unsupported container runtime"):
        OpenSourceNetworkCollector().collect(
            "frr-routes", container="r1", runtime="unsupported"
        )


def test_initial_syn_does_not_match_established_only_policy():
    flow = _syn_flow()
    rules = [
        PolicyRule(
            device_id="fw1", policy_type="firewall", table="filter", chain="forward",
            action="ALLOW", priority=1, state=["established", "related"],
        ),
        PolicyRule(
            device_id="fw1", policy_type="firewall", table="filter", chain="forward",
            action="DENY", priority=2, protocol="TCP", src_network="10.10.10.0/24",
            dst_network="10.20.20.10/32", dst_port="443",
        ),
    ]
    matched = match_policy_rule(flow, rules)
    assert matched is not None
    assert matched.action == "DENY"


def test_nft_parser_preserves_emitted_chain_order_not_handle_order():
    raw = {
        "nftables": [
            {"table": {"family": "inet", "name": "filter"}},
            {"chain": {"family": "inet", "table": "filter", "name": "forward"}},
            {"rule": {
                "family": "inet", "table": "filter", "chain": "forward", "handle": 500,
                "expr": [
                    {"match": {"left": {"ct": {"key": "state"}}, "right": {"set": ["established", "related"]}}},
                    {"accept": None},
                ],
            }},
            {"rule": {
                "family": "inet", "table": "filter", "chain": "forward", "handle": 2,
                "expr": [{"drop": None}],
            }},
        ]
    }
    result = parse_nft_json(raw, device_id="fw1")
    assert [rule.priority for rule in result.policies] == [1, 2]
    assert result.policies[0].state == ["established", "related"]
    assert result.policies[0].metadata["raw_handle"] == 500
    assert result.policies[1].metadata["raw_handle"] == 2


def test_server_bootstrap_only_configures_network_and_defers_services():
    script = (LAB / "containerlab" / "configs" / "common" / "host-start.sh").read_text()
    assert "http.server" not in script
    assert "iperf3 -s" not in script
    assert "/run/kansoku/server-address" in script


def test_lab_uses_detached_service_start_and_readiness_checks():
    lib = (LAB / "scripts" / "lib.sh").read_text()
    up = (LAB / "scripts" / "lab-up.sh").read_text()
    assert 'exec -d "$(container_name "$node")"' in lib
    assert "start_server_services" in lib
    assert "wait_for_server_services" in lib
    assert "dump_server_diagnostics" in lib
    assert "ss -lnt" in lib
    assert "http://10.20.20.10:443/" in up
    assert "iperf3 -c 10.20.20.10" in up


def test_reset_recovers_missing_server_services():
    lib = (LAB / "scripts" / "lib.sh").read_text()
    reset_body = lib.split("reset_network() {", 1)[1].split("\n}\n", 1)[0]
    assert "ensure_server_services" in reset_body


def test_nft_parser_accepts_native_prefix_objects_from_live_nft_json():
    raw = {
        "nftables": [
            {"table": {"family": "inet", "name": "filter"}},
            {"chain": {
                "family": "inet", "table": "filter", "name": "forward",
                "type": "filter", "hook": "forward", "prio": 0, "policy": "drop",
            }},
            {"rule": {
                "family": "inet", "table": "filter", "chain": "forward", "handle": 7,
                "expr": [
                    {"match": {
                        "op": "==",
                        "left": {"payload": {"protocol": "ip", "field": "saddr"}},
                        "right": {"prefix": {"addr": "10.10.10.0", "len": 24}},
                    }},
                    {"match": {
                        "op": "==",
                        "left": {"payload": {"protocol": "ip", "field": "daddr"}},
                        "right": "10.20.20.10",
                    }},
                    {"match": {
                        "op": "==",
                        "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                        "right": 443,
                    }},
                    {"accept": None},
                ],
            }},
        ]
    }
    result = parse_nft_json(raw, device_id="fw1", source_name="live-docker-container")
    assert len(result.policies) == 1
    rule = result.policies[0]
    assert rule.src_network == "10.10.10.0/24"
    assert rule.dst_network == "10.20.20.10"
    assert rule.protocol == "TCP"
    assert rule.dst_port == "443"
    assert rule.action == "ALLOW"


def test_nft_parser_accepts_native_port_range_objects():
    raw = {
        "nftables": [
            {"rule": {
                "family": "inet", "table": "filter", "chain": "forward",
                "expr": [
                    {"match": {
                        "op": "==",
                        "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                        "right": {"range": [1000, 2000]},
                    }},
                    {"drop": None},
                ],
            }},
        ]
    }
    result = parse_nft_json(raw, device_id="fw1")
    assert result.policies[0].dst_port == "1000-2000"
    assert result.policies[0].action == "DENY"


def test_lab_state_collection_reports_collector_errors_instead_of_hiding_them():
    lib = (LAB / "scripts" / "lib.sh").read_text()
    collect_block = lib.split("collect_live_state() {", 1)[1].split("\n}\n", 1)[0]
    assert "collect_state_or_fail" in lib
    assert "[FAIL] $label" in lib
    assert ">/dev/null" not in collect_block


def test_management_route_filter_excludes_containerlab_eth0_default_route():
    raw = {
        "0.0.0.0/0": [{
            "protocol": "kernel", "selected": True, "installed": True,
            "nexthops": [{"ip": "172.31.81.1", "interfaceName": "eth0", "active": True}],
        }],
        "10.20.20.0/24": [{
            "protocol": "static", "selected": True, "installed": True,
            "nexthops": [{"ip": "172.16.1.2", "interfaceName": "eth2", "active": True}],
        }],
    }
    result = parse_frr_json(raw, device_id="r1", source_name="live-docker-container")
    filtered = filter_network_import(result, exclude_interfaces=["eth0"])
    assert [route.prefix for route in filtered.routes] == ["10.20.20.0/24"]
    assert filtered.snapshot.route_count == 1
    assert filtered.snapshot.metadata["route_filter"]["excluded_route_count"] == 1


def test_lab_excludes_management_interface_from_route_correlation():
    lib = (LAB / "scripts" / "lib.sh").read_text()
    assert "--exclude-interface eth0" in lib


def test_firewall_fault_comment_is_passed_as_one_nft_string():
    script = (LAB / "scripts" / "scenarios" / "firewall-deny.sh").read_text()
    assert "comment '\"kansoku fault deny\"'" in script


def test_management_default_route_cannot_mask_data_plane_route_loss():
    raw = {
        "0.0.0.0/0": [{
            "protocol": "kernel", "selected": True, "installed": True,
            "nexthops": [{"ip": "172.31.81.1", "interfaceName": "eth0", "active": True}],
        }],
    }
    result = filter_network_import(
        parse_frr_json(raw, device_id="r1", source_name="live-docker-container"),
        exclude_interfaces=["eth0"],
    )
    allow_rule = PolicyRule(
        device_id="fw1", policy_type="firewall", table="filter", chain="forward",
        action="ALLOW", priority=1, protocol="TCP", src_network="10.10.10.0/24",
        dst_network="10.20.20.10/32", dst_port="443",
    )
    assessment = correlate_flow(
        _syn_flow(), ingress_device_id="fw1", routes=result.routes, rules=[allow_rule],
    )
    assert assessment.verdict == "UNROUTABLE"
    assert assessment.route_status == "NO_ROUTE"
    assert assessment.policy_status == "ALLOW"



def test_vlan_assertion_reads_status_from_json_payload():
    lib = (LAB / "scripts" / "lib.sh").read_text()
    block = lib.split("assert_vlan_status() {", 1)[1].split("\n}\n", 1)[0]
    assert "SELECT payload FROM flow_assessments" in block
    assert 'json.loads(payload).get("vlan_status")' in block
    assert "SELECT vlan_status FROM flow_assessments" not in block


def test_pre_release_check_resolves_project_python_and_propagates_it():
    script = (ROOT / "scripts" / "pre_release_check.sh").read_text()
    assert ".lab-venv/bin/python" in script
    assert ".venv/bin/python" in script
    assert 'KANSOKU_PYTHON="$PYTHON_BIN" ./scripts/v08_virtual_lab_smoke.sh' in script


def test_v08_smoke_resolves_project_python_without_shell_function_inheritance():
    script = (ROOT / "scripts" / "v08_virtual_lab_smoke.sh").read_text()
    assert 'if [[ -n "${KANSOKU_PYTHON:-}" ]]' in script
    assert 'PYTHON_BIN="$ROOT_DIR/.lab-venv/bin/python"' in script
