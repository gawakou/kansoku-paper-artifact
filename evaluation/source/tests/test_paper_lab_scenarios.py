from __future__ import annotations

from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
SCENARIO_DIR = ROOT / "lab" / "scripts" / "scenarios"
FIREWALL_RUNNER = ROOT / "scripts" / "experiments" / "run_paper_firewall_expansion.sh"
ROUTE_RUNNER = ROOT / "scripts" / "experiments" / "run_paper_route_expansion.sh"
ROUTE_BOUNDARY_RUNNER = ROOT / "scripts" / "experiments" / "run_paper_route_boundary.sh"
VLAN_BOUNDARY_RUNNER = ROOT / "scripts" / "experiments" / "run_paper_vlan_boundary.sh"
LIB = ROOT / "lab" / "scripts" / "lib.sh"
LAB_DOCKERFILE = ROOT / "lab" / "images" / "kansoku-lab-node" / "Dockerfile"


PLANNED_FIREWALL = {
    "firewall-subnet-deny": SCENARIO_DIR / "firewall-subnet-deny.sh",
    "firewall-port-range-deny": SCENARIO_DIR / "firewall-port-range-deny.sh",
    "firewall-rule-order": SCENARIO_DIR / "firewall-rule-order.sh",
}

PLANNED_ROUTE = {
    "route-unreachable-next-hop": SCENARIO_DIR / "route-unreachable-next-hop.sh",
}

PLANNED_ROUTE_BOUNDARY = {
    "route-wrong-interface": SCENARIO_DIR / "route-wrong-interface.sh",
    "route-blackhole-host": SCENARIO_DIR / "route-blackhole-host.sh",
}

PLANNED_VLAN_BOUNDARY = {
    "vlan-access-only-drift": SCENARIO_DIR / "vlan-access-only-drift.sh",
    "vlan-trunk-only-drift": SCENARIO_DIR / "vlan-trunk-only-drift.sh",
}


def test_planned_firewall_scripts_are_present_and_isolated_from_ground_truth():
    for scenario_id, path in PLANNED_FIREWALL.items():
        text = path.read_text(encoding="utf-8")
        assert text.startswith("#!/usr/bin/env bash")
        assert "set -euo pipefail" in text
        assert f'SCENARIO="{scenario_id}"' in text
        assert "reset_network" in text
        assert "trap 'reset_network" in text
        assert "capture_https_on_fw \"$PCAP\" no" in text
        assert "collect_live_state \"$DB\"" in text
        assert "assert_verdict \"$CORRELATION\" DENY" in text
        assert "ground_truth" not in text
        assert "expected_verdict" not in text
        assert "expected_fault_domain" not in text


def test_planned_route_script_preserves_empirical_gate_and_isolates_ground_truth():
    path = PLANNED_ROUTE["route-unreachable-next-hop"]
    text = path.read_text(encoding="utf-8")
    assert text.startswith("#!/usr/bin/env bash")
    assert "set -euo pipefail" in text
    assert 'SCENARIO="route-unreachable-next-hop"' in text
    assert "no ip route 10.20.20.0/24 172.16.1.2" in text
    assert "ip route 10.20.20.0/24 172.16.1.254" in text
    assert "show ip route 10.20.20.0/24 json" in text
    assert "expected unresolved next-hop route to be absent from active FRR RIB" in text
    assert 'capture_https_on_fw "$PCAP" no' in text
    assert 'assert_verdict "$CORRELATION" UNROUTABLE' in text
    assert "ground_truth" not in text
    assert "expected_verdict" not in text
    assert "expected_fault_domain" not in text


def test_wrong_interface_boundary_validates_live_fault_without_asserting_diagnosis():
    path = PLANNED_ROUTE_BOUNDARY["route-wrong-interface"]
    text = path.read_text(encoding="utf-8")
    assert text.startswith("#!/usr/bin/env bash")
    assert "set -euo pipefail" in text
    assert 'SCENARIO="route-wrong-interface"' in text
    assert "no ip route 10.20.20.0/24 172.16.1.2" in text
    assert "ip route 10.20.20.0/24 eth1" in text
    assert 'route.get("installed") is not True' in text
    assert 'nh.get("interfaceName") == "eth1"' in text
    assert 'capture_https_on_fw "$PCAP" no' in text
    assert 'collect_live_state "$DB"' in text
    assert "assert_verdict" not in text
    assert "ground_truth" not in text
    assert "expected_verdict" not in text
    assert "expected_fault_domain" not in text


def test_blackhole_boundary_validates_frr_semantics_without_asserting_diagnosis():
    path = PLANNED_ROUTE_BOUNDARY["route-blackhole-host"]
    text = path.read_text(encoding="utf-8")
    assert text.startswith("#!/usr/bin/env bash")
    assert "set -euo pipefail" in text
    assert 'SCENARIO="route-blackhole-host"' in text
    assert "ip route 10.20.20.10/32 blackhole" in text
    assert "show ip route 10.20.20.10/32 json" in text
    assert 'route.get("installed") is not True' in text
    assert 'nh.get("blackhole") is True' in text
    assert 'nh.get("unreachable") is True' in text
    assert 'capture_https_on_fw "$PCAP" no' in text
    assert 'collect_live_state "$DB"' in text
    assert "assert_verdict" not in text
    assert "ground_truth" not in text
    assert "expected_verdict" not in text
    assert "expected_fault_domain" not in text


def test_vlan_boundary_scripts_validate_one_sided_drift_without_asserting_diagnosis():
    access = PLANNED_VLAN_BOUNDARY["vlan-access-only-drift"].read_text(encoding="utf-8")
    trunk = PLANNED_VLAN_BOUNDARY["vlan-trunk-only-drift"].read_text(encoding="utf-8")

    for scenario_id, text in (
        ("vlan-access-only-drift", access),
        ("vlan-trunk-only-drift", trunk),
    ):
        assert text.startswith("#!/usr/bin/env bash")
        assert "set -euo pipefail" in text
        assert f'SCENARIO="{scenario_id}"' in text
        assert 'capture_https_on_fw "$PCAP" yes' in text
        assert 'collect_live_state "$DB"' in text
        assert "target HTTP failed" in text
        assert "assert_verdict" not in text
        assert "ground_truth" not in text
        assert "expected_verdict" not in text
        assert "expected_fault_domain" not in text

    assert "set Port eth1 tag=30" in access
    assert 'ACCESS_TAG" != "30"' in access
    assert 'TRUNK_VLANS" != "[10]"' in access
    assert "set Port eth2 trunks=30" in trunk
    assert 'ACCESS_TAG" != "10"' in trunk
    assert 'TRUNK_VLANS" != "[30]"' in trunk


def test_planned_shell_scripts_pass_bash_syntax_check():
    paths = [
        *PLANNED_FIREWALL.values(),
        *PLANNED_ROUTE.values(),
        *PLANNED_ROUTE_BOUNDARY.values(),
        *PLANNED_VLAN_BOUNDARY.values(),
        FIREWALL_RUNNER,
        ROUTE_RUNNER,
        ROUTE_BOUNDARY_RUNNER,
        VLAN_BOUNDARY_RUNNER,
        LIB,
    ]
    for path in paths:
        proc = subprocess.run(
            ["bash", "-n", str(path)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, f"{path}: {proc.stderr}"


def test_port_range_scenario_exercises_range_normalization():
    text = PLANNED_FIREWALL["firewall-port-range-deny"].read_text(encoding="utf-8")
    assert "tcp dport 400-500" in text


def test_rule_order_scenario_uses_broad_earlier_deny():
    text = PLANNED_FIREWALL["firewall-rule-order"].read_text(encoding="utf-8")
    assert "ip saddr 10.10.10.0/24" in text
    assert "ip daddr 10.20.20.0/24" in text
    injected = text.split("run_node fw1 nft insert rule", 1)[1].split("capture_https_on_fw", 1)[0]
    assert "tcp dport 443" not in injected


def test_firewall_expansion_runner_does_not_modify_active_ground_truth():
    text = FIREWALL_RUNNER.read_text(encoding="utf-8")
    for scenario_id in PLANNED_FIREWALL:
        assert scenario_id in text
    assert "ground_truth.json" not in text
    assert "evaluate_paper_diagnostics.py" not in text


def test_route_expansion_runner_starts_with_empirically_validated_core_case_only():
    text = ROUTE_RUNNER.read_text(encoding="utf-8")
    assert "route-unreachable-next-hop" in text
    assert "route-wrong-interface" not in text
    assert "route-blackhole-host" not in text
    assert "ground_truth.json" not in text
    assert "evaluate_paper_diagnostics.py" not in text


def test_route_boundary_runner_is_separate_from_active_ground_truth_evaluation():
    text = ROUTE_BOUNDARY_RUNNER.read_text(encoding="utf-8")
    assert "route-wrong-interface" in text
    assert "route-blackhole-host" in text
    assert "route-unreachable-next-hop" not in text
    assert "ground_truth.json" in text
    assert "does not evaluate against active ground_truth.json" in text
    assert "evaluate_paper_diagnostics.py" not in text


def test_vlan_boundary_runner_is_separate_from_active_ground_truth_evaluation():
    text = VLAN_BOUNDARY_RUNNER.read_text(encoding="utf-8")
    assert "vlan-access-only-drift" in text
    assert "vlan-trunk-only-drift" in text
    assert "vlan-mismatch" not in text
    assert "ground_truth.json" in text
    assert "does not evaluate against active ground_truth.json" in text
    assert "evaluate_paper_diagnostics.py" not in text


def test_reset_network_purges_all_planned_target_route_variants_before_restore():
    lib = LIB.read_text(encoding="utf-8")
    reset = lib.split("reset_network() {", 1)[1].split("\n}\n\ncollect_state_or_fail", 1)[0]
    cleanup = [
        "no ip route 10.20.20.0/24 172.16.1.2",
        "no ip route 10.20.20.0/24 172.16.1.254",
        "no ip route 10.20.20.0/24 eth1",
        "no ip route 10.20.20.10/32 blackhole",
    ]
    restore = "ip route 10.20.20.0/24 172.16.1.2"
    for command in cleanup:
        assert command in reset
        assert reset.index(command) < reset.rindex(restore)


def test_lab_uses_dedicated_tcpdump_path_and_reports_capture_failures():
    dockerfile = LAB_DOCKERFILE.read_text(encoding="utf-8")
    lib = LIB.read_text(encoding="utf-8")
    helper = "/usr/local/libexec/kansoku-tcpdump"

    assert f"cp /usr/bin/tcpdump {helper}" in dockerfile
    assert f'KANSOKU_TCPDUMP_BIN="${{KANSOKU_TCPDUMP_BIN:-{helper}}}"' in lib
    assert 'tcpdump capture failed (rc=$tcpdump_rc)' in lib
    assert "remote capture file is missing or empty" in lib
