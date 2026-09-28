from __future__ import annotations

from collections import Counter
import ipaddress
import json
from pathlib import Path

from kansoku.diagnostic_eval import TargetFlowSpec


ROOT = Path(__file__).resolve().parents[1]
INSTANCE_PATH = ROOT / "scenarios" / "paper" / "parameterized_instances.json"
GROUND_TRUTH_PATH = (
    ROOT / "scenarios" / "paper" / "parameterized_ground_truth.json"
)

TARGETS = [
    "10.20.20.10",
    "10.20.20.11",
    "10.20.20.12",
    "10.20.20.13",
    "10.20.20.14",
]

SOURCE_SUBNETS = [
    "10.10.10.0/24",
    "10.10.10.0/25",
    "10.10.10.0/26",
    "10.10.10.0/27",
    "10.10.10.8/29",
]

PORT_RANGES = [
    "440-445",
    "442-444",
    "400-500",
    "443-450",
    "430-443",
]

RULE_ORDER_PREFIXES = [
    "10.20.20.0/24",
    "10.20.20.0/25",
    "10.20.20.0/26",
    "10.20.20.0/27",
    "10.20.20.0/28",
]

NEXT_HOPS = [
    "172.16.1.250",
    "172.16.1.251",
    "172.16.1.252",
    "172.16.1.253",
    "172.16.1.254",
]

ROUTE_PREFIXES = [
    "10.20.20.0/25",
    "10.20.20.0/26",
    "10.20.20.0/27",
    "10.20.20.0/28",
    "10.20.20.10/32",
]

VLANS = [20, 30, 40, 50, 100]

BOUNDARY_PROTOTYPES = {
    "route-wrong-interface",
    "route-blackhole-host",
    "vlan-access-only-drift",
    "vlan-trunk-only-drift",
}


def _load():
    instances = json.loads(INSTANCE_PATH.read_text(encoding="utf-8"))
    ground_truth = json.loads(
        GROUND_TRUTH_PATH.read_text(encoding="utf-8")
    )
    return instances, ground_truth


def _expected_instance_ids(prototype: str) -> list[str]:
    return [
        f"{prototype}-v{i:02d}"
        for i in range(1, 6)
    ]


def _collect_keys(value):
    """Recursively collect dictionary keys for leakage checks."""
    keys = set()

    if isinstance(value, dict):
        for key, child in value.items():
            keys.add(key)
            keys.update(_collect_keys(child))
    elif isinstance(value, list):
        for child in value:
            keys.update(_collect_keys(child))

    return keys


def test_parameterized_plan_structure():
    plan, gt_doc = _load()

    assert plan["schema_version"] == 1
    assert gt_doc["schema_version"] == 1

    instances = plan["instances"]
    ground_truth = gt_doc["instances"]

    assert len(instances) == 60
    assert len(ground_truth) == 60
    assert set(instances) == set(ground_truth)

    prototype_counts = Counter(
        row["prototype_id"]
        for row in instances.values()
    )

    assert prototype_counts == {
        "normal": 5,
        "firewall-deny": 5,
        "firewall-subnet-deny": 5,
        "firewall-port-range-deny": 5,
        "firewall-rule-order": 5,
        "route-missing": 5,
        "route-unreachable-next-hop": 5,
        "route-wrong-interface": 5,
        "route-blackhole-host": 5,
        "vlan-mismatch": 5,
        "vlan-access-only-drift": 5,
        "vlan-trunk-only-drift": 5,
    }

    family_counts = Counter(
        row["family"]
        for row in instances.values()
    )

    assert family_counts == {
        "CONTROL": 5,
        "FIREWALL": 20,
        "ROUTE": 20,
        "VLAN": 15,
    }

    boundary_counts = Counter(
        row["boundary"]
        for row in ground_truth.values()
    )

    assert boundary_counts == {
        False: 40,
        True: 20,
    }


def test_phase2_design_metadata_is_preregistered():
    plan, _ = _load()
    design = plan["design"]

    assert design["instance_count"] == 60
    assert design["prototypes"] == 12
    assert design["variants_per_prototype"] == 5
    assert design["planned_repetitions_per_instance"] == 5
    assert design["planned_execution_count"] == 300

    assert design["accuracy_unit"] == "parameterized instance"

    assert (
        design[
            "deterministic_repetitions_are_not_independent_accuracy_samples"
        ]
        is True
    )

    assert design["ground_truth_must_not_be_available_to_diagnosers"] is True

    assert "reset_network" in design["trial_isolation"]
    assert "cleanup" in design["trial_isolation"].lower()


def test_all_targets_parse_with_production_target_flow_spec():
    plan, _ = _load()

    seen_query_ids = set()

    for instance_id, row in plan["instances"].items():
        target = TargetFlowSpec.from_dict(row["target"])

        assert target.query_id == f"phase2-{instance_id}"
        assert target.query_id not in seen_query_ids

        seen_query_ids.add(target.query_id)

        assert target.ip_version == 4
        assert target.protocol == "TCP"
        assert target.src_ip == "10.10.10.10"
        assert target.dst_port == 443
        assert target.src_port is None

    assert len(seen_query_ids) == 60


def test_execution_plan_contains_no_ground_truth_leakage():
    plan, _ = _load()

    all_keys = _collect_keys(plan)

    forbidden_exact = {
        "boundary",
        "method_expectation",
        "observed_model_result",
        "verdict_correct",
        "fault_domain_correct",
        "localization_correct",
        "strict_correct",
    }

    assert not (all_keys & forbidden_exact)

    for key in all_keys:
        assert not key.startswith("expected_")


def test_ground_truth_contains_no_method_specific_predictions():
    _, gt_doc = _load()

    all_keys = _collect_keys(gt_doc)

    forbidden = {
        "method_expectation",
        "FLOW_ONLY",
        "CONFIG_ONLY",
        "PROPOSED",
        "observed_model_result",
    }

    assert not (all_keys & forbidden)


def test_instance_and_ground_truth_metadata_agree():
    plan, gt_doc = _load()

    instances = plan["instances"]
    ground_truth = gt_doc["instances"]

    for instance_id in instances:
        assert (
            instances[instance_id]["prototype_id"]
            == ground_truth[instance_id]["prototype_id"]
        )
        assert (
            instances[instance_id]["family"]
            == ground_truth[instance_id]["family"]
        )


def test_exact_preregistered_target_variants():
    plan, _ = _load()
    instances = plan["instances"]

    for prototype in ("normal", "firewall-deny", "route-missing"):
        rows = [
            instances[iid]
            for iid in _expected_instance_ids(prototype)
        ]

        assert [
            row["target"]["dst_ip"]
            for row in rows
        ] == TARGETS

    for i, dst in enumerate(TARGETS, 1):
        row = instances[f"normal-v{i:02d}"]
        assert row["parameters"] == {
            "target_alias": dst,
        }

        row = instances[f"firewall-deny-v{i:02d}"]
        assert row["parameters"] == {
            "deny_dst_ip": dst,
        }

        row = instances[f"route-missing-v{i:02d}"]
        assert row["parameters"] == {
            "removed_prefix": "10.20.20.0/24",
            "target_alias": dst,
        }


def test_exact_preregistered_firewall_variants():
    plan, _ = _load()
    instances = plan["instances"]

    for i, subnet in enumerate(SOURCE_SUBNETS, 1):
        iid = f"firewall-subnet-deny-v{i:02d}"
        assert instances[iid]["parameters"] == {
            "source_subnet": subnet,
        }

        assert (
            ipaddress.ip_address("10.10.10.10")
            in ipaddress.ip_network(subnet)
        )

    for i, port_range in enumerate(PORT_RANGES, 1):
        iid = f"firewall-port-range-deny-v{i:02d}"
        assert instances[iid]["parameters"] == {
            "destination_port_range": port_range,
        }

        lo, hi = map(int, port_range.split("-"))
        assert lo <= 443 <= hi

    for i, prefix in enumerate(RULE_ORDER_PREFIXES, 1):
        iid = f"firewall-rule-order-v{i:02d}"
        assert instances[iid]["parameters"] == {
            "shadowing_destination_prefix": prefix,
        }

        assert (
            ipaddress.ip_address("10.20.20.10")
            in ipaddress.ip_network(prefix)
        )


def test_exact_preregistered_route_variants():
    plan, _ = _load()
    instances = plan["instances"]

    directly_connected = ipaddress.ip_network("172.16.1.0/30")

    for i, nh in enumerate(NEXT_HOPS, 1):
        iid = f"route-unreachable-next-hop-v{i:02d}"

        assert instances[iid]["parameters"] == {
            "unreachable_next_hop": nh,
        }

        assert (
            ipaddress.ip_address(nh)
            not in directly_connected
        )

    target = ipaddress.ip_address("10.20.20.10")

    for i, prefix in enumerate(ROUTE_PREFIXES, 1):
        iid = f"route-wrong-interface-v{i:02d}"

        assert instances[iid]["parameters"] == {
            "route_prefix": prefix,
            "wrong_interface": "eth1",
        }

        assert target in ipaddress.ip_network(prefix)

        iid = f"route-blackhole-host-v{i:02d}"

        assert instances[iid]["parameters"] == {
            "blackhole_prefix": prefix,
        }

        assert target in ipaddress.ip_network(prefix)


def test_exact_preregistered_vlan_variants():
    plan, _ = _load()
    instances = plan["instances"]

    for i, vlan in enumerate(VLANS, 1):
        assert vlan != 10

        assert instances[
            f"vlan-mismatch-v{i:02d}"
        ]["parameters"] == {
            "drift_vlan": vlan,
        }

        assert instances[
            f"vlan-access-only-drift-v{i:02d}"
        ]["parameters"] == {
            "access_drift_vlan": vlan,
        }

        assert instances[
            f"vlan-trunk-only-drift-v{i:02d}"
        ]["parameters"] == {
            "trunk_drift_vlan": vlan,
        }


def test_boundary_set_is_exactly_preregistered_four_prototypes():
    _, gt_doc = _load()

    actual = {
        row["prototype_id"]
        for row in gt_doc["instances"].values()
        if row["boundary"]
    }

    assert actual == BOUNDARY_PROTOTYPES

    for row in gt_doc["instances"].values():
        assert row["boundary"] == (
            row["prototype_id"] in BOUNDARY_PROTOTYPES
        )


def test_ground_truth_labels_match_preregistered_prototype_semantics():
    _, gt_doc = _load()
    ground_truth = gt_doc["instances"]

    expected = {
        "normal": (
            "ALLOW",
            "NONE",
            "",
            "NONE",
        ),
        "firewall-deny": (
            "DENY",
            "FIREWALL",
            "fw1",
            "POLICY_RULE",
        ),
        "firewall-subnet-deny": (
            "DENY",
            "FIREWALL",
            "fw1",
            "POLICY_RULE",
        ),
        "firewall-port-range-deny": (
            "DENY",
            "FIREWALL",
            "fw1",
            "POLICY_RULE",
        ),
        "firewall-rule-order": (
            "DENY",
            "FIREWALL",
            "fw1",
            "POLICY_RULE",
        ),
        "route-missing": (
            "UNROUTABLE",
            "ROUTE",
            "r1",
            "ROUTE",
        ),
        "route-unreachable-next-hop": (
            "UNROUTABLE",
            "ROUTE",
            "r1",
            "ROUTE",
        ),
        "route-wrong-interface": (
            "UNROUTABLE",
            "ROUTE",
            "r1",
            "ROUTE",
        ),
        "route-blackhole-host": (
            "UNROUTABLE",
            "ROUTE",
            "r1",
            "ROUTE",
        ),
        "vlan-mismatch": (
            "UNKNOWN",
            "VLAN",
            "sw1",
            "VLAN",
        ),
        "vlan-access-only-drift": (
            "UNKNOWN",
            "VLAN",
            "sw1",
            "VLAN",
        ),
        "vlan-trunk-only-drift": (
            "UNKNOWN",
            "VLAN",
            "sw1",
            "VLAN",
        ),
    }

    for instance_id, row in ground_truth.items():
        (
            verdict,
            domain,
            device,
            element_type,
        ) = expected[row["prototype_id"]]

        assert row["expected_verdict"] == verdict
        assert row["expected_fault_domain"] == domain
        assert row["expected_affected_device"] == device
        assert row["expected_element_type"] == element_type
