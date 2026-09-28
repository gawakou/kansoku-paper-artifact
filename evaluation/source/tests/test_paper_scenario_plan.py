from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PLAN = ROOT / "scenarios" / "paper" / "scenario_plan.json"
CATALOG = ROOT / "scenarios" / "paper" / "catalog.json"
GROUND_TRUTH = ROOT / "scenarios" / "paper" / "ground_truth.json"


def _load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_scenario_plan_has_expected_structure():
    plan = _load(PLAN)
    assert plan["schema_version"] == 1
    assert plan["target_spec"] == "target_https.json"
    assert plan["active_ground_truth"] == "ground_truth.json"
    assert plan["design_rules"]["diagnosers_must_not_read_ground_truth"] is True
    assert plan["design_rules"]["single_faults_before_compound_faults"] is True
    assert plan["design_rules"]["boundary_cases_are_retained_even_when_the_current_model_is_expected_to_fail"] is True


def test_single_fault_plan_is_balanced_and_compounds_are_deferred():
    scenarios = _load(PLAN)["scenarios"]
    singles = {sid: item for sid, item in scenarios.items() if item["phase"] == "single"}
    compounds = {sid: item for sid, item in scenarios.items() if item["phase"] == "compound"}

    assert len(singles) == 12
    assert len(compounds) == 2

    family_counts = {}
    for item in singles.values():
        family_counts[item["family"]] = family_counts.get(item["family"], 0) + 1
    assert family_counts == {
        "CONTROL": 1,
        "FIREWALL": 4,
        "ROUTE": 4,
        "VLAN": 3,
    }

    for item in compounds.values():
        assert item["status"] == "deferred"
        assert item["evaluator_schema_support"] is False
        assert item["expected_limitation"] is True


def test_active_ground_truth_is_exactly_the_validated_catalog_subset():
    plan = _load(PLAN)["scenarios"]
    catalog = _load(CATALOG)["scenarios"]
    ground_truth = _load(GROUND_TRUTH)["scenarios"]

    validated = {
        sid
        for sid, item in catalog.items()
        if item["validation_status"] in {"pilot-verified", "live-verified"}
    }
    assert set(ground_truth) == validated
    assert validated == {
        "normal",
        "firewall-deny",
        "firewall-subnet-deny",
        "firewall-port-range-deny",
        "firewall-rule-order",
        "route-missing",
        "route-unreachable-next-hop",
        "route-wrong-interface",
        "route-blackhole-host",
        "vlan-mismatch",
        "vlan-access-only-drift",
        "vlan-trunk-only-drift",
    }
    assert validated <= set(plan)


def test_live_promotions_were_predeclared_in_scenario_plan():
    plan = _load(PLAN)["scenarios"]
    catalog = _load(CATALOG)["scenarios"]
    live = {sid for sid, item in catalog.items() if item["validation_status"] == "live-verified"}
    assert live == {
        "firewall-subnet-deny",
        "firewall-port-range-deny",
        "firewall-rule-order",
        "route-unreachable-next-hop",
        "route-wrong-interface",
        "route-blackhole-host",
        "vlan-access-only-drift",
        "vlan-trunk-only-drift",
    }

    firewall_live = {
        "firewall-subnet-deny",
        "firewall-port-range-deny",
        "firewall-rule-order",
    }
    for scenario_id in firewall_live:
        item = plan[scenario_id]
        assert item["status"] == "planned-core"
        assert item["ground_truth"]["expected_verdict"] == "DENY"
        assert item["ground_truth"]["expected_fault_domain"] == "FIREWALL"
        assert item["ground_truth"]["expected_affected_device"] == "fw1"
        assert item["ground_truth"]["expected_element_type"] == "POLICY_RULE"

    route_item = plan["route-unreachable-next-hop"]
    assert route_item["status"] == "planned-core-empirical-gate"
    assert route_item["ground_truth"]["expected_verdict"] == "UNROUTABLE"
    assert route_item["ground_truth"]["expected_fault_domain"] == "ROUTE"
    assert route_item["ground_truth"]["expected_affected_device"] == "r1"
    assert route_item["ground_truth"]["expected_element_type"] == "ROUTE"

    for scenario_id in {"route-wrong-interface", "route-blackhole-host"}:
        boundary_item = plan[scenario_id]
        assert boundary_item["status"] == "planned-boundary"
        assert boundary_item["expected_limitation"] is True
        assert boundary_item["ground_truth"]["expected_verdict"] == "UNROUTABLE"
        assert boundary_item["ground_truth"]["expected_fault_domain"] == "ROUTE"
        assert boundary_item["ground_truth"]["expected_affected_device"] == "r1"
        assert boundary_item["ground_truth"]["expected_element_type"] == "ROUTE"
        assert catalog[scenario_id]["boundary"] is True
        assert catalog[scenario_id]["expected_limitation"] is True

    for scenario_id in {"vlan-access-only-drift", "vlan-trunk-only-drift"}:
        boundary_item = plan[scenario_id]
        assert boundary_item["status"] == "planned-boundary"
        assert boundary_item["expected_limitation"] is True
        assert boundary_item["ground_truth"]["expected_verdict"] == "UNKNOWN"
        assert boundary_item["ground_truth"]["expected_fault_domain"] == "VLAN"
        assert boundary_item["ground_truth"]["expected_affected_device"] == "sw1"
        assert boundary_item["ground_truth"]["expected_element_type"] == "VLAN"
        assert catalog[scenario_id]["boundary"] is True
        assert catalog[scenario_id]["expected_limitation"] is True


def test_every_non_control_single_fault_has_reset_and_promotion_gate():
    plan = _load(PLAN)
    assert plan["design_rules"]["reset_between_trials"] == "reset_network"
    for scenario_id, item in plan["scenarios"].items():
        assert item["promotion_gate"].strip(), scenario_id
        if item["phase"] == "single" and item["family"] != "CONTROL":
            assert item["fault_injection"]["summary"].strip(), scenario_id
            assert item["ground_truth"]["expected_fault_domain"] in {"FIREWALL", "ROUTE", "VLAN"}


def test_boundary_cases_are_explicit_not_silently_counted_as_supported():
    scenarios = _load(PLAN)["scenarios"]
    boundary = {
        "route-wrong-interface",
        "route-blackhole-host",
        "vlan-access-only-drift",
        "vlan-trunk-only-drift",
    }
    for scenario_id in boundary:
        item = scenarios[scenario_id]
        assert item["expected_limitation"] is True
        assert "boundary" in item["status"]


def test_current_cross_layer_discriminating_case_remains_registered():
    item = _load(PLAN)["scenarios"]["vlan-mismatch"]
    assert item["method_expectation"]["FLOW_ONLY"] == "ALLOW/NONE"
    assert item["method_expectation"]["CONFIG_ONLY"] == "ALLOW/NONE"
    assert item["method_expectation"]["PROPOSED"] == "UNKNOWN/VLAN"
    assert item["expected_limitation"] is False
