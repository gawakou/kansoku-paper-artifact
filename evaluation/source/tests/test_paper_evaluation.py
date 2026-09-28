from __future__ import annotations

from pathlib import Path

import pytest

from kansoku.paper_evaluation import (
    ElementRefExpectation,
    evaluate_diagnostics_payload,
    evaluate_method,
    load_ground_truth,
    summarize_records,
)


ROOT = Path(__file__).resolve().parents[1]
GROUND_TRUTH = ROOT / "scenarios" / "paper" / "ground_truth.json"

PILOT_SCENARIOS = {
    "normal",
    "firewall-deny",
    "route-missing",
    "vlan-mismatch",
}

ACTIVE_SCENARIOS = PILOT_SCENARIOS | {
    "firewall-subnet-deny",
    "firewall-port-range-deny",
    "firewall-rule-order",
    "route-unreachable-next-hop",
    "route-wrong-interface",
    "route-blackhole-host",
    "vlan-access-only-drift",
    "vlan-trunk-only-drift",
}


def result(
    method: str,
    verdict: str,
    domain: str,
    device: str,
    element_type: str,
    element_ref: str,
    *,
    abstained: bool = False,
):
    return {
        "method": method,
        "verdict": verdict,
        "fault_domain": domain,
        "affected_device": device,
        "affected_element_type": element_type,
        "affected_element_ref": element_ref,
        "abstained": abstained,
    }


def pilot_payloads():
    return {
        "normal": {
            "results": {
                "FLOW_ONLY": result("FLOW_ONLY", "ALLOW", "NONE", "", "NONE", "none"),
                "CONFIG_ONLY": result("CONFIG_ONLY", "ALLOW", "NONE", "", "NONE", "none"),
                "PROPOSED": result("PROPOSED", "ALLOW", "NONE", "", "NONE", "none"),
            }
        },
        "firewall-deny": {
            "results": {
                "FLOW_ONLY": result(
                    "FLOW_ONLY", "UNKNOWN", "UNKNOWN", "UNKNOWN", "UNKNOWN", "unknown",
                    abstained=True,
                ),
                "CONFIG_ONLY": result(
                    "CONFIG_ONLY", "DENY", "FIREWALL", "fw1", "POLICY_RULE",
                    "policy:rule-runtime-id",
                ),
                "PROPOSED": result(
                    "PROPOSED", "DENY", "FIREWALL", "fw1", "POLICY_RULE",
                    "policy:rule-runtime-id",
                ),
            }
        },
        "route-missing": {
            "results": {
                "FLOW_ONLY": result(
                    "FLOW_ONLY", "UNKNOWN", "UNKNOWN", "UNKNOWN", "UNKNOWN", "unknown",
                    abstained=True,
                ),
                "CONFIG_ONLY": result(
                    "CONFIG_ONLY", "UNROUTABLE", "ROUTE", "r1", "ROUTE",
                    "route-missing:10.20.20.10",
                ),
                "PROPOSED": result(
                    "PROPOSED", "UNROUTABLE", "ROUTE", "r1", "ROUTE",
                    "route-missing:10.20.20.10",
                ),
            }
        },
        "vlan-mismatch": {
            "results": {
                "FLOW_ONLY": result("FLOW_ONLY", "ALLOW", "NONE", "", "NONE", "none"),
                "CONFIG_ONLY": result("CONFIG_ONLY", "ALLOW", "NONE", "", "NONE", "none"),
                "PROPOSED": result(
                    "PROPOSED", "UNKNOWN", "VLAN", "sw1", "VLAN", "vlan-missing:10",
                ),
            }
        },
    }


def test_ground_truth_loads_independently():
    ground_truth = load_ground_truth(GROUND_TRUTH)
    assert set(ground_truth) == ACTIVE_SCENARIOS
    assert ground_truth["firewall-deny"].expected_fault_domain == "FIREWALL"
    assert ground_truth["firewall-subnet-deny"].expected_fault_domain == "FIREWALL"
    assert ground_truth["firewall-port-range-deny"].expected_element_ref.mode == "prefix"
    assert ground_truth["firewall-rule-order"].expected_element_ref.value == "policy:"
    assert ground_truth["route-unreachable-next-hop"].expected_verdict == "UNROUTABLE"
    assert ground_truth["route-unreachable-next-hop"].expected_fault_domain == "ROUTE"
    assert ground_truth["route-unreachable-next-hop"].expected_element_ref.value == "route-missing:10.20.20.10"
    assert ground_truth["route-wrong-interface"].expected_verdict == "UNROUTABLE"
    assert ground_truth["route-wrong-interface"].expected_fault_domain == "ROUTE"
    assert ground_truth["route-wrong-interface"].expected_element_ref.mode == "ignore"
    assert ground_truth["route-blackhole-host"].expected_verdict == "UNROUTABLE"
    assert ground_truth["route-blackhole-host"].expected_fault_domain == "ROUTE"
    assert ground_truth["route-blackhole-host"].expected_element_ref.mode == "ignore"
    assert ground_truth["vlan-mismatch"].expected_element_ref.value == "vlan-missing:10"
    for scenario_id in {"vlan-access-only-drift", "vlan-trunk-only-drift"}:
        assert ground_truth[scenario_id].expected_verdict == "UNKNOWN"
        assert ground_truth[scenario_id].expected_fault_domain == "VLAN"
        assert ground_truth[scenario_id].expected_affected_device == "sw1"
        assert ground_truth[scenario_id].expected_element_ref.mode == "ignore"


def test_element_ref_match_modes():
    assert ElementRefExpectation("exact", "route-missing:10.20.20.10").matches(
        "route-missing:10.20.20.10"
    )
    assert ElementRefExpectation("prefix", "policy:").matches("policy:rule-123")
    assert ElementRefExpectation("ignore", "").matches("anything")
    with pytest.raises(ValueError):
        ElementRefExpectation("regex", ".*").validate()


def test_firewall_runtime_rule_id_is_not_fixed_in_ground_truth():
    ground_truth = load_ground_truth(GROUND_TRUTH)["firewall-deny"]
    record = evaluate_method(
        ground_truth,
        "PROPOSED",
        result(
            "PROPOSED",
            "DENY",
            "FIREWALL",
            "fw1",
            "POLICY_RULE",
            "policy:any-runtime-generated-id",
        ),
    )
    assert record.verdict_correct is True
    assert record.localization_correct is True
    assert record.strict_correct is True


def test_abstention_is_recorded_but_not_counted_as_correct_fault_diagnosis():
    ground_truth = load_ground_truth(GROUND_TRUTH)["route-missing"]
    record = evaluate_method(
        ground_truth,
        "FLOW_ONLY",
        result(
            "FLOW_ONLY",
            "UNKNOWN",
            "UNKNOWN",
            "UNKNOWN",
            "UNKNOWN",
            "unknown",
            abstained=True,
        ),
    )
    assert record.abstained is True
    assert record.answered is False
    assert record.verdict_correct is False
    assert record.localization_correct is False
    assert record.strict_correct is False


def test_vlan_cross_layer_result_is_correct_but_config_only_allow_is_not():
    ground_truth = load_ground_truth(GROUND_TRUTH)["vlan-mismatch"]
    proposed = evaluate_method(
        ground_truth,
        "PROPOSED",
        result("PROPOSED", "UNKNOWN", "VLAN", "sw1", "VLAN", "vlan-missing:10"),
    )
    config_only = evaluate_method(
        ground_truth,
        "CONFIG_ONLY",
        result("CONFIG_ONLY", "ALLOW", "NONE", "", "NONE", "none"),
    )
    assert proposed.strict_correct is True
    assert proposed.abstained is False
    assert config_only.verdict_correct is False
    assert config_only.localization_correct is False


def test_wrong_interface_boundary_retains_observed_allow_as_incorrect():
    ground_truth = load_ground_truth(GROUND_TRUTH)["route-wrong-interface"]
    proposed = evaluate_method(
        ground_truth,
        "PROPOSED",
        result("PROPOSED", "ALLOW", "NONE", "", "NONE", "none"),
    )
    config_only = evaluate_method(
        ground_truth,
        "CONFIG_ONLY",
        result("CONFIG_ONLY", "ALLOW", "NONE", "", "NONE", "none"),
    )
    assert proposed.verdict_correct is False
    assert proposed.fault_domain_correct is False
    assert proposed.localization_correct is False
    assert proposed.strict_correct is False
    assert config_only.strict_correct is False


def test_blackhole_boundary_retains_observed_allow_as_incorrect():
    ground_truth = load_ground_truth(GROUND_TRUTH)["route-blackhole-host"]
    proposed = evaluate_method(
        ground_truth,
        "PROPOSED",
        result("PROPOSED", "ALLOW", "NONE", "", "NONE", "none"),
    )
    config_only = evaluate_method(
        ground_truth,
        "CONFIG_ONLY",
        result("CONFIG_ONLY", "ALLOW", "NONE", "", "NONE", "none"),
    )
    assert proposed.verdict_correct is False
    assert proposed.fault_domain_correct is False
    assert proposed.localization_correct is False
    assert proposed.strict_correct is False
    assert config_only.strict_correct is False


def test_partial_vlan_boundaries_retain_observed_allow_as_incorrect():
    ground_truth = load_ground_truth(GROUND_TRUTH)
    for scenario_id in {"vlan-access-only-drift", "vlan-trunk-only-drift"}:
        for method in ("FLOW_ONLY", "CONFIG_ONLY", "PROPOSED"):
            record = evaluate_method(
                ground_truth[scenario_id],
                method,
                result(method, "ALLOW", "NONE", "", "NONE", "none"),
            )
            assert record.verdict_correct is False
            assert record.fault_domain_correct is False
            assert record.localization_correct is False
            assert record.strict_correct is False


def test_payload_rejects_method_key_mismatch():
    ground_truth = load_ground_truth(GROUND_TRUTH)["normal"]
    payload = {
        "results": {
            "FLOW_ONLY": result("PROPOSED", "ALLOW", "NONE", "", "NONE", "none")
        }
    }
    with pytest.raises(ValueError, match="method mismatch"):
        evaluate_diagnostics_payload(ground_truth, payload)


def test_pilot_summary_expected_pattern():
    active_ground_truth = load_ground_truth(GROUND_TRUTH)
    payloads = pilot_payloads()
    pilot_ground_truth = {
        scenario_id: active_ground_truth[scenario_id]
        for scenario_id in payloads
    }
    records = []
    for scenario_id, payload in payloads.items():
        records.extend(evaluate_diagnostics_payload(pilot_ground_truth[scenario_id], payload))

    summary = summarize_records(records, pilot_ground_truth)
    flow = summary["methods"]["FLOW_ONLY"]
    config = summary["methods"]["CONFIG_ONLY"]
    proposed = summary["methods"]["PROPOSED"]

    assert summary["scenario_count"] == 4
    assert summary["record_count"] == 12

    assert flow["coverage"] == pytest.approx(0.5)
    assert flow["verdict_accuracy"] == pytest.approx(0.25)
    assert flow["fault_domain_accuracy"] == pytest.approx(0.25)
    assert flow["localization_accuracy"] == pytest.approx(0.0)

    assert config["coverage"] == pytest.approx(1.0)
    assert config["verdict_accuracy"] == pytest.approx(0.75)
    assert config["fault_domain_accuracy"] == pytest.approx(0.75)
    assert config["localization_accuracy"] == pytest.approx(2 / 3)

    assert proposed["coverage"] == pytest.approx(1.0)
    assert proposed["verdict_accuracy"] == pytest.approx(1.0)
    assert proposed["fault_domain_accuracy"] == pytest.approx(1.0)
    assert proposed["localization_accuracy"] == pytest.approx(1.0)
    assert proposed["strict_accuracy"] == pytest.approx(1.0)
