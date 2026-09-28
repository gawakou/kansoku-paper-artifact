from __future__ import annotations

import json
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

PLAN = (
    ROOT
    / "scenarios"
    / "paper"
    / "rq3_guarded_remediation_plan.json"
)

GT = (
    ROOT
    / "scenarios"
    / "paper"
    / "rq3_guarded_remediation_ground_truth.json"
)


def load(path: Path):
    return json.loads(
        path.read_text(encoding="utf-8")
    )


def test_rq3_plan_shape():
    plan = load(PLAN)
    gt = load(GT)

    assert plan["schema_version"] == 1
    assert gt["schema_version"] == 1

    assert plan["execution_count"] == 15
    assert gt["execution_count"] == 15

    assert plan["fault_family_count"] == 3
    assert gt["fault_family_count"] == 3

    assert plan["repetitions_per_family"] == 5
    assert gt["repetitions_per_family"] == 5

    assert set(plan["executions"]) == set(
        gt["instances"]
    )


def test_rq3_family_balance():
    plan = load(PLAN)

    families = Counter(
        row["family"]
        for row in plan["executions"].values()
    )

    assert families == {
        "FIREWALL": 5,
        "ROUTE": 5,
        "VLAN": 5,
    }


def test_rq3_repetitions_are_not_independent():
    plan = load(PLAN)
    gt = load(GT)

    assert (
        "not independent fault samples"
        in plan[
            "independence_statement"
        ]
    )

    stats = gt[
        "statistical_interpretation"
    ]

    assert (
        stats[
            "repetitions_are_not_independent_fault_samples"
        ]
        is True
    )

    assert (
        stats["independent_fault_families"]
        == 3
    )


def test_rq3_runner_plan_contains_no_outcome_gt():
    plan = load(PLAN)

    forbidden = {
        "expected_recommendation_category",
        "expected_category",
        "expected_device",
        "expected_top1_variant",
    }

    for row in plan["families"].values():
        assert not (
            forbidden & set(row)
        )


def test_rq3_ground_truth_is_runner_forbidden():
    gt = load(GT)

    assert (
        gt[
            "ground_truth_must_not_be_consumed_by_runner"
        ]
        is True
    )


def test_rq3_preregistered_probes():
    plan = load(PLAN)

    lab = plan["lab"]

    assert (
        lab["target"]["destination_port"]
        == 443
    )

    assert (
        lab["security_invariant"][
            "destination_port"
        ]
        == 8443
    )

    assert (
        lab["security_invariant"][
            "service_must_be_listening"
        ]
        is True
    )

    assert (
        lab["security_invariant"][
            "expected_client_reachability"
        ]
        is False
    )

    assert (
        lab["independent_control"][
            "destination_ip"
        ]
        == "10.20.20.1"
    )

    assert (
        lab["firewall_same_path_control"][
            "destination_port"
        ]
        == 5201
    )


def test_rq3_fault_families():
    plan = load(PLAN)

    f = plan["families"]

    assert (
        f["FIREWALL"]["fault_scenario"]
        == "firewall-deny"
    )

    assert (
        f["ROUTE"]["fault_scenario"]
        == "route-missing"
    )

    assert (
        f["VLAN"]["fault_scenario"]
        == "vlan-mismatch"
    )

    assert (
        f["FIREWALL"][
            "same_path_control_required"
        ]
        is True
    )

    assert (
        f["ROUTE"][
            "same_path_control_required"
        ]
        is False
    )

    assert (
        f["VLAN"][
            "same_path_control_required"
        ]
        is False
    )


def test_rq3_ground_truth_state_transitions():
    gt = load(GT)

    for row in gt["instances"].values():
        assert (
            row["expected_fault_state"][
                "target_reachable"
            ]
            is False
        )

        assert (
            row["expected_post_change_state"][
                "target_reachable"
            ]
            is True
        )

        assert (
            row["expected_post_rollback_state"][
                "target_reachable"
            ]
            is False
        )

        assert (
            row["expected_final_baseline_state"][
                "target_reachable"
            ]
            is True
        )

        for stage in (
            "expected_fault_state",
            "expected_post_change_state",
            "expected_post_rollback_state",
            "expected_final_baseline_state",
        ):
            assert (
                row[stage][
                    "independent_control_reachable"
                ]
                is True
            )

            assert (
                row[stage][
                    "security_invariant_reachable"
                ]
                is False
            )


def test_rq3_primary_metrics_are_fixed():
    plan = load(PLAN)

    assert plan["primary_metrics"] == [
        "eligible_top1_rate",
        "apply_success_rate",
        "target_recovery_rate",
        "independent_control_preservation_rate",
        "security_invariant_preservation_rate",
        "rollback_success_rate",
        "fault_restoration_rate",
        "what_if_actual_agreement_rate",
        "final_baseline_restoration_rate",
    ]


def test_rq3_repair_context_is_preregistered():
    plan = load(PLAN)

    assert (
        plan["runner_constraints"][
            "ground_truth_file_must_not_be_read"
        ]
        is True
    )

    assert (
        plan["runner_constraints"][
            "rollback_after_verify"
        ]
        is True
    )

    f = plan["families"]

    assert f["FIREWALL"][
        "recommendation_inputs"
    ] == {
        "policy_device_id": "fw1"
    }

    assert f["ROUTE"][
        "recommendation_inputs"
    ] == {
        "route_device_id": "r1",
        "destination_prefix": "10.20.20.0/24",
        "next_hop": "172.16.1.2",
        "out_interface": "eth2",
    }

    assert f["VLAN"][
        "recommendation_inputs"
    ] == {
        "vlan_device_id": "sw1",
        "access_interface": "eth1",
        "trunk_interface": "eth2",
    }


def test_rq3_fault_injection_and_capture_timing_are_fixed():
    plan = load(PLAN)
    f = plan["families"]

    assert (
        f["FIREWALL"]["capture_timing"]
        == "after_fault_injection"
    )
    assert (
        f["ROUTE"]["capture_timing"]
        == "after_fault_injection"
    )
    assert (
        f["VLAN"]["capture_timing"]
        == "before_fault_injection"
    )

    assert (
        f["FIREWALL"]["fault_injection"]["type"]
        == "NFT_INSERT_DENY"
    )
    assert (
        f["FIREWALL"]["fault_injection"][
            "dst_port"
        ]
        == 443
    )

    assert (
        f["ROUTE"]["fault_injection"]["type"]
        == "REMOVE_STATIC_ROUTE"
    )
    assert (
        f["ROUTE"]["fault_injection"][
            "next_hop"
        ]
        == "172.16.1.2"
    )

    assert (
        f["VLAN"]["fault_injection"]["type"]
        == "VLAN_ACCESS_TRUNK_DRIFT"
    )
    assert (
        f["VLAN"]["fault_injection"][
            "access_vlan"
        ]
        == 30
    )
    assert (
        f["VLAN"]["fault_injection"][
            "trunk_vlan"
        ]
        == 30
    )
