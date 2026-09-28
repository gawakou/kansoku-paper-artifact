from __future__ import annotations

import json
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

PLAN = (
    ROOT
    / "scenarios"
    / "paper"
    / "rq2_recommendation_instances.json"
)

GT = (
    ROOT
    / "scenarios"
    / "paper"
    / "rq2_recommendation_ground_truth.json"
)


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_rq2_plan_has_15_balanced_instances():
    plan = load(PLAN)
    gt = load(GT)

    assert plan["schema_version"] == 1
    assert gt["schema_version"] == 1

    assert plan["instance_count"] == 15
    assert gt["instance_count"] == 15

    assert set(plan["instances"]) == set(
        gt["instances"]
    )

    families = Counter(
        row["family"]
        for row in plan["instances"].values()
    )

    assert families == {
        "FIREWALL": 5,
        "ROUTE": 5,
        "VLAN": 5,
    }


def test_rq2_sources_are_frozen_rep01():
    plan = load(PLAN)

    assert (
        plan["source_phase2"]["source_repetition"]
        == 1
    )

    assert (
        plan["source_phase2"][
            "raw_snapshot_manifest_sha256"
        ]
        ==
        "881fbe3aa9580de37dd8681eb626b127"
        "daf1d9fb55002b738edc4376060c7cad"
    )

    for row in plan["instances"].values():
        assert row["source_repetition"] == 1
        assert (
            row["source_root"]
            ==
            "artifacts/paper/phase2-parameterized"
        )


def test_rq2_family_source_mapping():
    plan = load(PLAN)

    for iid, row in plan["instances"].items():
        suffix = iid.rsplit("-", 1)[-1]

        if row["family"] == "FIREWALL":
            assert (
                row["source_instance"]
                == f"firewall-deny-{suffix}"
            )

        elif row["family"] == "ROUTE":
            assert (
                row["source_instance"]
                == f"route-missing-{suffix}"
            )

        elif row["family"] == "VLAN":
            assert (
                row["source_instance"]
                == f"vlan-mismatch-{suffix}"
            )

        else:
            raise AssertionError(row["family"])


def test_rq2_ground_truth_categories():
    gt = load(GT)

    expected = {
        "FIREWALL": (
            "FIREWALL_POLICY",
            "fw1",
            "primary",
        ),
        "ROUTE": (
            "ROUTE",
            "r1",
            "host-route",
        ),
        "VLAN": (
            "VLAN",
            "sw1",
            "primary",
        ),
    }

    for row in gt["instances"].values():
        category, device, variant = expected[
            row["family"]
        ]

        assert row["expected_category"] == category
        assert row["expected_device"] == device
        assert (
            row["expected_top1_variant"]
            == variant
        )

        assert (
            row["expected_simulation_status"]
            == "PASSED"
        )
        assert (
            row["expected_simulated_verdict"]
            == "ALLOW"
        )


def test_rq2_candidate_variant_vocabulary():
    gt = load(GT)

    normalization = gt[
        "candidate_variant_normalization"
    ]

    assert (
        normalization[
            "missing_or_empty_candidate_variant"
        ]
        == "primary"
    )

    assert (
        normalization[
            "manual_review_candidate_variant"
        ]
        == "observation-only"
    )

    for row in gt["instances"].values():
        forbidden = set(
            row["forbidden_top1_variants"]
        )

        assert "manual-review" not in forbidden
        assert "observation-only" in forbidden

        if row["family"] == "FIREWALL":
            assert "host-pair-protocol" in forbidden

        if row["family"] == "VLAN":
            assert "access-only" in forbidden
            assert "trunk-only" in forbidden


def test_rq2_evidence_expectations():
    gt = load(GT)

    for row in gt["instances"].values():
        assert "FLOW" in row["required_node_types"]
        assert "ASSESSMENT" in row[
            "required_node_types"
        ]
        assert "ASSESSES" in row[
            "required_relations"
        ]

        if row["family"] == "FIREWALL":
            assert "POLICY_RULE" in row[
                "required_node_types"
            ]
            assert "MATCHED_BY" in row[
                "required_relations"
            ]

        elif row["family"] == "ROUTE":
            assert "gap:route" in row.get(
                "required_node_ids", []
            )
            assert "MISSING" in row[
                "required_relations"
            ]

        elif row["family"] == "VLAN":
            assert "gap:vlan:10" in row.get(
                "required_node_ids", []
            )
            assert "MISSING" in row[
                "required_relations"
            ]


def test_rq2_runner_must_not_consume_ground_truth():
    gt = load(GT)

    assert (
        gt[
            "ground_truth_must_not_be_consumed_by_runner"
        ]
        is True
    )
