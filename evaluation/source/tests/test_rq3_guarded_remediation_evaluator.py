from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]

MODULE = (
    ROOT
    / "scripts"
    / "experiments"
    / "evaluate_rq3_guarded_remediation.py"
)

spec = importlib.util.spec_from_file_location(
    "evaluate_rq3_guarded_remediation",
    MODULE,
)

assert spec is not None
assert spec.loader is not None

evaluator = importlib.util.module_from_spec(
    spec
)

spec.loader.exec_module(evaluator)


def write_json(
    path: Path,
    value,
):
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_text(
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def sha256(path: Path) -> str:
    return hashlib.sha256(
        path.read_bytes()
    ).hexdigest()


def make_fixture(
    tmp_path: Path,
):
    raw = tmp_path / "raw"
    snapshot = tmp_path / "snapshot"
    gt_path = tmp_path / "gt.json"

    raw.mkdir()
    snapshot.mkdir()

    gt_instances = {}

    manifest_files = []

    family_data = (
        (
            "FIREWALL",
            "firewall",
            "FIREWALL_POLICY",
            "fw1",
            "primary",
            True,
        ),
        (
            "ROUTE",
            "route",
            "ROUTE",
            "r1",
            "host-route",
            False,
        ),
        (
            "VLAN",
            "vlan",
            "VLAN",
            "sw1",
            "primary",
            False,
        ),
    )

    counter = 0

    for (
        family,
        prefix,
        category,
        device,
        variant,
        same_path_applicable,
    ) in family_data:
        for repetition in range(1, 6):
            counter += 1

            iid = (
                f"rq3-{prefix}-"
                f"r{repetition:02d}"
            )

            gt_instances[iid] = {
                "family": family,
                "repetition": repetition,

                "expected_category":
                    category,
                "expected_device":
                    device,
                "expected_top1_variant":
                    variant,

                "expected_execution_status":
                    "ROLLED_BACK",

                "expected_what_if": {
                    "simulation_status":
                        "PASSED",
                    "simulated_verdict":
                        "ALLOW",
                },

                "expected_fault_state": {
                    "target_reachable":
                        False,
                    "independent_control_reachable":
                        True,
                    "security_invariant_reachable":
                        False,
                },

                "expected_post_change_state": {
                    "target_reachable":
                        True,
                    "independent_control_reachable":
                        True,
                    "security_invariant_reachable":
                        False,
                },

                "expected_post_rollback_state": {
                    "target_reachable":
                        False,
                    "independent_control_reachable":
                        True,
                    "security_invariant_reachable":
                        False,
                },

                "expected_final_baseline_state": {
                    "target_reachable":
                        True,
                    "independent_control_reachable":
                        True,
                    "security_invariant_reachable":
                        False,
                },

                "same_path_control_applicable":
                    same_path_applicable,

                "expected_same_path_control":
                    (
                        {
                            "fault_state_reachable":
                                True,
                            "post_change_reachable":
                                True,
                            "post_rollback_reachable":
                                True,
                            "final_baseline_reachable":
                                True,
                        }
                        if same_path_applicable
                        else None
                    ),
            }

            same = (
                True
                if same_path_applicable
                else None
            )

            states = {
                "baseline": {
                    "target_reachable": True,
                    "independent_control_reachable":
                        True,
                    "security_invariant_reachable":
                        False,
                    "security_service_listening":
                        True,
                    "same_path_control_reachable":
                        same,
                },

                "fault": {
                    "target_reachable": False,
                    "independent_control_reachable":
                        True,
                    "security_invariant_reachable":
                        False,
                    "security_service_listening":
                        True,
                    "same_path_control_reachable":
                        same,
                },

                "post_change": {
                    "target_reachable": True,
                    "independent_control_reachable":
                        True,
                    "security_invariant_reachable":
                        False,
                    "security_service_listening":
                        True,
                    "same_path_control_reachable":
                        same,
                },

                "post_rollback": {
                    "target_reachable": False,
                    "independent_control_reachable":
                        True,
                    "security_invariant_reachable":
                        False,
                    "security_service_listening":
                        True,
                    "same_path_control_reachable":
                        same,
                },

                "final_baseline": {
                    "target_reachable": True,
                    "independent_control_reachable":
                        True,
                    "security_invariant_reachable":
                        False,
                    "security_service_listening":
                        True,
                    "same_path_control_reachable":
                        same,
                },
            }

            recommendation_id = (
                f"recommendation-{counter}"
            )

            result = {
                "schema_version": 1,
                "instance_id": iid,
                "family": family,
                "repetition": repetition,

                "ground_truth_consumed_by_runner":
                    False,

                "top1": {
                    "recommendation_id":
                        recommendation_id,
                    "rank": 1,
                    "approval_issues": [],
                    "approved": True,
                    "category": category,
                    "device_id": device,
                    "variant": variant,
                    "simulation_status":
                        "PASSED",
                    "simulated_verdict":
                        "ALLOW",
                },

                "execution": {
                    "execution_id":
                        f"execution-{counter}",
                    "status":
                        "ROLLED_BACK",
                    "apply_success":
                        True,
                    "rollback_success":
                        True,
                    "error": "",
                },

                "observed_states":
                    states,

                "what_if_actual_agreement":
                    True,

                "timing": {
                    "apply_duration_ms":
                        10.0 + counter,
                    "post_change_verification_duration_ms":
                        100.0 + counter,
                    "rollback_duration_ms":
                        20.0 + counter,
                    "post_rollback_verification_duration_ms":
                        200.0 + counter,
                    "total_guarded_remediation_duration_ms":
                        400.0 + counter,
                },
            }

            approval = {
                "recommendation_id":
                    recommendation_id,
                "status":
                    "APPROVED",
                "simulation_status":
                    "PASSED",
                "simulated_verdict":
                    "ALLOW",
                "event": {
                    "status":
                        "APPROVED",
                    "reviewed_by":
                        "rq3-operator",
                },
            }

            execution = {
                "recommendation_id":
                    recommendation_id,
                "status":
                    "ROLLED_BACK",

                "apply_results": [
                    {
                        "returncode": 0,
                    }
                ],

                "rollback_results": [
                    {
                        "returncode": 0,
                    }
                ],

                "verification": {
                    "passed": True,
                    "observed_success":
                        True,
                },

                "rollback_verification": {
                    "passed": True,
                    "observed_success":
                        False,
                },
            }

            instance_dir = raw / iid

            for name, payload in (
                ("result.json", result),
                ("approval.json", approval),
                (
                    "remediation-execution.json",
                    execution,
                ),
            ):
                path = instance_dir / name
                write_json(path, payload)
                manifest_files.append(path)

    gt_doc = {
        "schema_version": 1,
        "execution_count": 15,
        "fault_family_count": 3,
        "repetitions_per_family": 5,
        "ground_truth_must_not_be_consumed_by_runner":
            True,
        "instances":
            gt_instances,
    }

    write_json(
        gt_path,
        gt_doc,
    )

    manifest = (
        snapshot / "SHA256SUMS.txt"
    )

    manifest.write_text(
        "".join(
            f"{sha256(path)}  {path}\n"
            for path in sorted(
                manifest_files
            )
        ),
        encoding="utf-8",
    )

    return (
        raw,
        gt_path,
        snapshot,
        sha256(manifest),
        sha256(gt_path),
    )


def run_eval(
    tmp_path: Path,
):
    (
        raw,
        gt,
        snapshot,
        manifest_hash,
        gt_hash,
    ) = make_fixture(tmp_path)

    out = tmp_path / "out"

    result = evaluator.evaluate(
        raw_root=raw,
        gt_path=gt,
        snapshot_dir=snapshot,
        output_dir=out,
        expected_raw_manifest_sha256=
            manifest_hash,
        expected_ground_truth_sha256=
            gt_hash,
        repo_root=tmp_path,
    )

    return (
        result,
        out,
        raw,
        gt,
        snapshot,
        manifest_hash,
        gt_hash,
    )


def test_all_success_metrics(
    tmp_path: Path,
):
    result, out, *_ = run_eval(
        tmp_path
    )

    summary = result["summary"]

    assert (
        summary["instance_count"]
        == 15
    )

    for key in evaluator.PRIMARY_METRICS:
        metric = (
            summary[
                "primary_metrics"
            ][key]
        )

        assert metric["count"] == 15
        assert metric["total"] == 15
        assert metric["rate"] == 1.0

    same = (
        summary[
            "secondary_metrics"
        ][
            "firewall_same_path_control_preservation_rate"
        ]
    )

    assert same == {
        "count": 5,
        "total": 5,
        "rate": 1.0,
    }

    assert (
        out / "summary.json"
    ).is_file()

    assert (
        out / "timing-summary.json"
    ).is_file()


def test_family_metrics_are_5_of_5(
    tmp_path: Path,
):
    result, *_ = run_eval(
        tmp_path
    )

    families = (
        result[
            "family_summary"
        ]["families"]
    )

    assert set(families) == {
        "FIREWALL",
        "ROUTE",
        "VLAN",
    }

    for family in families.values():
        assert (
            family[
                "instance_count"
            ]
            == 5
        )

        for key in (
            evaluator.PRIMARY_METRICS
        ):
            assert (
                family[
                    "primary_metrics"
                ][key]["count"]
                == 5
            )


def test_timing_summary(
    tmp_path: Path,
):
    result, *_ = run_eval(
        tmp_path
    )

    timing = result[
        "timing_summary"
    ]

    overall = timing[
        "overall"
    ][
        "total_guarded_remediation_duration_ms"
    ]

    assert overall["n"] == 15

    # Values are 401..415.
    assert overall["median_ms"] == 408.0
    assert overall["q1_ms"] == 404.5
    assert overall["q3_ms"] == 411.5
    assert overall["iqr_ms"] == 7.0

    assert (
        overall["p95_ms"]
        == pytest.approx(414.3)
    )


def test_rejects_manifest_hash_mismatch(
    tmp_path: Path,
):
    (
        raw,
        gt,
        snapshot,
        _,
        gt_hash,
    ) = make_fixture(tmp_path)

    with pytest.raises(
        ValueError,
        match=(
            "raw snapshot manifest "
            "SHA256 mismatch"
        ),
    ):
        evaluator.evaluate(
            raw_root=raw,
            gt_path=gt,
            snapshot_dir=snapshot,
            output_dir=tmp_path / "out",
            expected_raw_manifest_sha256=
                "0" * 64,
            expected_ground_truth_sha256=
                gt_hash,
            repo_root=tmp_path,
        )


def test_rejects_missing_snapshot_file(
    tmp_path: Path,
):
    (
        raw,
        gt,
        snapshot,
        manifest_hash,
        gt_hash,
    ) = make_fixture(tmp_path)

    target = (
        raw
        / "rq3-vlan-r05"
        / "result.json"
    )

    target.unlink()

    with pytest.raises(
        FileNotFoundError,
        match="snapshot file missing",
    ):
        evaluator.evaluate(
            raw_root=raw,
            gt_path=gt,
            snapshot_dir=snapshot,
            output_dir=tmp_path / "out",
            expected_raw_manifest_sha256=
                manifest_hash,
            expected_ground_truth_sha256=
                gt_hash,
            repo_root=tmp_path,
        )


def test_rejects_raw_ground_truth_id_mismatch(
    tmp_path: Path,
):
    (
        raw,
        gt,
        snapshot,
        manifest_hash,
        _,
    ) = make_fixture(tmp_path)

    doc = json.loads(
        gt.read_text(
            encoding="utf-8"
        )
    )

    original = doc[
        "instances"
    ].pop(
        "rq3-vlan-r05"
    )

    doc["instances"][
        "rq3-vlan-r99"
    ] = original

    write_json(
        gt,
        doc,
    )

    gt_hash = sha256(gt)

    with pytest.raises(
        ValueError,
        match=(
            "raw/ground-truth "
            "instance IDs differ"
        ),
    ):
        evaluator.evaluate(
            raw_root=raw,
            gt_path=gt,
            snapshot_dir=snapshot,
            output_dir=tmp_path / "out",
            expected_raw_manifest_sha256=
                manifest_hash,
            expected_ground_truth_sha256=
                gt_hash,
            repo_root=tmp_path,
        )


def test_security_service_must_be_listening(
    tmp_path: Path,
):
    (
        raw,
        gt,
        snapshot,
        _,
        gt_hash,
    ) = make_fixture(tmp_path)

    target = (
        raw
        / "rq3-route-r01"
        / "result.json"
    )

    doc = json.loads(
        target.read_text(
            encoding="utf-8"
        )
    )

    doc[
        "observed_states"
    ][
        "post_change"
    ][
        "security_service_listening"
    ] = False

    write_json(
        target,
        doc,
    )

    # Rebuild the synthetic snapshot after
    # deliberately changing raw evidence.
    manifest = (
        snapshot
        / "SHA256SUMS.txt"
    )

    paths = sorted(
        raw.rglob("*.json")
    )

    manifest.write_text(
        "".join(
            f"{sha256(path)}  {path}\n"
            for path in paths
        ),
        encoding="utf-8",
    )

    manifest_hash = sha256(
        manifest
    )

    result = evaluator.evaluate(
        raw_root=raw,
        gt_path=gt,
        snapshot_dir=snapshot,
        output_dir=tmp_path / "out",
        expected_raw_manifest_sha256=
            manifest_hash,
        expected_ground_truth_sha256=
            gt_hash,
        repo_root=tmp_path,
    )

    metric = (
        result[
            "summary"
        ][
            "primary_metrics"
        ][
            "security_invariant_preservation_rate"
        ]
    )

    assert metric["count"] == 14
    assert metric["total"] == 15


def test_detects_same_path_control_failure(
    tmp_path: Path,
):
    (
        raw,
        gt,
        snapshot,
        _,
        gt_hash,
    ) = make_fixture(tmp_path)

    target = (
        raw
        / "rq3-firewall-r03"
        / "result.json"
    )

    doc = json.loads(
        target.read_text(
            encoding="utf-8"
        )
    )

    doc[
        "observed_states"
    ][
        "post_change"
    ][
        "same_path_control_reachable"
    ] = False

    write_json(
        target,
        doc,
    )

    manifest = (
        snapshot
        / "SHA256SUMS.txt"
    )

    paths = sorted(
        raw.rglob("*.json")
    )

    manifest.write_text(
        "".join(
            f"{sha256(path)}  {path}\n"
            for path in paths
        ),
        encoding="utf-8",
    )

    result = evaluator.evaluate(
        raw_root=raw,
        gt_path=gt,
        snapshot_dir=snapshot,
        output_dir=tmp_path / "out",
        expected_raw_manifest_sha256=
            sha256(manifest),
        expected_ground_truth_sha256=
            gt_hash,
        repo_root=tmp_path,
    )

    metric = (
        result[
            "summary"
        ][
            "secondary_metrics"
        ][
            "firewall_same_path_control_preservation_rate"
        ]
    )

    assert metric["count"] == 4
    assert metric["total"] == 5
