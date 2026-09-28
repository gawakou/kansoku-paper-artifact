#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import subprocess
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable


FROZEN_RAW_MANIFEST_SHA256 = (
    "5a50c830268f1a7bcd7321f4ce01369839c376df"
    "975cb627f8732369a721d2cf"
)

FROZEN_GT_SHA256 = (
    "4d64def0906cb64d67488e8130e7070f15457585"
    "fd8c1afc100eca4a73b5ddc2"
)

DEFAULT_RAW_ROOT = Path(
    "artifacts/paper/"
    "rq3-guarded-remediation-v1"
)

DEFAULT_GT = Path(
    "scenarios/paper/"
    "rq3_guarded_remediation_ground_truth.json"
)

DEFAULT_SNAPSHOT = Path(
    "artifacts/paper/"
    "rq3-snapshots/raw-v1"
)

DEFAULT_OUTPUT = Path(
    "artifacts/paper/"
    "rq3-evaluation-v1"
)

FAMILIES = (
    "FIREWALL",
    "ROUTE",
    "VLAN",
)

PRIMARY_METRICS = (
    "eligible_top1_rate",
    "apply_success_rate",
    "target_recovery_rate",
    "independent_control_preservation_rate",
    "security_invariant_preservation_rate",
    "rollback_success_rate",
    "fault_restoration_rate",
    "what_if_actual_agreement_rate",
    "final_baseline_restoration_rate",
)

TIMING_FIELDS = (
    "apply_duration_ms",
    "post_change_verification_duration_ms",
    "rollback_duration_ms",
    "post_rollback_verification_duration_ms",
    "total_guarded_remediation_duration_ms",
)

STATE_GT = (
    ("fault", "expected_fault_state"),
    ("post_change", "expected_post_change_state"),
    ("post_rollback", "expected_post_rollback_state"),
    ("final_baseline", "expected_final_baseline_state"),
)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()

    with path.open("rb") as f:
        for chunk in iter(
            lambda: f.read(1024 * 1024),
            b"",
        ):
            h.update(chunk)

    return h.hexdigest()


def load_json(path: Path) -> Any:
    return json.loads(
        path.read_text(encoding="utf-8")
    )


def write_json(
    path: Path,
    payload: Any,
) -> None:
    path.write_text(
        json.dumps(
            payload,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )


def resolve_manifest_path(
    filename: str,
    *,
    repo_root: Path,
) -> Path:
    path = Path(filename)

    if path.is_absolute():
        return path

    return repo_root / path


def verify_manifest(
    *,
    raw_root: Path,
    snapshot_dir: Path,
    repo_root: Path,
    expected_manifest_sha256: str,
) -> None:
    manifest = (
        snapshot_dir
        / "SHA256SUMS.txt"
    )

    if not manifest.is_file():
        raise FileNotFoundError(
            f"snapshot manifest missing: {manifest}"
        )

    actual_manifest_sha256 = (
        sha256_file(manifest)
    )

    if (
        actual_manifest_sha256
        != expected_manifest_sha256
    ):
        raise ValueError(
            "raw snapshot manifest SHA256 mismatch: "
            f"expected={expected_manifest_sha256} "
            f"actual={actual_manifest_sha256}"
        )

    raw_resolved = raw_root.resolve()

    lines = manifest.read_text(
        encoding="utf-8"
    ).splitlines()

    if not lines:
        raise ValueError(
            "raw snapshot manifest is empty"
        )

    for line in lines:
        line = line.strip()

        if not line:
            continue

        try:
            expected, filename = (
                line.split(maxsplit=1)
            )
        except ValueError as exc:
            raise ValueError(
                "invalid SHA256 manifest line: "
                f"{line!r}"
            ) from exc

        filename = filename.lstrip("*")

        path = resolve_manifest_path(
            filename,
            repo_root=repo_root,
        )

        if not path.is_file():
            raise FileNotFoundError(
                f"snapshot file missing: {path}"
            )

        resolved = path.resolve()

        if not resolved.is_relative_to(
            raw_resolved
        ):
            raise ValueError(
                "snapshot manifest contains file "
                "outside raw root: "
                f"{path}"
            )

        actual = sha256_file(path)

        if actual != expected:
            raise ValueError(
                "snapshot file SHA256 mismatch: "
                f"{path}"
            )


def verify_ground_truth(
    *,
    gt_path: Path,
    expected_sha256: str,
) -> dict[str, Any]:
    if not gt_path.is_file():
        raise FileNotFoundError(
            f"ground truth missing: {gt_path}"
        )

    actual = sha256_file(gt_path)

    if actual != expected_sha256:
        raise ValueError(
            "ground-truth SHA256 mismatch: "
            f"expected={expected_sha256} "
            f"actual={actual}"
        )

    gt = load_json(gt_path)

    if gt.get("schema_version") != 1:
        raise ValueError(
            "unsupported RQ3 ground-truth schema"
        )

    if gt.get("execution_count") != 15:
        raise ValueError(
            "RQ3 ground truth must contain "
            "15 executions"
        )

    instances = gt.get("instances")

    if not isinstance(
        instances,
        dict,
    ):
        raise ValueError(
            "RQ3 ground truth instances "
            "must be an object"
        )

    if len(instances) != 15:
        raise ValueError(
            "RQ3 ground truth instance count "
            "must equal 15"
        )

    return gt


def rate(
    count: int,
    total: int,
) -> dict[str, Any]:
    return {
        "count": count,
        "total": total,
        "rate": (
            count / total
            if total
            else None
        ),
    }


def percentile_linear(
    values: Iterable[float],
    probability: float,
) -> float:
    rows = sorted(
        float(x)
        for x in values
    )

    if not rows:
        raise ValueError(
            "cannot calculate percentile "
            "of empty data"
        )

    if not (
        0.0 <= probability <= 1.0
    ):
        raise ValueError(
            "probability must be in [0, 1]"
        )

    if len(rows) == 1:
        return rows[0]

    pos = (
        (len(rows) - 1)
        * probability
    )

    lower = math.floor(pos)
    upper = math.ceil(pos)

    if lower == upper:
        return rows[lower]

    weight = pos - lower

    return (
        rows[lower]
        + (
            rows[upper]
            - rows[lower]
        )
        * weight
    )


def timing_statistics(
    values: Iterable[float],
) -> dict[str, Any]:
    rows = [
        float(x)
        for x in values
    ]

    if not rows:
        return {
            "n": 0,
            "median_ms": None,
            "q1_ms": None,
            "q3_ms": None,
            "iqr_ms": None,
            "p95_ms": None,
        }

    for value in rows:
        if (
            not math.isfinite(value)
            or value < 0.0
        ):
            raise ValueError(
                "invalid timing value"
            )

    q1 = percentile_linear(
        rows,
        0.25,
    )

    median = percentile_linear(
        rows,
        0.50,
    )

    q3 = percentile_linear(
        rows,
        0.75,
    )

    p95 = percentile_linear(
        rows,
        0.95,
    )

    return {
        "n": len(rows),
        "median_ms": median,
        "q1_ms": q1,
        "q3_ms": q3,
        "iqr_ms": q3 - q1,
        "p95_ms": p95,
    }


def expected_state_matches(
    observed: dict[str, Any],
    expected: dict[str, Any],
) -> bool:
    for key, expected_value in (
        expected.items()
    ):
        if (
            observed.get(key)
            != expected_value
        ):
            return False

    return True


def control_preserved(
    result: dict[str, Any],
    gt: dict[str, Any],
) -> bool:
    observed_states = result[
        "observed_states"
    ]

    for stage, gt_key in STATE_GT:
        observed = (
            observed_states[stage]
        )

        expected = gt[gt_key]

        if (
            observed.get(
                "independent_control_reachable"
            )
            != expected[
                "independent_control_reachable"
            ]
        ):
            return False

    return True


def security_preserved(
    result: dict[str, Any],
    gt: dict[str, Any],
) -> bool:
    observed_states = result[
        "observed_states"
    ]

    for stage, gt_key in STATE_GT:
        observed = (
            observed_states[stage]
        )

        expected = gt[gt_key]

        if (
            observed.get(
                "security_invariant_reachable"
            )
            != expected[
                "security_invariant_reachable"
            ]
        ):
            return False

        # Critical anti-false-positive check:
        # the protected service must actually
        # be listening while client reachability
        # remains denied.
        if (
            observed.get(
                "security_service_listening"
            )
            is not True
        ):
            return False

    return True


def same_path_preserved(
    result: dict[str, Any],
    gt: dict[str, Any],
) -> bool | None:
    if not gt[
        "same_path_control_applicable"
    ]:
        return None

    expected = gt[
        "expected_same_path_control"
    ]

    if not isinstance(
        expected,
        dict,
    ):
        raise ValueError(
            "same-path control expected "
            "for applicable instance"
        )

    observed = result[
        "observed_states"
    ]

    mapping = (
        (
            "fault",
            "fault_state_reachable",
        ),
        (
            "post_change",
            "post_change_reachable",
        ),
        (
            "post_rollback",
            "post_rollback_reachable",
        ),
        (
            "final_baseline",
            "final_baseline_reachable",
        ),
    )

    for stage, expected_key in mapping:
        if (
            observed[stage].get(
                "same_path_control_reachable"
            )
            != expected[expected_key]
        ):
            return False

    return True


def evaluate_instance(
    *,
    instance_id: str,
    raw_dir: Path,
    gt: dict[str, Any],
) -> dict[str, Any]:
    required = (
        "result.json",
        "approval.json",
        "remediation-execution.json",
    )

    for filename in required:
        path = raw_dir / filename

        if not path.is_file():
            raise FileNotFoundError(
                f"required raw artifact missing: "
                f"{path}"
            )

    result = load_json(
        raw_dir / "result.json"
    )

    approval = load_json(
        raw_dir / "approval.json"
    )

    execution = load_json(
        raw_dir
        / "remediation-execution.json"
    )

    if (
        result.get("instance_id")
        != instance_id
    ):
        raise ValueError(
            "result instance ID mismatch: "
            f"{instance_id}"
        )

    if (
        result.get("family")
        != gt["family"]
    ):
        raise ValueError(
            "result/ground-truth family mismatch: "
            f"{instance_id}"
        )

    if (
        result.get("repetition")
        != gt["repetition"]
    ):
        raise ValueError(
            "result/ground-truth repetition mismatch: "
            f"{instance_id}"
        )

    if (
        result.get(
            "ground_truth_consumed_by_runner"
        )
        is not False
    ):
        raise ValueError(
            "runner provenance does not "
            "confirm GT isolation: "
            f"{instance_id}"
        )

    top1 = result["top1"]
    observed = result[
        "observed_states"
    ]

    expected_what_if = gt[
        "expected_what_if"
    ]

    recommendation_id = top1[
        "recommendation_id"
    ]

    approval_event = approval.get(
        "event",
        {},
    )

    eligible_top1 = all(
        (
            top1.get("rank") == 1,
            top1.get("approval_issues") == [],
            top1.get("approved") is True,
            top1.get("simulation_status")
            == expected_what_if[
                "simulation_status"
            ],
            top1.get("simulated_verdict")
            == expected_what_if[
                "simulated_verdict"
            ],
            approval.get(
                "recommendation_id"
            )
            == recommendation_id,
            approval.get("status")
            == "APPROVED",
            approval_event.get("status")
            == "APPROVED",
            bool(
                str(
                    approval_event.get(
                        "reviewed_by",
                        "",
                    )
                ).strip()
            ),
        )
    )

    apply_results = execution.get(
        "apply_results",
        [],
    )

    apply_success = (
        result["execution"].get(
            "apply_success"
        )
        is True
        and bool(apply_results)
        and all(
            item.get("returncode") == 0
            for item in apply_results
        )
    )

    expected_post_change = gt[
        "expected_post_change_state"
    ]

    post_change = observed[
        "post_change"
    ]

    verification = execution.get(
        "verification",
        {},
    )

    target_recovery = all(
        (
            post_change.get(
                "target_reachable"
            )
            == expected_post_change[
                "target_reachable"
            ],
            verification.get("passed")
            is True,
            verification.get(
                "observed_success"
            )
            == expected_post_change[
                "target_reachable"
            ],
        )
    )

    rollback_results = execution.get(
        "rollback_results",
        [],
    )

    rollback_success = (
        result["execution"].get(
            "rollback_success"
        )
        is True
        and bool(rollback_results)
        and all(
            item.get("returncode") == 0
            for item in rollback_results
        )
        and result["execution"].get(
            "status"
        )
        == gt[
            "expected_execution_status"
        ]
        and execution.get("status")
        == gt[
            "expected_execution_status"
        ]
    )

    expected_post_rollback = gt[
        "expected_post_rollback_state"
    ]

    post_rollback = observed[
        "post_rollback"
    ]

    rollback_verification = (
        execution.get(
            "rollback_verification",
            {},
        )
    )

    fault_restoration = all(
        (
            post_rollback.get(
                "target_reachable"
            )
            == expected_post_rollback[
                "target_reachable"
            ],
            rollback_verification.get(
                "passed"
            )
            is True,
            rollback_verification.get(
                "observed_success"
            )
            == expected_post_rollback[
                "target_reachable"
            ],
        )
    )

    independent_control = (
        control_preserved(
            result,
            gt,
        )
    )

    security_invariant = (
        security_preserved(
            result,
            gt,
        )
    )

    same_path = same_path_preserved(
        result,
        gt,
    )

    what_if_actual = all(
        (
            top1.get(
                "simulation_status"
            )
            == expected_what_if[
                "simulation_status"
            ],
            top1.get(
                "simulated_verdict"
            )
            == expected_what_if[
                "simulated_verdict"
            ],
            result.get(
                "what_if_actual_agreement"
            )
            is True,
            post_change.get(
                "target_reachable"
            )
            == expected_post_change[
                "target_reachable"
            ],
        )
    )

    expected_final = gt[
        "expected_final_baseline_state"
    ]

    final_state = observed[
        "final_baseline"
    ]

    final_baseline = (
        expected_state_matches(
            final_state,
            expected_final,
        )
        and final_state.get(
            "security_service_listening"
        )
        is True
    )

    top1_identity = all(
        (
            top1.get("category")
            == gt["expected_category"],
            top1.get("device_id")
            == gt["expected_device"],
            top1.get("variant")
            == gt[
                "expected_top1_variant"
            ],
        )
    )

    execution_status_match = (
        result["execution"].get(
            "status"
        )
        == gt[
            "expected_execution_status"
        ]
        and execution.get("status")
        == gt[
            "expected_execution_status"
        ]
    )

    timing = result.get(
        "timing",
        {},
    )

    timing_row: dict[str, float] = {}

    for key in TIMING_FIELDS:
        if key not in timing:
            raise ValueError(
                f"missing timing field "
                f"{key}: {instance_id}"
            )

        value = float(timing[key])

        if (
            not math.isfinite(value)
            or value < 0.0
        ):
            raise ValueError(
                f"invalid timing value "
                f"{key}: {instance_id}"
            )

        timing_row[key] = value

    return {
        "instance_id":
            instance_id,
        "family":
            gt["family"],
        "repetition":
            gt["repetition"],

        "eligible_top1_rate":
            eligible_top1,
        "apply_success_rate":
            apply_success,
        "target_recovery_rate":
            target_recovery,
        "independent_control_preservation_rate":
            independent_control,
        "security_invariant_preservation_rate":
            security_invariant,
        "rollback_success_rate":
            rollback_success,
        "fault_restoration_rate":
            fault_restoration,
        "what_if_actual_agreement_rate":
            what_if_actual,
        "final_baseline_restoration_rate":
            final_baseline,

        "firewall_same_path_control_preservation":
            same_path,

        "top1_identity_match":
            top1_identity,
        "execution_status_match":
            execution_status_match,

        "top1_category":
            top1.get("category"),
        "top1_device":
            top1.get("device_id"),
        "top1_variant":
            top1.get("variant"),

        **timing_row,
    }


def aggregate_metrics(
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    metrics: dict[str, Any] = {}

    for key in PRIMARY_METRICS:
        metrics[key] = rate(
            sum(
                bool(row[key])
                for row in records
            ),
            len(records),
        )

    firewall_rows = [
        row
        for row in records
        if (
            row[
                "firewall_same_path_control_preservation"
            ]
            is not None
        )
    ]

    secondary = {
        "firewall_same_path_control_preservation_rate":
            rate(
                sum(
                    bool(
                        row[
                            "firewall_same_path_control_preservation"
                        ]
                    )
                    for row in firewall_rows
                ),
                len(firewall_rows),
            )
    }

    audit = {
        "top1_identity_match_rate":
            rate(
                sum(
                    bool(
                        row[
                            "top1_identity_match"
                        ]
                    )
                    for row in records
                ),
                len(records),
            ),

        "execution_status_match_rate":
            rate(
                sum(
                    bool(
                        row[
                            "execution_status_match"
                        ]
                    )
                    for row in records
                ),
                len(records),
            ),
    }

    return {
        "primary_metrics":
            metrics,
        "secondary_metrics":
            secondary,
        "audit_metrics":
            audit,
    }


def timing_summary(
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "overall": {},
        "families": {},
        "percentile_method":
            (
                "linear interpolation over "
                "rank position (n-1)*p"
            ),
    }

    for key in TIMING_FIELDS:
        result["overall"][key] = (
            timing_statistics(
                row[key]
                for row in records
            )
        )

    for family in FAMILIES:
        rows = [
            row
            for row in records
            if row["family"] == family
        ]

        result["families"][
            family
        ] = {}

        for key in TIMING_FIELDS:
            result["families"][
                family
            ][key] = (
                timing_statistics(
                    row[key]
                    for row in rows
                )
            )

    return result


def write_records_csv(
    path: Path,
    records: list[dict[str, Any]],
) -> None:
    fields = (
        "instance_id",
        "family",
        "repetition",
        *PRIMARY_METRICS,
        "firewall_same_path_control_preservation",
        "top1_identity_match",
        "execution_status_match",
        "top1_category",
        "top1_device",
        "top1_variant",
        *TIMING_FIELDS,
    )

    with path.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as f:
        writer = csv.DictWriter(
            f,
            fieldnames=fields,
        )

        writer.writeheader()

        for row in records:
            writer.writerow(
                {
                    key: row.get(key)
                    for key in fields
                }
            )


def evaluate(
    *,
    raw_root: Path,
    gt_path: Path,
    snapshot_dir: Path,
    output_dir: Path,
    expected_raw_manifest_sha256: str,
    expected_ground_truth_sha256: str,
    repo_root: Path,
) -> dict[str, Any]:
    if output_dir.exists():
        raise FileExistsError(
            "evaluation output already exists: "
            f"{output_dir}"
        )

    verify_manifest(
        raw_root=raw_root,
        snapshot_dir=snapshot_dir,
        repo_root=repo_root,
        expected_manifest_sha256=(
            expected_raw_manifest_sha256
        ),
    )

    gt = verify_ground_truth(
        gt_path=gt_path,
        expected_sha256=(
            expected_ground_truth_sha256
        ),
    )

    gt_instances = gt["instances"]

    raw_ids = {
        path.name
        for path in raw_root.iterdir()
        if path.is_dir()
    }

    gt_ids = set(
        gt_instances
    )

    if raw_ids != gt_ids:
        raise ValueError(
            "raw/ground-truth instance IDs differ"
        )

    family_counts = Counter(
        row["family"]
        for row in gt_instances.values()
    )

    if family_counts != Counter(
        {
            "FIREWALL": 5,
            "ROUTE": 5,
            "VLAN": 5,
        }
    ):
        raise ValueError(
            "unexpected RQ3 family composition"
        )

    records: list[
        dict[str, Any]
    ] = []

    for instance_id in sorted(
        gt_ids
    ):
        records.append(
            evaluate_instance(
                instance_id=instance_id,
                raw_dir=(
                    raw_root
                    / instance_id
                ),
                gt=gt_instances[
                    instance_id
                ],
            )
        )

    overall = aggregate_metrics(
        records
    )

    families: dict[
        str,
        Any,
    ] = {}

    for family in FAMILIES:
        rows = [
            row
            for row in records
            if row["family"] == family
        ]

        families[family] = {
            "instance_count":
                len(rows),
            **aggregate_metrics(rows),
        }

    timings = timing_summary(
        records
    )

    summary = {
        "schema_version": 1,
        "phase":
            "RQ3 guarded remediation evaluation",
        "instance_count":
            len(records),
        "fault_family_count": 3,
        "independent_fault_families": 3,
        "repetitions_per_family": 5,
        "repetitions_are_not_independent_fault_samples":
            True,
        **overall,
        "interpretation":
            (
                "The 15 executions are five "
                "reliability/timing repetitions "
                "for each of three preregistered "
                "fault families and are not "
                "15 independent fault classes."
            ),
    }

    family_summary = {
        "schema_version": 1,
        "families": families,
    }

    output_dir.mkdir(
        parents=True,
        exist_ok=False,
    )

    write_json(
        output_dir / "records.json",
        {
            "schema_version": 1,
            "records": records,
        },
    )

    write_records_csv(
        output_dir / "records.csv",
        records,
    )

    write_json(
        output_dir / "summary.json",
        summary,
    )

    write_json(
        output_dir
        / "family-summary.json",
        family_summary,
    )

    write_json(
        output_dir
        / "timing-summary.json",
        timings,
    )

    return {
        "summary": summary,
        "family_summary":
            family_summary,
        "timing_summary":
            timings,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Evaluate frozen KANSOKU RQ3 "
            "guarded-remediation results."
        )
    )

    parser.add_argument(
        "--raw-root",
        default=str(DEFAULT_RAW_ROOT),
    )

    parser.add_argument(
        "--ground-truth",
        default=str(DEFAULT_GT),
    )

    parser.add_argument(
        "--snapshot-dir",
        default=str(DEFAULT_SNAPSHOT),
    )

    parser.add_argument(
        "--output-dir",
        default=str(DEFAULT_OUTPUT),
    )

    parser.add_argument(
        "--expected-raw-manifest-sha256",
        default=FROZEN_RAW_MANIFEST_SHA256,
    )

    parser.add_argument(
        "--expected-ground-truth-sha256",
        default=FROZEN_GT_SHA256,
    )

    return parser


def main() -> int:
    args = build_parser().parse_args()

    repo_root = Path(
        subprocess.check_output(
            [
                "git",
                "rev-parse",
                "--show-toplevel",
            ],
            text=True,
        ).strip()
    )

    result = evaluate(
        raw_root=(
            repo_root
            / args.raw_root
        ).resolve(),
        gt_path=(
            repo_root
            / args.ground_truth
        ).resolve(),
        snapshot_dir=(
            repo_root
            / args.snapshot_dir
        ).resolve(),
        output_dir=(
            repo_root
            / args.output_dir
        ).resolve(),
        expected_raw_manifest_sha256=(
            args.expected_raw_manifest_sha256
        ),
        expected_ground_truth_sha256=(
            args.expected_ground_truth_sha256
        ),
        repo_root=repo_root,
    )

    print(
        json.dumps(
            result["summary"],
            indent=2,
            sort_keys=True,
        )
    )

    print(
        "PASS: evaluated frozen "
        "RQ3 guarded-remediation dataset"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
