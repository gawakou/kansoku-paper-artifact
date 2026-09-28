#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from dataclasses import asdict
from pathlib import Path
from typing import Any

from kansoku.paper_evaluation import (
    ElementRefExpectation,
    ScenarioGroundTruth,
    evaluate_diagnostics_payload,
    summarize_records,
)


METHODS = ("CONFIG_ONLY", "FLOW_ONLY", "PROPOSED")


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        ) + "\n",
        encoding="utf-8",
    )


def load_phase2_ground_truth(
    path: Path,
) -> tuple[
    dict[str, ScenarioGroundTruth],
    dict[str, dict[str, Any]],
]:
    payload = load_json(path)

    if not isinstance(payload, dict):
        raise ValueError("ground truth must be a JSON object")

    if int(payload.get("schema_version", 0)) != 1:
        raise ValueError("unsupported ground-truth schema_version")

    instances = payload.get("instances")

    if not isinstance(instances, dict) or not instances:
        raise ValueError(
            "Phase-2 ground truth must contain "
            "a non-empty instances object"
        )

    ground_truth: dict[str, ScenarioGroundTruth] = {}
    metadata: dict[str, dict[str, Any]] = {}

    for iid, row in sorted(instances.items()):
        if not isinstance(row, dict):
            raise ValueError(
                f"ground-truth instance is not an object: {iid}"
            )

        gt = ScenarioGroundTruth(
            scenario_id=iid,
            expected_verdict=str(row["expected_verdict"]),
            expected_fault_domain=str(
                row["expected_fault_domain"]
            ),
            expected_affected_device=str(
                row.get("expected_affected_device", "")
            ),
            expected_element_type=str(
                row["expected_element_type"]
            ),
            expected_element_ref=(
                ElementRefExpectation.from_dict(
                    row.get("expected_element_ref")
                )
            ),
            notes="",
        )
        gt.validate()

        ground_truth[iid] = gt
        metadata[iid] = {
            "prototype_id": str(row["prototype_id"]),
            "family": str(row["family"]),
            "boundary": bool(row["boundary"]),
        }

    return ground_truth, metadata


def diagnostic_signature(
    result: dict[str, Any],
    *,
    include_element_ref: bool,
) -> tuple[Any, ...]:
    sig: tuple[Any, ...] = (
        str(result.get("verdict", "")),
        str(result.get("fault_domain", "")),
        str(result.get("affected_device", "")),
        str(result.get("affected_element_type", "")),
        bool(result.get("abstained", False)),
    )

    if include_element_ref:
        sig += (
            str(result.get("affected_element_ref", "")),
        )

    return sig


def subset_summary(
    records,
    ground_truth,
    instance_ids,
):
    ids = set(instance_ids)

    sub_gt = {
        iid: ground_truth[iid]
        for iid in sorted(ids)
    }

    sub_records = [
        r for r in records
        if r.scenario_id in ids
    ]

    return summarize_records(
        sub_records,
        sub_gt,
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Evaluate frozen Phase-2 parameterized KANSOKU "
            "diagnostic results."
        )
    )

    parser.add_argument(
        "--results-root",
        required=True,
    )
    parser.add_argument(
        "--ground-truth",
        required=True,
    )
    parser.add_argument(
        "--output-dir",
        required=True,
    )

    args = parser.parse_args()

    root = Path(args.results_root)
    gt_path = Path(args.ground_truth)
    out = Path(args.output_dir)

    ground_truth, metadata = (
        load_phase2_ground_truth(gt_path)
    )

    if len(ground_truth) != 60:
        raise ValueError(
            f"expected 60 instances, got {len(ground_truth)}"
        )

    all_records = []
    primary_records = []

    raw_signatures: dict[
        str,
        dict[str, list[tuple[Any, ...]]],
    ] = defaultdict(lambda: defaultdict(list))

    semantic_signatures: dict[
        str,
        dict[str, list[tuple[Any, ...]]],
    ] = defaultdict(lambda: defaultdict(list))

    per_execution = []

    for iid in sorted(ground_truth):
        for repetition in range(1, 6):
            diagnostics_path = (
                root
                / iid
                / f"rep-{repetition:02d}"
                / "diagnostics.json"
            )

            trial_path = (
                root
                / iid
                / f"rep-{repetition:02d}"
                / "trial.json"
            )

            if not diagnostics_path.exists():
                raise FileNotFoundError(
                    f"missing diagnostics: {diagnostics_path}"
                )

            if not trial_path.exists():
                raise FileNotFoundError(
                    f"missing trial metadata: {trial_path}"
                )

            diagnostics = load_json(diagnostics_path)
            trial = load_json(trial_path)

            if trial["instance_id"] != iid:
                raise ValueError(
                    f"instance mismatch: {trial_path}"
                )

            if int(trial["repetition"]) != repetition:
                raise ValueError(
                    f"repetition mismatch: {trial_path}"
                )

            if (
                trial["ground_truth_consumed_by_runner"]
                is not False
            ):
                raise ValueError(
                    f"ground truth leakage flag: {trial_path}"
                )

            results = diagnostics.get("results")

            if set(results) != set(METHODS):
                raise ValueError(
                    f"unexpected methods for {iid} "
                    f"rep-{repetition:02d}: "
                    f"{sorted(results)}"
                )

            records = evaluate_diagnostics_payload(
                ground_truth[iid],
                diagnostics,
            )

            all_records.extend(records)

            if repetition == 1:
                primary_records.extend(records)

            record_by_method = {
                r.method: r
                for r in records
            }

            for method in METHODS:
                result = results[method]

                raw_signatures[iid][method].append(
                    diagnostic_signature(
                        result,
                        include_element_ref=True,
                    )
                )

                semantic_signatures[iid][method].append(
                    diagnostic_signature(
                        result,
                        include_element_ref=False,
                    )
                )

                r = record_by_method[method]

                per_execution.append({
                    "instance_id": iid,
                    "prototype_id":
                        metadata[iid]["prototype_id"],
                    "family":
                        metadata[iid]["family"],
                    "boundary":
                        metadata[iid]["boundary"],
                    "repetition": repetition,
                    **asdict(r),
                })

    if len(all_records) != 900:
        raise ValueError(
            f"expected 900 method records, "
            f"got {len(all_records)}"
        )

    if len(primary_records) != 180:
        raise ValueError(
            f"expected 180 primary records, "
            f"got {len(primary_records)}"
        )

    primary_summary = summarize_records(
        primary_records,
        ground_truth,
    )

    stability = {
        "schema_version": 1,
        "instance_count": 60,
        "repetitions_per_instance": 5,
        "methods": {},
    }

    for method in METHODS:
        raw_stable = 0
        semantic_stable = 0
        unstable_instances = []

        for iid in sorted(ground_truth):
            raw_unique = set(
                raw_signatures[iid][method]
            )
            semantic_unique = set(
                semantic_signatures[iid][method]
            )

            if len(raw_unique) == 1:
                raw_stable += 1

            if len(semantic_unique) == 1:
                semantic_stable += 1
            else:
                unstable_instances.append(iid)

        stability["methods"][method] = {
            "raw_output_stable_instances": raw_stable,
            "raw_output_stability_rate":
                raw_stable / 60,
            "semantic_output_stable_instances":
                semantic_stable,
            "semantic_output_stability_rate":
                semantic_stable / 60,
            "semantic_unstable_instances":
                unstable_instances,
        }

    groups: dict[str, list[str]] = {
        "ALL": sorted(ground_truth),
        "NON_BOUNDARY": sorted(
            iid for iid in ground_truth
            if not metadata[iid]["boundary"]
        ),
        "BOUNDARY": sorted(
            iid for iid in ground_truth
            if metadata[iid]["boundary"]
        ),
    }

    for family in sorted(
        {m["family"] for m in metadata.values()}
    ):
        groups[f"FAMILY_{family}"] = sorted(
            iid for iid in ground_truth
            if metadata[iid]["family"] == family
        )

    for prototype in sorted(
        {m["prototype_id"] for m in metadata.values()}
    ):
        groups[f"PROTOTYPE_{prototype}"] = sorted(
            iid for iid in ground_truth
            if metadata[iid]["prototype_id"]
            == prototype
        )

    stratified = {
        "schema_version": 1,
        "primary_repetition": 1,
        "accuracy_unit": "parameterized instance",
        "groups": {},
    }

    for name, ids in groups.items():
        stratified["groups"][name] = {
            "instance_count": len(ids),
            "summary": subset_summary(
                primary_records,
                ground_truth,
                ids,
            ),
        }

    write_json(
        out / "primary-summary.json",
        primary_summary,
    )

    write_json(
        out / "stability-summary.json",
        stability,
    )

    write_json(
        out / "stratified-summary.json",
        stratified,
    )

    write_json(
        out / "records-all.json",
        per_execution,
    )

    csv_path = out / "primary-stratified-summary.csv"
    csv_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with csv_path.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as f:
        writer = csv.writer(f)

        writer.writerow([
            "group",
            "instance_count",
            "method",
            "coverage",
            "verdict_accuracy",
            "fault_domain_accuracy",
            "localization_accuracy",
            "strict_accuracy",
        ])

        for group_name, group in sorted(
            stratified["groups"].items()
        ):
            for method, values in sorted(
                group["summary"]["methods"].items()
            ):
                writer.writerow([
                    group_name,
                    group["instance_count"],
                    method,
                    values["coverage"],
                    values["verdict_accuracy"],
                    values["fault_domain_accuracy"],
                    values["localization_accuracy"],
                    values["strict_accuracy"],
                ])

    print(
        "PASS: evaluated 60 parameterized instances "
        "across 5 repetitions"
    )
    print(
        "PASS: primary accuracy uses rep-01 only "
        "(60 instances, 180 method records)"
    )
    print(
        "PASS: repetitions 2-5 used for stability, "
        "not as independent accuracy samples"
    )
    print(f"output: {out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
