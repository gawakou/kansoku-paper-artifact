#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


DEFAULT_RAW = Path(
    "artifacts/paper/rq2-recommendation-v1"
)

DEFAULT_GT = Path(
    "scenarios/paper/"
    "rq2_recommendation_ground_truth.json"
)

DEFAULT_SNAPSHOT = Path(
    "artifacts/paper/rq2-snapshots/raw-v1"
)

EXPECTED_INSTANCE_COUNT = 15

EXPECTED_FAMILIES = {
    "FIREWALL": 5,
    "ROUTE": 5,
    "VLAN": 5,
}


def load_json(path: Path) -> Any:
    return json.loads(
        path.read_text(encoding="utf-8")
    )


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_text(
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
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


def parse_sha256_manifest(
    path: Path,
) -> list[tuple[str, Path]]:
    rows = []

    for line in path.read_text(
        encoding="utf-8"
    ).splitlines():
        if not line.strip():
            continue

        digest, filename = line.split(
            None,
            1,
        )

        rows.append(
            (
                digest,
                Path(filename.strip()),
            )
        )

    return rows


def verify_manifest(path: Path) -> None:
    for expected, file_path in (
        parse_sha256_manifest(path)
    ):
        if not file_path.exists():
            raise FileNotFoundError(
                f"snapshot file missing: "
                f"{file_path}"
            )

        actual = sha256_file(file_path)

        if actual != expected:
            raise ValueError(
                "snapshot checksum mismatch: "
                f"{file_path}: "
                f"expected={expected} "
                f"actual={actual}"
            )


def normalize_variant(value: Any) -> str:
    text = str(value or "").strip()

    if not text:
        return "primary"

    return text


def required_subset(
    expected: list[str],
    actual: list[str],
) -> bool:
    return set(expected).issubset(
        set(actual)
    )


def evaluate_instance(
    *,
    instance_id: str,
    gt: dict[str, Any],
    raw_dir: Path,
) -> dict[str, Any]:
    trial = load_json(
        raw_dir / "trial.json"
    )

    result = load_json(
        raw_dir / "result.json"
    )

    graph = load_json(
        raw_dir / "evidence-graph.json"
    )

    ranked = load_json(
        raw_dir / "ranked-candidates.json"
    )

    if (
        trial.get(
            "ground_truth_consumed_by_runner"
        )
        is not False
    ):
        raise ValueError(
            f"{instance_id}: runner consumed "
            "ground truth"
        )

    if (
        trial.get("rq2_instance_id")
        != instance_id
    ):
        raise ValueError(
            f"{instance_id}: trial ID mismatch"
        )

    top1 = result.get("top1")

    if not isinstance(top1, dict):
        raise ValueError(
            f"{instance_id}: top1 missing"
        )

    ranked_rows = ranked.get("ranked")

    if (
        not isinstance(ranked_rows, list)
        or not ranked_rows
    ):
        raise ValueError(
            f"{instance_id}: ranked candidates "
            "missing"
        )

    rank1 = next(
        (
            row
            for row in ranked_rows
            if int(row["rank"]) == 1
        ),
        None,
    )

    if rank1 is None:
        raise ValueError(
            f"{instance_id}: rank-1 candidate "
            "missing"
        )

    rank1_rec = rank1["recommendation"]

    if (
        rank1_rec["category"]
        != top1["category"]
    ):
        raise ValueError(
            f"{instance_id}: result/ranking "
            "category mismatch"
        )

    if (
        rank1_rec["device_id"]
        != top1["device_id"]
    ):
        raise ValueError(
            f"{instance_id}: result/ranking "
            "device mismatch"
        )

    rank1_variant = normalize_variant(
        rank1.get("variant")
    )

    top1_variant = normalize_variant(
        top1.get("variant")
    )

    if rank1_variant != top1_variant:
        raise ValueError(
            f"{instance_id}: result/ranking "
            "variant mismatch"
        )

    graph_nodes = graph.get("nodes", [])
    graph_edges = graph.get("edges", [])

    node_types = sorted({
        str(node["node_type"])
        for node in graph_nodes
    })

    node_ids = sorted({
        str(node["node_id"])
        for node in graph_nodes
    })

    relations = sorted({
        str(edge["relation"])
        for edge in graph_edges
    })

    category_correct = (
        top1["category"]
        == gt["expected_category"]
    )

    device_correct = (
        top1["device_id"]
        == gt["expected_device"]
    )

    variant_correct = (
        top1_variant
        == gt["expected_top1_variant"]
    )

    top1_correct = (
        category_correct
        and device_correct
        and variant_correct
    )

    what_if_correct = (
        top1["simulation_status"]
        == gt["expected_simulation_status"]
        and
        top1["simulated_verdict"]
        == gt["expected_simulated_verdict"]
    )

    trace_nodes = required_subset(
        gt.get(
            "required_node_types",
            [],
        ),
        node_types,
    )

    trace_relations = required_subset(
        gt.get(
            "required_relations",
            [],
        ),
        relations,
    )

    trace_ids = required_subset(
        gt.get(
            "required_node_ids",
            [],
        ),
        node_ids,
    )

    traceability_correct = (
        trace_nodes
        and trace_relations
        and trace_ids
    )

    forbidden = set(
        gt.get(
            "forbidden_top1_variants",
            [],
        )
    )

    unsafe_or_broader = (
        top1_variant in forbidden
    )

    return {
        "instance_id": instance_id,
        "family": gt["family"],

        "actual_category":
            top1["category"],
        "expected_category":
            gt["expected_category"],
        "category_correct":
            category_correct,

        "actual_device":
            top1["device_id"],
        "expected_device":
            gt["expected_device"],
        "device_correct":
            device_correct,

        "actual_top1_variant":
            top1_variant,
        "expected_top1_variant":
            gt["expected_top1_variant"],
        "variant_correct":
            variant_correct,

        "top1_correct":
            top1_correct,

        "actual_simulation_status":
            top1["simulation_status"],
        "expected_simulation_status":
            gt[
                "expected_simulation_status"
            ],

        "actual_simulated_verdict":
            top1["simulated_verdict"],
        "expected_simulated_verdict":
            gt[
                "expected_simulated_verdict"
            ],

        "what_if_correct":
            what_if_correct,

        "required_node_types_met":
            trace_nodes,
        "required_relations_met":
            trace_relations,
        "required_node_ids_met":
            trace_ids,

        "traceability_correct":
            traceability_correct,

        "unsafe_or_broader_top1":
            unsafe_or_broader,

        "candidate_count":
            int(result["candidate_count"]),

        "top1_score":
            float(top1["score"]),

        "evidence_coverage":
            float(
                result[
                    "evidence_graph_summary"
                ]["evidence_coverage"]
            ),

        "source_query_id":
            result["source_query_id"],
    }


def metric(
    records: list[dict[str, Any]],
    key: str,
) -> dict[str, Any]:
    n = len(records)

    count = sum(
        1
        for row in records
        if bool(row[key])
    )

    return {
        "count": count,
        "total": n,
        "rate": count / n if n else None,
    }


def summarize(
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "instance_count":
            len(records),

        "recommendation_category_accuracy":
            metric(
                records,
                "category_correct",
            ),

        "device_accuracy":
            metric(
                records,
                "device_correct",
            ),

        "top1_accuracy":
            metric(
                records,
                "top1_correct",
            ),

        "what_if_pass_rate":
            metric(
                records,
                "what_if_correct",
            ),

        "evidence_traceability_rate":
            metric(
                records,
                "traceability_correct",
            ),

        "unsafe_or_broader_top1_rate":
            metric(
                records,
                "unsafe_or_broader_top1",
            ),
    }


def write_csv(
    path: Path,
    records: list[dict[str, Any]],
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    if not records:
        raise ValueError(
            "cannot write empty CSV"
        )

    fields = list(records[0])

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
        writer.writerows(records)


def evaluate(
    *,
    raw_root: Path,
    gt_path: Path,
    snapshot_dir: Path,
    output_dir: Path,
    expected_raw_manifest_sha256:
        str | None = None,
) -> dict[str, Any]:
    if output_dir.exists():
        raise FileExistsError(
            f"output directory already exists: "
            f"{output_dir}"
        )

    gt_doc = load_json(gt_path)

    if gt_doc.get("schema_version") != 1:
        raise ValueError(
            "unsupported ground-truth schema"
        )

    gt_instances = gt_doc.get(
        "instances"
    )

    if (
        not isinstance(gt_instances, dict)
        or len(gt_instances)
        != EXPECTED_INSTANCE_COUNT
    ):
        raise ValueError(
            "RQ2 ground truth must contain "
            "exactly 15 instances"
        )

    gt_families = Counter(
        row["family"]
        for row in gt_instances.values()
    )

    if dict(gt_families) != (
        EXPECTED_FAMILIES
    ):
        raise ValueError(
            "unexpected RQ2 family composition: "
            f"{dict(gt_families)}"
        )

    provenance = load_json(
        snapshot_dir / "provenance.json"
    )

    if (
        provenance.get(
            "ground_truth_evaluated_before_snapshot"
        )
        is not False
    ):
        raise ValueError(
            "raw snapshot was not explicitly "
            "frozen before ground-truth evaluation"
        )

    if (
        provenance.get(
            "ground_truth_consumed_by_runner"
        )
        is not False
    ):
        raise ValueError(
            "snapshot provenance indicates "
            "ground-truth consumption"
        )

    raw_manifest = (
        snapshot_dir / "SHA256SUMS.txt"
    )

    if expected_raw_manifest_sha256:
        actual_manifest_hash = sha256_file(
            raw_manifest
        )

        if (
            actual_manifest_hash
            != expected_raw_manifest_sha256
        ):
            raise ValueError(
                "raw snapshot manifest hash "
                "does not match expected freeze: "
                f"{actual_manifest_hash}"
            )

    verify_manifest(
        raw_manifest
    )

    verify_manifest(
        snapshot_dir
        / "SNAPSHOT-SHA256SUMS.txt"
    )

    raw_dirs = {
        p.name: p
        for p in raw_root.iterdir()
        if p.is_dir()
    }

    if set(raw_dirs) != set(gt_instances):
        missing = sorted(
            set(gt_instances)
            - set(raw_dirs)
        )

        extra = sorted(
            set(raw_dirs)
            - set(gt_instances)
        )

        raise ValueError(
            "raw/ground-truth instance IDs "
            "differ: "
            f"missing={missing}, extra={extra}"
        )

    required_files = {
        "trial.json",
        "evidence-graph.json",
        "candidates.json",
        "ranked-candidates.json",
        "result.json",
    }

    records = []

    for instance_id in sorted(
        gt_instances
    ):
        d = raw_dirs[instance_id]

        actual_files = {
            p.name
            for p in d.iterdir()
            if p.is_file()
        }

        if actual_files != required_files:
            raise ValueError(
                f"{instance_id}: unexpected "
                "raw file set: "
                f"{sorted(actual_files)}"
            )

        records.append(
            evaluate_instance(
                instance_id=instance_id,
                gt=gt_instances[
                    instance_id
                ],
                raw_dir=d,
            )
        )

    summary = summarize(records)

    by_family = defaultdict(list)

    for row in records:
        by_family[
            row["family"]
        ].append(row)

    family_summary = {
        family: summarize(rows)
        for family, rows
        in sorted(by_family.items())
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

    write_csv(
        output_dir / "records.csv",
        records,
    )

    write_json(
        output_dir / "summary.json",
        {
            "schema_version": 1,
            "metrics": summary,
        },
    )

    write_json(
        output_dir / "family-summary.json",
        {
            "schema_version": 1,
            "families": family_summary,
        },
    )

    return {
        "summary": summary,
        "family_summary": family_summary,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Evaluate frozen KANSOKU RQ2 "
            "recommendation results."
        )
    )

    parser.add_argument(
        "--raw-root",
        default=str(DEFAULT_RAW),
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
        required=True,
    )

    parser.add_argument(
        "--expected-raw-manifest-sha256",
    )

    return parser


def main() -> int:
    args = build_parser().parse_args()

    result = evaluate(
        raw_root=Path(args.raw_root),
        gt_path=Path(args.ground_truth),
        snapshot_dir=Path(
            args.snapshot_dir
        ),
        output_dir=Path(
            args.output_dir
        ),
        expected_raw_manifest_sha256=(
            args.expected_raw_manifest_sha256
        ),
    )

    print(
        json.dumps(
            result,
            indent=2,
            sort_keys=True,
        )
    )

    print(
        "PASS: evaluated 15 frozen RQ2 "
        "recommendation instances"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
