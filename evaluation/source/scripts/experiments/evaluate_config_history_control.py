#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
from typing import Any


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def dump(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description="Evaluate frozen CONFIG_HISTORY_ONLY control outputs after execution.")
    ap.add_argument("--results-root", required=True)
    ap.add_argument("--spec", required=True)
    ap.add_argument("--ground-truth", required=True)
    ap.add_argument("--output-dir", required=True)
    ap.add_argument("--repetitions", type=int, default=1)
    args = ap.parse_args()
    if args.repetitions < 1 or args.repetitions > 5:
        raise ValueError("--repetitions must be 1..5")

    root = Path(args.results_root)
    spec = load(Path(args.spec))
    gt_doc = load(Path(args.ground_truth))
    gt_instances = gt_doc.get("instances", gt_doc)
    rows = []

    for iid in spec["instances"]:
        gt = gt_instances[iid]
        for rep in range(1, args.repetitions + 1):
            dpath = root / iid / f"rep-{rep:02d}" / "diagnostics.json"
            tpath = root / iid / f"rep-{rep:02d}" / "trial.json"
            if not dpath.exists() or not tpath.exists():
                raise FileNotFoundError(f"missing frozen output for {iid} rep-{rep:02d}")
            diag = load(dpath)
            trial = load(tpath)
            if trial.get("ground_truth_consumed_by_runner_or_diagnoser") is not False:
                raise ValueError(f"ground-truth leakage flag for {iid} rep-{rep:02d}")
            r = diag["result"]
            verdict_ok = r["verdict"] == gt["expected_verdict"]
            domain_ok = r["fault_domain"] == gt["expected_fault_domain"]
            device_expected = str(gt.get("expected_affected_device", ""))
            type_expected = str(gt.get("expected_element_type", ""))
            device_ok = (not device_expected) or r["affected_device"] == device_expected
            type_ok = (not type_expected) or r["affected_element_type"] == type_expected
            rows.append({
                "instance_id": iid,
                "repetition": rep,
                "verdict": r["verdict"],
                "fault_domain": r["fault_domain"],
                "affected_device": r["affected_device"],
                "affected_element_type": r["affected_element_type"],
                "abstained": bool(r["abstained"]),
                "verdict_correct": verdict_ok,
                "fault_domain_correct": domain_ok,
                "strict_correct": verdict_ok and domain_ok,
                "affected_device_correct": device_ok,
                "affected_element_type_correct": type_ok,
                "diagnostics_sha256": sha256_file(dpath),
            })

    primary = [r for r in rows if r["repetition"] == 1]
    instance_count = len(primary)
    summary = {
        "schema_version": 1,
        "control_id": spec["control_id"],
        "primary_repetition": 1,
        "primary_instance_count": instance_count,
        "strict_correct": sum(r["strict_correct"] for r in primary),
        "verdict_correct": sum(r["verdict_correct"] for r in primary),
        "fault_domain_correct": sum(r["fault_domain_correct"] for r in primary),
        "affected_device_correct": sum(r["affected_device_correct"] for r in primary),
        "affected_element_type_correct": sum(r["affected_element_type_correct"] for r in primary),
        "primary_results": primary,
        "all_execution_records": rows,
    }
    if args.repetitions > 1:
        stability = {}
        for iid in spec["instances"]:
            sigs = {
                (r["verdict"], r["fault_domain"], r["affected_device"], r["affected_element_type"], r["abstained"])
                for r in rows if r["instance_id"] == iid
            }
            stability[iid] = {"semantic_stable": len(sigs) == 1, "unique_signatures": len(sigs)}
        summary["stability"] = stability
        summary["stable_instances"] = sum(v["semantic_stable"] for v in stability.values())

    out = Path(args.output_dir)
    dump(out / "summary.json", summary)
    with (out / "records.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    print(f"CONFIG_HISTORY_ONLY strict correctness: {summary['strict_correct']}/{instance_count}")
    print(f"affected-device correctness: {summary['affected_device_correct']}/{instance_count}")
    print(f"affected-element-type correctness: {summary['affected_element_type_correct']}/{instance_count}")
    if args.repetitions > 1:
        print(f"semantic stability: {summary['stable_instances']}/{len(spec['instances'])} instances")
    print(f"output: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
