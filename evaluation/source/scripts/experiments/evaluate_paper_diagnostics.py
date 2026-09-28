#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from kansoku.paper_evaluation import (
    evaluate_suite,
    load_ground_truth,
    summarize_records,
)


def _write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate paper diagnostics against independent ground truth."
    )
    parser.add_argument(
        "--ground-truth",
        default="scenarios/paper/ground_truth.json",
        help="Independent ground-truth JSON",
    )
    parser.add_argument(
        "--diagnostics-root",
        default="artifacts/paper",
        help="Directory containing <scenario>/diagnostics.json",
    )
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()

    ground_truth = load_ground_truth(args.ground_truth)
    records = evaluate_suite(ground_truth, args.diagnostics_root)
    summary = summarize_records(records, ground_truth)

    out = Path(args.output_dir)
    _write_json(out / "records.json", [record.to_dict() for record in records])
    _write_json(out / "summary.json", summary)

    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
