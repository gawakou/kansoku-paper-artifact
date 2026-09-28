#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _ratio(numerator: int, denominator: int):
    return None if denominator == 0 else numerator / denominator


def _summarize_rows(rows: Iterable[Mapping[str, Any]]) -> Dict[str, Any]:
    items = list(rows)
    trials = len(items)
    answered = sum(bool(row["answered"]) for row in items)
    verdict_correct = sum(bool(row["verdict_correct"]) for row in items)
    fault_domain_correct = sum(bool(row["fault_domain_correct"]) for row in items)
    strict_correct = sum(bool(row["strict_correct"]) for row in items)
    localization_rows = [row for row in items if bool(row["localization_applicable"])]
    localization_correct = sum(bool(row["localization_correct"]) for row in localization_rows)
    return {
        "trials": trials,
        "answered": answered,
        "coverage": _ratio(answered, trials),
        "verdict_correct": verdict_correct,
        "verdict_accuracy": _ratio(verdict_correct, trials),
        "fault_domain_correct": fault_domain_correct,
        "fault_domain_accuracy": _ratio(fault_domain_correct, trials),
        "localization_applicable": len(localization_rows),
        "localization_correct": localization_correct,
        "localization_accuracy": _ratio(localization_correct, len(localization_rows)),
        "strict_correct": strict_correct,
        "strict_accuracy": _ratio(strict_correct, trials),
    }


def build_stratified_summary(
    records: Iterable[Mapping[str, Any]],
    catalog: Mapping[str, Mapping[str, Any]],
) -> Dict[str, Any]:
    items = list(records)
    scenario_ids = sorted({str(row["scenario_id"]) for row in items})
    missing = [scenario_id for scenario_id in scenario_ids if scenario_id not in catalog]
    if missing:
        raise ValueError(f"catalog is missing scenarios: {', '.join(missing)}")

    groups: Dict[str, set[str]] = {
        "ALL": set(scenario_ids),
        "NON_BOUNDARY": {
            scenario_id
            for scenario_id in scenario_ids
            if not bool(catalog[scenario_id].get("boundary", False))
        },
        "BOUNDARY": {
            scenario_id
            for scenario_id in scenario_ids
            if bool(catalog[scenario_id].get("boundary", False))
        },
    }
    families = sorted({str(catalog[scenario_id]["family"]) for scenario_id in scenario_ids})
    for family in families:
        groups[f"FAMILY_{family}"] = {
            scenario_id
            for scenario_id in scenario_ids
            if str(catalog[scenario_id]["family"]) == family
        }

    methods = sorted({str(row["method"]) for row in items})
    output: Dict[str, Any] = {}
    for group_name, scenarios in groups.items():
        block = {
            "scenario_count": len(scenarios),
            "scenarios": sorted(scenarios),
            "methods": {},
        }
        for method in methods:
            rows = [
                row
                for row in items
                if str(row["scenario_id"]) in scenarios and str(row["method"]) == method
            ]
            block["methods"][method] = _summarize_rows(rows)
        output[group_name] = block
    return output


def _write_csv(path: Path, summary: Mapping[str, Any]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "stratum",
                "method",
                "scenario_count",
                "coverage",
                "verdict_accuracy",
                "fault_domain_accuracy",
                "localization_accuracy",
                "strict_accuracy",
            ]
        )
        for stratum, block in summary.items():
            for method, metrics in block["methods"].items():
                writer.writerow(
                    [
                        stratum,
                        method,
                        block["scenario_count"],
                        metrics["coverage"],
                        metrics["verdict_accuracy"],
                        metrics["fault_domain_accuracy"],
                        metrics["localization_accuracy"],
                        metrics["strict_accuracy"],
                    ]
                )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create all/core-boundary/family stratified summaries for paper diagnostics."
    )
    parser.add_argument("--records", required=True, help="records.json from evaluate_paper_diagnostics.py")
    parser.add_argument("--catalog", default="scenarios/paper/catalog.json")
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()

    records_path = Path(args.records)
    catalog_path = Path(args.catalog)
    output_dir = Path(args.output_dir)

    records = _load_json(records_path)
    catalog_payload = _load_json(catalog_path)
    if not isinstance(records, list):
        raise ValueError("records JSON must contain a list")
    catalog = catalog_payload.get("scenarios") if isinstance(catalog_payload, dict) else None
    if not isinstance(catalog, dict):
        raise ValueError("catalog JSON must contain a scenarios object")

    summary = build_stratified_summary(records, catalog)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "stratified-summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _write_csv(output_dir / "stratified-summary.csv", summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
