from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "experiments" / "summarize_paper_strata.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("summarize_paper_strata", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _row(scenario_id: str, method: str, *, correct: bool, answered: bool = True):
    return {
        "scenario_id": scenario_id,
        "method": method,
        "answered": answered,
        "verdict_correct": correct,
        "fault_domain_correct": correct,
        "localization_applicable": scenario_id != "normal",
        "localization_correct": correct and scenario_id != "normal",
        "strict_correct": correct,
    }


def test_stratified_summary_separates_boundary_and_family():
    module = _load_module()
    catalog = {
        "normal": {"family": "CONTROL"},
        "core-route": {"family": "ROUTE"},
        "boundary-route": {"family": "ROUTE", "boundary": True},
    }
    records = []
    for method in ("CONFIG_ONLY", "FLOW_ONLY", "PROPOSED"):
        records.append(_row("normal", method, correct=True))
        records.append(_row("core-route", method, correct=(method != "FLOW_ONLY"), answered=method != "FLOW_ONLY"))
        records.append(_row("boundary-route", method, correct=False, answered=method != "FLOW_ONLY"))

    summary = module.build_stratified_summary(records, catalog)

    assert summary["ALL"]["scenario_count"] == 3
    assert summary["NON_BOUNDARY"]["scenarios"] == ["core-route", "normal"]
    assert summary["BOUNDARY"]["scenarios"] == ["boundary-route"]
    assert summary["FAMILY_ROUTE"]["scenario_count"] == 2

    proposed_non_boundary = summary["NON_BOUNDARY"]["methods"]["PROPOSED"]
    assert proposed_non_boundary["strict_accuracy"] == pytest.approx(1.0)
    assert proposed_non_boundary["localization_accuracy"] == pytest.approx(1.0)

    proposed_boundary = summary["BOUNDARY"]["methods"]["PROPOSED"]
    assert proposed_boundary["strict_accuracy"] == pytest.approx(0.0)

    flow_all = summary["ALL"]["methods"]["FLOW_ONLY"]
    assert flow_all["coverage"] == pytest.approx(1 / 3)


def test_stratified_summary_rejects_catalog_gaps():
    module = _load_module()
    records = [_row("missing", "PROPOSED", correct=False)]
    with pytest.raises(ValueError, match="catalog is missing scenarios"):
        module.build_stratified_summary(records, {})
