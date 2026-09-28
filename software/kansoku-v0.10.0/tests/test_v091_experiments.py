from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from kansoku.experiment import (
    ExperimentDefinition,
    ExperimentTrial,
    export_experiment,
    import_lab_summary,
    load_scenario_catalog,
    summarize_trials,
    write_environment_manifest,
)
from kansoku.hub import Hub


ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "scenarios" / "evaluation" / "catalog.json"


def _experiment() -> ExperimentDefinition:
    return ExperimentDefinition(
        name="evaluation",
        scenarios=["normal", "firewall-deny"],
        repetitions=2,
        base_seed=100,
        baselines=["flow-only", "configuration-only"],
    )


def _trial(experiment_id: str, scenario: str, repetition: int, *, passed: bool = True) -> ExperimentTrial:
    return ExperimentTrial(
        experiment_id=experiment_id,
        scenario_id=scenario,
        repetition=repetition,
        seed=100 + repetition,
        status="PASS" if passed else "FAIL",
        expected_verdict="ALLOW" if scenario == "normal" else "DENY",
        observed_verdict=("ALLOW" if scenario == "normal" else "DENY") if passed else "UNKNOWN",
        timings_ms={"diagnosis": float(10 * repetition), "total": float(20 * repetition)},
        counters={"observation_bytes": float(1000 * repetition)},
    )


def test_experiment_definition_requires_unique_scenarios():
    item = ExperimentDefinition(name="bad", scenarios=["same", "same"])
    with pytest.raises(ValueError, match="unique"):
        item.validate()


def test_hub_migrates_and_persists_experiments_and_trials(tmp_path: Path):
    hub = Hub(tmp_path / "hub.db")
    experiment = _experiment()
    assert hub.add_experiments([experiment]) == 1
    trial = _trial(experiment.experiment_id, "normal", 1)
    assert hub.add_experiment_trials([trial]) == 1
    assert hub.get_experiment(experiment.experiment_id).to_dict() == experiment.to_dict()
    assert hub.get_experiment_trial(trial.trial_id).to_dict() == trial.to_dict()
    assert hub.list_experiment_trials(experiment_id=experiment.experiment_id)[0].trial_id == trial.trial_id
    completed = hub.set_experiment_status(experiment.experiment_id, "COMPLETED")
    assert completed.status == "COMPLETED"
    with hub.connect() as conn:
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"experiments", "experiment_trials"} <= tables


def test_trial_rejects_negative_timing():
    item = ExperimentTrial(
        experiment_id="experiment-1",
        scenario_id="normal",
        repetition=1,
        seed=1,
        status="PASS",
        timings_ms={"diagnosis": -1},
    )
    with pytest.raises(ValueError, match="non-negative"):
        item.validate()


def test_summary_calculates_accuracy_recovery_and_percentiles():
    experiment = _experiment()
    trials = [
        _trial(experiment.experiment_id, "normal", 1),
        _trial(experiment.experiment_id, "normal", 2),
        _trial(experiment.experiment_id, "firewall-deny", 1),
        _trial(experiment.experiment_id, "firewall-deny", 2, passed=False),
        ExperimentTrial(
            experiment_id=experiment.experiment_id,
            scenario_id="packet-loss",
            repetition=1,
            seed=105,
            status="PASS",
            expected_recovery=True,
            recovered=True,
            timings_ms={"recovery": 50},
        ),
    ]
    experiment.scenarios.append("packet-loss")
    summary = summarize_trials(experiment, trials)
    assert summary["trial_count"] == 5
    assert summary["status_counts"]["PASS"] == 4
    assert summary["pass_rate"] == pytest.approx(0.8)
    assert summary["verdict"]["evaluated"] == 4
    assert summary["verdict"]["accuracy"] == pytest.approx(0.75)
    assert summary["recovery"]["accuracy"] == 1.0
    assert summary["timings_ms"]["diagnosis"]["median"] == 15.0
    assert summary["timings_ms"]["diagnosis"]["p95"] == pytest.approx(20.0)
    assert summary["verdict_confusion"]["DENY"]["UNKNOWN"] == 1


def test_export_writes_machine_readable_json_and_csv(tmp_path: Path):
    experiment = _experiment()
    trials = [_trial(experiment.experiment_id, "normal", 1)]
    paths = export_experiment(experiment, trials, output_dir=tmp_path / "export")
    assert set(paths) == {"experiment", "trials_json", "trials_csv", "summary"}
    assert json.loads(paths["summary"].read_text())["trial_count"] == 1
    with paths["trials_csv"].open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["scenario_id"] == "normal"
    assert rows[0]["diagnosis_ms"] == "10.0"
    assert rows[0]["observation_bytes"] == "1000.0"


def test_import_lab_summary_creates_five_scenarios_and_three_recommendations(tmp_path: Path):
    summary_path = tmp_path / "summary.json"
    summary_path.write_text(json.dumps({
        "suite": "kansoku-v0.10.0-containerlab",
        "passed": 5,
        "total": 5,
        "scenarios": [
            {"scenario": "normal", "status": "PASS", "packets": 4, "flows": 1, "verdicts": {"ALLOW": 1}},
            {"scenario": "firewall-deny", "status": "PASS", "expected": "DENY", "verdicts": {"DENY": 1}},
            {"scenario": "route-missing", "status": "PASS", "expected": "UNROUTABLE", "verdicts": {"UNROUTABLE": 1}},
            {"scenario": "vlan-mismatch", "status": "PASS", "expected": "UNKNOWN", "verdicts": {"UNKNOWN": 1}},
            {"scenario": "packet-loss", "status": "PASS", "recovery": "restored"},
            {"recommendation_id": "recommendation-fw", "target": "lab-firewall-deny", "category": "FIREWALL_POLICY", "simulation_status": "PASSED", "simulated_verdict": "ALLOW"},
            {"recommendation_id": "recommendation-route", "target": "lab-route-missing", "category": "ROUTE", "simulation_status": "PASSED", "simulated_verdict": "ALLOW"},
            {"recommendation_id": "recommendation-vlan", "target": "lab-vlan-mismatch", "category": "VLAN", "simulation_status": "PASSED", "simulated_verdict": "ALLOW"}
        ]
    }))
    rows = import_lab_summary(summary_path, experiment_id="experiment-1", environment={"host": "lab"})
    assert len(rows) == 8
    assert all(item.status == "PASS" for item in rows)
    assert next(item for item in rows if item.scenario_id == "normal").counters == {
        "packet_count": 4.0,
        "flow_count": 1.0,
    }
    firewall = next(item for item in rows if item.scenario_id == "firewall-deny-recommendation")
    assert firewall.expected_category == "FIREWALL_POLICY"
    assert firewall.observed_category == "FIREWALL_POLICY"
    assert firewall.observed_verdict == "ALLOW"


def test_scenario_catalog_is_unique_and_separates_implemented_from_planned():
    rows = load_scenario_catalog(CATALOG)
    assert len(rows) >= 15
    assert len({item.scenario_id for item in rows}) == len(rows)
    implemented = {item.scenario_id for item in rows if item.implemented}
    assert {"normal", "firewall-deny", "route-missing", "vlan-mismatch", "packet-loss"} <= implemented
    assert any(item.layer == "compound" and not item.implemented for item in rows)


def test_environment_manifest_is_json(monkeypatch, tmp_path: Path):
    monkeypatch.setattr("kansoku.experiment._command_version", lambda command: "test-version")
    path = write_environment_manifest(tmp_path / "environment.json", labels={"site": "ci"})
    payload = json.loads(path.read_text())
    assert payload["kansoku_version"] == "0.10.0"
    assert payload["git_commit"] == "test-version"
    assert payload["labels"] == {"site": "ci"}


def test_lab_suite_exports_reproducible_experiment_results():
    script = (ROOT / "lab" / "scripts" / "lab-test.sh").read_text()
    assert "experiment create" in script
    assert "experiment import-lab" in script
    assert "experiment export" in script
    assert "trial_count" in script
    assert "11 trials" in script
    assert "recommend apply-lab" in script
    assert "3/3 guarded remediations" in script
