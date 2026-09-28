from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = (
    ROOT
    / "scripts"
    / "experiments"
    / "evaluate_phase2_parameterized.py"
)

spec = importlib.util.spec_from_file_location(
    "evaluate_phase2_parameterized",
    MODULE_PATH,
)
assert spec is not None
assert spec.loader is not None

evaluator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evaluator)


METHODS = ("CONFIG_ONLY", "FLOW_ONLY", "PROPOSED")


def _write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            payload,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def _result(
    *,
    verdict: str = "ALLOW",
    fault_domain: str = "NONE",
    affected_device: str = "",
    affected_element_type: str = "NONE",
    affected_element_ref: str = "none",
    abstained: bool = False,
):
    return {
        "verdict": verdict,
        "fault_domain": fault_domain,
        "affected_device": affected_device,
        "affected_element_type": affected_element_type,
        "affected_element_ref": affected_element_ref,
        "abstained": abstained,
    }


def _build_suite(tmp_path: Path):
    results_root = tmp_path / "results"
    gt_path = tmp_path / "ground_truth.json"
    out_dir = tmp_path / "evaluation"

    gt = {
        "schema_version": 1,
        "purpose": "synthetic Phase-2 evaluator test",
        "instances": {},
    }

    for index in range(60):
        iid = f"synthetic-v{index + 1:02d}"

        # Exactly 20 boundary and 40 non-boundary instances.
        boundary = index < 20

        gt["instances"][iid] = {
            "prototype_id": f"prototype-{index // 5:02d}",
            "family": "CONTROL",
            "boundary": boundary,
            "expected_verdict": "ALLOW",
            "expected_fault_domain": "NONE",
            "expected_affected_device": "",
            "expected_element_type": "NONE",
            "expected_element_ref": {
                "mode": "ignore",
                "value": "",
            },
        }

        for repetition in range(1, 6):
            rep = (
                results_root
                / iid
                / f"rep-{repetition:02d}"
            )

            diagnostics = {
                "capture_id": (
                    f"capture-{index + 1:02d}-"
                    f"{repetition:02d}"
                ),
                "query_id": f"q-{index + 1:02d}",
                "results": {
                    method: _result()
                    for method in METHODS
                },
            }

            trial = {
                "instance_id": iid,
                "prototype_id":
                    gt["instances"][iid]["prototype_id"],
                "family": "CONTROL",
                "repetition": repetition,
                "ground_truth_consumed_by_runner": False,
            }

            _write_json(
                rep / "diagnostics.json",
                diagnostics,
            )
            _write_json(
                rep / "trial.json",
                trial,
            )

    _write_json(gt_path, gt)

    return results_root, gt_path, out_dir


def _run(
    monkeypatch,
    results_root: Path,
    gt_path: Path,
    out_dir: Path,
):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "evaluate_phase2_parameterized.py",
            "--results-root",
            str(results_root),
            "--ground-truth",
            str(gt_path),
            "--output-dir",
            str(out_dir),
        ],
    )

    return evaluator.main()


def test_valid_60_by_5_suite(monkeypatch, tmp_path):
    results_root, gt_path, out_dir = (
        _build_suite(tmp_path)
    )

    assert (
        _run(
            monkeypatch,
            results_root,
            gt_path,
            out_dir,
        )
        == 0
    )

    primary = json.loads(
        (
            out_dir
            / "primary-summary.json"
        ).read_text()
    )

    stability = json.loads(
        (
            out_dir
            / "stability-summary.json"
        ).read_text()
    )

    records = json.loads(
        (
            out_dir
            / "records-all.json"
        ).read_text()
    )

    assert primary["scenario_count"] == 60
    assert primary["record_count"] == 180
    assert len(records) == 900

    for method in METHODS:
        values = primary["methods"][method]

        assert values["trials"] == 60
        assert values["verdict_accuracy"] == 1.0

        s = stability["methods"][method]

        assert (
            s["semantic_output_stable_instances"]
            == 60
        )
        assert (
            s["raw_output_stable_instances"]
            == 60
        )


def test_rejects_non_60_ground_truth(
    monkeypatch,
    tmp_path,
):
    results_root, gt_path, out_dir = (
        _build_suite(tmp_path)
    )

    gt = json.loads(gt_path.read_text())

    gt["instances"].pop(
        sorted(gt["instances"])[-1]
    )

    _write_json(gt_path, gt)

    try:
        _run(
            monkeypatch,
            results_root,
            gt_path,
            out_dir,
        )
    except ValueError as exc:
        assert "expected 60 instances" in str(exc)
    else:
        raise AssertionError(
            "59-instance ground truth was accepted"
        )


def test_rejects_missing_repetition(
    monkeypatch,
    tmp_path,
):
    results_root, gt_path, out_dir = (
        _build_suite(tmp_path)
    )

    shutil.rmtree(
        results_root
        / "synthetic-v01"
        / "rep-05"
    )

    try:
        _run(
            monkeypatch,
            results_root,
            gt_path,
            out_dir,
        )
    except FileNotFoundError as exc:
        assert "missing diagnostics" in str(exc)
    else:
        raise AssertionError(
            "missing repetition was accepted"
        )


def test_rejects_missing_method(
    monkeypatch,
    tmp_path,
):
    results_root, gt_path, out_dir = (
        _build_suite(tmp_path)
    )

    path = (
        results_root
        / "synthetic-v01"
        / "rep-01"
        / "diagnostics.json"
    )

    diagnostics = json.loads(path.read_text())

    diagnostics["results"].pop("FLOW_ONLY")

    _write_json(path, diagnostics)

    try:
        _run(
            monkeypatch,
            results_root,
            gt_path,
            out_dir,
        )
    except ValueError as exc:
        assert "unexpected methods" in str(exc)
    else:
        raise AssertionError(
            "missing method was accepted"
        )


def test_rejects_ground_truth_consumption_flag(
    monkeypatch,
    tmp_path,
):
    results_root, gt_path, out_dir = (
        _build_suite(tmp_path)
    )

    path = (
        results_root
        / "synthetic-v01"
        / "rep-01"
        / "trial.json"
    )

    trial = json.loads(path.read_text())

    trial[
        "ground_truth_consumed_by_runner"
    ] = True

    _write_json(path, trial)

    try:
        _run(
            monkeypatch,
            results_root,
            gt_path,
            out_dir,
        )
    except ValueError as exc:
        assert "ground truth leakage flag" in str(exc)
    else:
        raise AssertionError(
            "ground-truth consumption was accepted"
        )


def test_primary_accuracy_uses_rep01_only(
    monkeypatch,
    tmp_path,
):
    results_root, gt_path, out_dir = (
        _build_suite(tmp_path)
    )

    # Make repetitions 2-5 wrong for PROPOSED on
    # every instance. Rep-01 remains correct.
    for iid_dir in sorted(
        p for p in results_root.iterdir()
        if p.is_dir()
    ):
        for repetition in range(2, 6):
            path = (
                iid_dir
                / f"rep-{repetition:02d}"
                / "diagnostics.json"
            )

            diagnostics = json.loads(
                path.read_text()
            )

            diagnostics["results"]["PROPOSED"] = (
                _result(
                    verdict="DENY",
                    fault_domain="FIREWALL",
                    affected_device="fw1",
                    affected_element_type=(
                        "POLICY_RULE"
                    ),
                    affected_element_ref=(
                        "policy:synthetic"
                    ),
                )
            )

            _write_json(path, diagnostics)

    assert (
        _run(
            monkeypatch,
            results_root,
            gt_path,
            out_dir,
        )
        == 0
    )

    primary = json.loads(
        (
            out_dir
            / "primary-summary.json"
        ).read_text()
    )

    stability = json.loads(
        (
            out_dir
            / "stability-summary.json"
        ).read_text()
    )

    # Accuracy is based only on the 60 rep-01
    # parameterized instances.
    proposed = primary["methods"]["PROPOSED"]

    assert proposed["trials"] == 60
    assert proposed["verdict_accuracy"] == 1.0

    # Repetitions 2-5 expose instability rather
    # than inflating accuracy N from 60 to 300.
    assert (
        stability["methods"]["PROPOSED"][
            "semantic_output_stable_instances"
        ]
        == 0
    )


def test_boundary_and_non_boundary_counts(
    monkeypatch,
    tmp_path,
):
    results_root, gt_path, out_dir = (
        _build_suite(tmp_path)
    )

    assert (
        _run(
            monkeypatch,
            results_root,
            gt_path,
            out_dir,
        )
        == 0
    )

    stratified = json.loads(
        (
            out_dir
            / "stratified-summary.json"
        ).read_text()
    )

    groups = stratified["groups"]

    assert groups["ALL"]["instance_count"] == 60
    assert (
        groups["BOUNDARY"]["instance_count"]
        == 20
    )
    assert (
        groups["NON_BOUNDARY"]["instance_count"]
        == 40
    )


def test_raw_and_semantic_stability_are_distinct(
    monkeypatch,
    tmp_path,
):
    results_root, gt_path, out_dir = (
        _build_suite(tmp_path)
    )

    # Change only the element reference for one
    # execution. The semantic diagnosis remains
    # unchanged, while the raw output changes.
    path = (
        results_root
        / "synthetic-v01"
        / "rep-02"
        / "diagnostics.json"
    )

    diagnostics = json.loads(path.read_text())

    diagnostics["results"]["CONFIG_ONLY"][
        "affected_element_ref"
    ] = "synthetic-ref-change"

    _write_json(path, diagnostics)

    assert (
        _run(
            monkeypatch,
            results_root,
            gt_path,
            out_dir,
        )
        == 0
    )

    stability = json.loads(
        (
            out_dir
            / "stability-summary.json"
        ).read_text()
    )

    config = stability["methods"]["CONFIG_ONLY"]

    assert (
        config[
            "semantic_output_stable_instances"
        ]
        == 60
    )

    assert (
        config["raw_output_stable_instances"]
        == 59
    )

    assert (
        config["semantic_unstable_instances"]
        == []
    )
