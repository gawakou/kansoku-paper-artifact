from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
import csv
from datetime import datetime, timezone
import importlib.metadata
import json
import math
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

from .models import new_id, utc_now


EXPERIMENT_STATUSES = {"PLANNED", "RUNNING", "COMPLETED", "FAILED", "ARCHIVED"}
TRIAL_STATUSES = {"PASS", "FAIL", "ERROR", "SKIPPED"}
DEFAULT_METRICS = [
    "verdict_accuracy",
    "recommendation_accuracy",
    "recovery_success_rate",
    "diagnosis_ms",
    "recommendation_ms",
    "recovery_ms",
    "observation_bytes",
]


@dataclass
class ExperimentDefinition:
    name: str
    scenarios: List[str]
    repetitions: int = 1
    base_seed: int = 1
    description: str = ""
    baselines: List[str] = field(default_factory=list)
    metrics: List[str] = field(default_factory=lambda: list(DEFAULT_METRICS))
    status: str = "PLANNED"
    experiment_id: str = field(default_factory=lambda: new_id("experiment"))
    created_at: str = field(default_factory=utc_now)
    updated_at: str = field(default_factory=utc_now)
    tags: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        if not self.name.strip():
            raise ValueError("experiment name is required")
        if not self.scenarios:
            raise ValueError("at least one scenario is required")
        if any(not item.strip() for item in self.scenarios):
            raise ValueError("scenario identifiers must not be empty")
        if len(set(self.scenarios)) != len(self.scenarios):
            raise ValueError("scenario identifiers must be unique")
        if self.repetitions < 1:
            raise ValueError("repetitions must be at least 1")
        if self.status not in EXPERIMENT_STATUSES:
            raise ValueError(f"unsupported experiment status: {self.status}")

    def to_dict(self) -> Dict[str, Any]:
        self.validate()
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ExperimentDefinition":
        defaults = {
            "description": "",
            "baselines": [],
            "metrics": list(DEFAULT_METRICS),
            "status": "PLANNED",
            "tags": {},
            "metadata": {},
        }
        item = cls(**{**defaults, **dict(data)})
        item.validate()
        return item

    def with_status(self, status: str) -> "ExperimentDefinition":
        item = replace(self, status=status, updated_at=utc_now())
        item.validate()
        return item


@dataclass
class ExperimentTrial:
    experiment_id: str
    scenario_id: str
    repetition: int
    seed: int
    status: str
    expected_verdict: str = ""
    observed_verdict: str = ""
    expected_category: str = ""
    observed_category: str = ""
    expected_recovery: Optional[bool] = None
    recovered: Optional[bool] = None
    timings_ms: Dict[str, float] = field(default_factory=dict)
    counters: Dict[str, float] = field(default_factory=dict)
    artifacts: Dict[str, str] = field(default_factory=dict)
    environment: Dict[str, Any] = field(default_factory=dict)
    error: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    trial_id: str = field(default_factory=lambda: new_id("trial"))
    started_at: str = field(default_factory=utc_now)
    finished_at: str = field(default_factory=utc_now)

    def validate(self) -> None:
        if not self.experiment_id or not self.scenario_id:
            raise ValueError("experiment_id and scenario_id are required")
        if self.repetition < 1:
            raise ValueError("repetition must be at least 1")
        if self.status not in TRIAL_STATUSES:
            raise ValueError(f"unsupported trial status: {self.status}")
        for name, value in self.timings_ms.items():
            if float(value) < 0:
                raise ValueError(f"timing must be non-negative: {name}")
        for name, value in self.counters.items():
            if not math.isfinite(float(value)):
                raise ValueError(f"counter must be finite: {name}")

    def to_dict(self) -> Dict[str, Any]:
        self.validate()
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ExperimentTrial":
        defaults = {
            "expected_verdict": "",
            "observed_verdict": "",
            "expected_category": "",
            "observed_category": "",
            "expected_recovery": None,
            "recovered": None,
            "timings_ms": {},
            "counters": {},
            "artifacts": {},
            "environment": {},
            "error": "",
            "metadata": {},
        }
        item = cls(**{**defaults, **dict(data)})
        item.validate()
        return item


@dataclass
class ScenarioSpec:
    scenario_id: str
    layer: str
    fault_type: str
    implemented: bool
    expected_verdict: str = ""
    expected_category: str = ""
    expected_recovery: Optional[bool] = None
    description: str = ""
    topology: str = "kansoku-virtual-lab"
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        if not self.scenario_id or not self.layer or not self.fault_type:
            raise ValueError("scenario_id, layer, and fault_type are required")

    def to_dict(self) -> Dict[str, Any]:
        self.validate()
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ScenarioSpec":
        item = cls(**dict(data))
        item.validate()
        return item


def load_scenario_catalog(path: str | Path) -> List[ScenarioSpec]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    rows = payload.get("scenarios") if isinstance(payload, dict) else payload
    if not isinstance(rows, list):
        raise ValueError("scenario catalog must contain a scenarios list")
    items = [ScenarioSpec.from_dict(row) for row in rows]
    identifiers = [item.scenario_id for item in items]
    if len(set(identifiers)) != len(identifiers):
        raise ValueError("scenario catalog contains duplicate scenario_id values")
    return items


def _command_version(command: Sequence[str]) -> str:
    try:
        completed = subprocess.run(
            list(command), capture_output=True, text=True, timeout=3, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    text = (completed.stdout or completed.stderr).strip().splitlines()
    return text[0] if text else ""


def capture_environment(*, labels: Optional[Mapping[str, str]] = None) -> Dict[str, Any]:
    try:
        package_version = importlib.metadata.version("kansoku")
    except importlib.metadata.PackageNotFoundError:
        from . import __version__
        package_version = __version__
    git_commit = _command_version(["git", "rev-parse", "HEAD"])
    git_dirty = ""
    if git_commit:
        try:
            completed = subprocess.run(
                ["git", "status", "--porcelain"], capture_output=True,
                text=True, timeout=3, check=False,
            )
            git_dirty = str(bool(completed.stdout.strip())).lower()
        except (OSError, subprocess.SubprocessError):
            git_dirty = ""
    return {
        "captured_at": utc_now(),
        "kansoku_version": package_version,
        "python": sys.version.split()[0],
        "python_implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "hostname": platform.node(),
        "cpu_count": os.cpu_count(),
        "git_commit": git_commit,
        "git_dirty": git_dirty,
        "docker": _command_version(["docker", "--version"]),
        "containerlab": _command_version(["containerlab", "version"]),
        "labels": dict(labels or {}),
    }


def write_environment_manifest(
    output: str | Path, *, labels: Optional[Mapping[str, str]] = None,
) -> Path:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(capture_environment(labels=labels), ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


def _percentile(values: Sequence[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(float(item) for item in values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * percentile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    fraction = position - lower
    return ordered[lower] * (1.0 - fraction) + ordered[upper] * fraction


def _numeric_summary(values: Iterable[float]) -> Dict[str, Any]:
    rows = [float(item) for item in values]
    if not rows:
        return {"count": 0, "min": None, "max": None, "mean": None, "median": None, "p95": None}
    return {
        "count": len(rows),
        "min": min(rows),
        "max": max(rows),
        "mean": statistics.fmean(rows),
        "median": statistics.median(rows),
        "p95": _percentile(rows, 0.95),
    }


def _accuracy(pairs: Iterable[tuple[str, str]]) -> Dict[str, Any]:
    rows = [(expected, observed) for expected, observed in pairs if expected and observed]
    correct = sum(1 for expected, observed in rows if expected == observed)
    return {
        "evaluated": len(rows),
        "correct": correct,
        "accuracy": (correct / len(rows)) if rows else None,
    }


def summarize_trials(
    experiment: ExperimentDefinition,
    trials: Sequence[ExperimentTrial],
) -> Dict[str, Any]:
    experiment.validate()
    for item in trials:
        item.validate()
        if item.experiment_id != experiment.experiment_id:
            raise ValueError("trial belongs to a different experiment")

    counts = {status: sum(1 for item in trials if item.status == status) for status in sorted(TRIAL_STATUSES)}
    expected_recovery_rows = [item for item in trials if item.expected_recovery is not None]
    recovered_rows = [item for item in expected_recovery_rows if item.recovered is not None]
    recovery_correct = sum(item.recovered == item.expected_recovery for item in recovered_rows)

    timing_names = sorted({name for item in trials for name in item.timings_ms})
    counter_names = sorted({name for item in trials for name in item.counters})
    scenario_ids = sorted({item.scenario_id for item in trials})
    by_scenario: Dict[str, Any] = {}
    for scenario_id in scenario_ids:
        rows = [item for item in trials if item.scenario_id == scenario_id]
        by_scenario[scenario_id] = {
            "total": len(rows),
            "pass": sum(item.status == "PASS" for item in rows),
            "fail": sum(item.status == "FAIL" for item in rows),
            "error": sum(item.status == "ERROR" for item in rows),
            "verdict": _accuracy((item.expected_verdict, item.observed_verdict) for item in rows),
            "recommendation": _accuracy((item.expected_category, item.observed_category) for item in rows),
        }

    verdict_confusion: Dict[str, Dict[str, int]] = {}
    for item in trials:
        if item.expected_verdict and item.observed_verdict:
            verdict_confusion.setdefault(item.expected_verdict, {})
            verdict_confusion[item.expected_verdict][item.observed_verdict] = (
                verdict_confusion[item.expected_verdict].get(item.observed_verdict, 0) + 1
            )

    return {
        "schema_version": "1.0",
        "generated_at": utc_now(),
        "experiment": experiment.to_dict(),
        "trial_count": len(trials),
        "status_counts": counts,
        "pass_rate": (counts["PASS"] / len(trials)) if trials else None,
        "verdict": _accuracy((item.expected_verdict, item.observed_verdict) for item in trials),
        "recommendation": _accuracy((item.expected_category, item.observed_category) for item in trials),
        "recovery": {
            "evaluated": len(recovered_rows),
            "correct": recovery_correct,
            "accuracy": (recovery_correct / len(recovered_rows)) if recovered_rows else None,
        },
        "timings_ms": {
            name: _numeric_summary(item.timings_ms[name] for item in trials if name in item.timings_ms)
            for name in timing_names
        },
        "counters": {
            name: _numeric_summary(item.counters[name] for item in trials if name in item.counters)
            for name in counter_names
        },
        "verdict_confusion": verdict_confusion,
        "by_scenario": by_scenario,
    }


def export_experiment(
    experiment: ExperimentDefinition,
    trials: Sequence[ExperimentTrial],
    *,
    output_dir: str | Path,
) -> Dict[str, Path]:
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    definition_path = destination / "experiment.json"
    trials_json_path = destination / "trials.json"
    trials_csv_path = destination / "trials.csv"
    summary_path = destination / "summary.json"

    definition_path.write_text(
        json.dumps(experiment.to_dict(), ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    trials_json_path.write_text(
        json.dumps([item.to_dict() for item in trials], ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    summary_path.write_text(
        json.dumps(summarize_trials(experiment, trials), ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    fields = [
        "trial_id", "experiment_id", "scenario_id", "repetition", "seed", "status",
        "expected_verdict", "observed_verdict", "expected_category", "observed_category",
        "expected_recovery", "recovered", "diagnosis_ms", "recommendation_ms",
        "recovery_ms", "total_ms", "observation_bytes", "packet_count", "flow_count",
        "started_at", "finished_at", "error", "artifacts_json", "metadata_json",
    ]
    with trials_csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for item in trials:
            writer.writerow({
                "trial_id": item.trial_id,
                "experiment_id": item.experiment_id,
                "scenario_id": item.scenario_id,
                "repetition": item.repetition,
                "seed": item.seed,
                "status": item.status,
                "expected_verdict": item.expected_verdict,
                "observed_verdict": item.observed_verdict,
                "expected_category": item.expected_category,
                "observed_category": item.observed_category,
                "expected_recovery": item.expected_recovery,
                "recovered": item.recovered,
                "diagnosis_ms": item.timings_ms.get("diagnosis"),
                "recommendation_ms": item.timings_ms.get("recommendation"),
                "recovery_ms": item.timings_ms.get("recovery"),
                "total_ms": item.timings_ms.get("total"),
                "observation_bytes": item.counters.get("observation_bytes"),
                "packet_count": item.counters.get("packet_count"),
                "flow_count": item.counters.get("flow_count"),
                "started_at": item.started_at,
                "finished_at": item.finished_at,
                "error": item.error,
                "artifacts_json": json.dumps(item.artifacts, ensure_ascii=False, sort_keys=True),
                "metadata_json": json.dumps(item.metadata, ensure_ascii=False, sort_keys=True),
            })
    return {
        "experiment": definition_path,
        "trials_json": trials_json_path,
        "trials_csv": trials_csv_path,
        "summary": summary_path,
    }


def _dominant_verdict(verdicts: Mapping[str, Any]) -> str:
    if not verdicts:
        return ""
    return max(verdicts.items(), key=lambda pair: (int(pair[1]), pair[0]))[0]


def import_lab_summary(
    path: str | Path,
    *,
    experiment_id: str,
    repetition: int = 1,
    seed: int = 1,
    environment: Optional[Mapping[str, Any]] = None,
) -> List[ExperimentTrial]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    rows = payload.get("scenarios", [])
    if not isinstance(rows, list):
        raise ValueError("lab summary scenarios must be a list")
    imported: List[ExperimentTrial] = []
    expected_categories = {
        "firewall-deny": "FIREWALL_POLICY",
        "route-missing": "ROUTE",
        "vlan-mismatch": "VLAN",
    }
    for raw in rows:
        if not isinstance(raw, dict):
            continue
        target = str(raw.get("target") or "")
        scenario = str(raw.get("scenario") or "")
        if not scenario and target.startswith("lab-"):
            scenario = target[4:]
        if raw.get("execution_id"):
            base = scenario or "remediation"
            verification = raw.get("verification") if isinstance(raw.get("verification"), dict) else {}
            rollback_verification = (
                raw.get("rollback_verification")
                if isinstance(raw.get("rollback_verification"), dict)
                else {}
            )
            status = str(raw.get("status") or "ERROR")
            recovered = bool(verification.get("observed_success"))
            rollback_ok = bool(rollback_verification.get("passed")) if rollback_verification else True
            imported.append(ExperimentTrial(
                experiment_id=experiment_id,
                scenario_id=f"{base}-remediation" if not base.endswith("-remediation") else base,
                repetition=repetition,
                seed=seed,
                status="PASS" if status in {"VERIFIED", "ROLLED_BACK"} and recovered and rollback_ok else "FAIL",
                expected_verdict="ALLOW",
                observed_verdict="ALLOW" if recovered else "",
                expected_category=expected_categories.get(base.replace("-remediation", ""), ""),
                observed_category=str(raw.get("category") or ""),
                expected_recovery=True,
                recovered=recovered,
                timings_ms={
                    "recovery": float(verification.get("duration_ms") or 0.0),
                    "total": sum(
                        float(item.get("duration_ms") or 0.0)
                        for item in (raw.get("apply_results") or []) + (raw.get("rollback_results") or [])
                        if isinstance(item, dict)
                    ) + float(verification.get("duration_ms") or 0.0)
                    + float(rollback_verification.get("duration_ms") or 0.0),
                },
                artifacts={"lab_summary": str(path)},
                environment=dict(environment or {}),
                metadata={
                    "source": "kansoku-lab-summary",
                    "execution_id": raw.get("execution_id"),
                    "rollback_verified": rollback_ok,
                },
            ))
            continue
        if raw.get("recommendation_id"):
            base = scenario or "recommendation"
            imported.append(ExperimentTrial(
                experiment_id=experiment_id,
                scenario_id=f"{base}-recommendation",
                repetition=repetition,
                seed=seed,
                status="PASS" if raw.get("simulation_status") == "PASSED" else "FAIL",
                expected_verdict="ALLOW",
                observed_verdict=str(raw.get("simulated_verdict") or ""),
                expected_category=expected_categories.get(base, ""),
                observed_category=str(raw.get("category") or ""),
                artifacts={"lab_summary": str(path)},
                environment=dict(environment or {}),
                metadata={"source": "kansoku-lab-summary", "recommendation_id": raw.get("recommendation_id")},
            ))
            continue
        if not scenario:
            continue
        verdicts = raw.get("verdicts") if isinstance(raw.get("verdicts"), dict) else {}
        expected = str(raw.get("expected") or ("ALLOW" if scenario == "normal" else ""))
        observed = _dominant_verdict(verdicts)
        expected_recovery: Optional[bool] = None
        recovered: Optional[bool] = None
        if scenario == "packet-loss":
            expected_recovery = True
            recovered = raw.get("status") == "PASS"
        imported.append(ExperimentTrial(
            experiment_id=experiment_id,
            scenario_id=scenario,
            repetition=repetition,
            seed=seed,
            status=str(raw.get("status") or "ERROR"),
            expected_verdict=expected,
            observed_verdict=observed,
            expected_recovery=expected_recovery,
            recovered=recovered,
            counters={
                mapped: float(raw[source])
                for source, mapped in (("packets", "packet_count"), ("flows", "flow_count"))
                if isinstance(raw.get(source), (int, float))
            },
            artifacts={"lab_summary": str(path)},
            environment=dict(environment or {}),
            metadata={"source": "kansoku-lab-summary", "raw": raw},
        ))
    return imported
