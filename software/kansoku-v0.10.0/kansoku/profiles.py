from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
from statistics import median
from typing import Any, Dict, Iterable, Optional

from .models import Observation, new_id, utc_now


@dataclass
class TargetProfile:
    """Target-specific expectations used by the state engine.

    Throughput is evaluated relative to ``baseline_throughput_mbps`` when it is
    available, otherwise relative to ``expected_bandwidth_mbps``.  If neither
    value is set, KANSOKU falls back to the v0.2 absolute thresholds.
    """

    target: str
    name: str = "default"
    expected_bandwidth_mbps: Optional[float] = None
    baseline_throughput_mbps: Optional[float] = None

    throughput_normal_ratio: float = 0.85
    throughput_warning_ratio: float = 0.70
    throughput_degraded_ratio: float = 0.40

    rtt_warning_ms: float = 80.0
    rtt_degraded_ms: float = 120.0
    rtt_critical_ms: float = 300.0
    loss_warning_pct: float = 1.0
    loss_degraded_pct: float = 4.0
    loss_critical_pct: float = 15.0

    normal_interval_sec: int = 30
    warning_interval_sec: int = 5

    profile_id: str = field(default_factory=lambda: new_id("profile"))
    updated_at: str = field(default_factory=utc_now)
    source: str = "user"

    def validate(self) -> None:
        if not self.target.strip():
            raise ValueError("target must not be empty")
        for name in ("expected_bandwidth_mbps", "baseline_throughput_mbps"):
            value = getattr(self, name)
            if value is not None and value <= 0:
                raise ValueError(f"{name} must be greater than zero")
        ratios = (
            self.throughput_normal_ratio,
            self.throughput_warning_ratio,
            self.throughput_degraded_ratio,
        )
        if not (1.0 >= ratios[0] > ratios[1] > ratios[2] >= 0.0):
            raise ValueError(
                "throughput ratios must satisfy 1 >= normal > warning > degraded >= 0"
            )
        if not (0 <= self.rtt_warning_ms < self.rtt_degraded_ms < self.rtt_critical_ms):
            raise ValueError("RTT thresholds must be strictly increasing")
        if not (0 <= self.loss_warning_pct < self.loss_degraded_pct < self.loss_critical_pct):
            raise ValueError("packet-loss thresholds must be strictly increasing")
        if self.normal_interval_sec <= 0 or self.warning_interval_sec <= 0:
            raise ValueError("observation intervals must be greater than zero")

    @property
    def throughput_reference_mbps(self) -> Optional[float]:
        return self.baseline_throughput_mbps or self.expected_bandwidth_mbps

    @property
    def throughput_reference_source(self) -> Optional[str]:
        if self.baseline_throughput_mbps is not None:
            return "baseline"
        if self.expected_bandwidth_mbps is not None:
            return "expected_bandwidth"
        return None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TargetProfile":
        profile = cls(**data)
        profile.validate()
        return profile

    def updated(self, **changes: Any) -> "TargetProfile":
        result = replace(self, **changes, updated_at=utc_now())
        result.validate()
        return result


@dataclass
class ObservationPlan:
    target: str
    interval_sec: int
    mode: str = "normal"
    reason: str = "profile default"
    source_proposal_id: Optional[str] = None
    plan_id: str = field(default_factory=lambda: new_id("plan"))
    updated_at: str = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        if self.interval_sec <= 0:
            raise ValueError("interval_sec must be greater than zero")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ObservationPlan":
        return cls(**data)


def learn_throughput_baseline(
    target: str,
    observations: Iterable[Observation],
    *,
    minimum_samples: int = 1,
) -> float:
    values = [
        float(obs.value)
        for obs in observations
        if obs.target == target and obs.metric == "throughput_mbps" and float(obs.value) > 0
    ]
    if len(values) < minimum_samples:
        raise ValueError(
            f"at least {minimum_samples} throughput observations are required; found {len(values)}"
        )
    # Median is intentionally robust against one-off outliers and failed runs.
    return float(median(values))
