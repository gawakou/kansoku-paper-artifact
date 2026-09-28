from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
from typing import Any, Dict

from .models import new_id, utc_now


@dataclass
class ManagedTarget:
    """Persistent configuration for a target observed by the v0.5 service.

    The inventory deliberately stores only observation and orchestration settings.
    Evaluation thresholds remain in :class:`TargetProfile`, while action permissions
    remain in :class:`SafetyPolicy`.
    """

    target: str
    name: str
    enabled: bool = True
    ping_enabled: bool = True
    ping_count: int = 3
    ping_timeout_sec: float = 5.0
    iperf3_enabled: bool = False
    iperf3_port: int = 5201
    iperf3_duration_sec: int = 10
    iperf3_parallel: int = 1
    iperf3_every_n_cycles: int = 0
    auto_process_low_risk: bool = True
    raw_dir: str = "./artifacts/raw"
    target_id: str = field(default_factory=lambda: new_id("target"))
    updated_at: str = field(default_factory=utc_now)

    def validate(self) -> None:
        if not self.target.strip():
            raise ValueError("target must not be empty")
        if not self.name.strip():
            raise ValueError("name must not be empty")
        if self.ping_count < 1:
            raise ValueError("ping_count must be >= 1")
        if self.ping_timeout_sec <= 0:
            raise ValueError("ping_timeout_sec must be > 0")
        if not 1 <= self.iperf3_port <= 65535:
            raise ValueError("iperf3_port must be between 1 and 65535")
        if self.iperf3_duration_sec < 1:
            raise ValueError("iperf3_duration_sec must be >= 1")
        if self.iperf3_parallel < 1:
            raise ValueError("iperf3_parallel must be >= 1")
        if self.iperf3_every_n_cycles < 0:
            raise ValueError("iperf3_every_n_cycles must be >= 0")
        if self.iperf3_enabled and self.iperf3_every_n_cycles == 0:
            raise ValueError(
                "iperf3_every_n_cycles must be >= 1 when iperf3 is enabled"
            )

    def updated(self, **changes: Any) -> "ManagedTarget":
        item = replace(self, **changes, updated_at=utc_now())
        item.validate()
        return item

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ManagedTarget":
        return cls(**data)
