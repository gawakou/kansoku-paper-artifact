from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .models import new_id


def parse_time(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


@dataclass
class SchedulerCycle:
    target: str
    owner_id: str
    status: str
    started_at: str
    finished_at: str
    collection_run_ids: List[str] = field(default_factory=list)
    observation_count: int = 0
    state_id: Optional[str] = None
    proposal_id: Optional[str] = None
    transaction_id: Optional[str] = None
    message: str = ""
    cycle_id: str = field(default_factory=lambda: new_id("cycle"))

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SchedulerCycle":
        return cls(**data)


@dataclass
class SchedulerLease:
    name: str
    owner_id: str
    acquired_at: str
    expires_at: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SchedulerLease":
        return cls(**data)


@dataclass
class DueStatus:
    target: str
    enabled: bool
    interval_sec: int
    last_finished_at: Optional[str]
    next_due_at: Optional[str]
    due: bool

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

