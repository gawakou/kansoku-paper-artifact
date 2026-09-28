from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import json
import uuid


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


class Domain(str, Enum):
    NETWORK = "network"
    SYSTEM = "system"
    SERVICE = "service"
    PHYSICAL = "physical"
    MQTT = "mqtt"
    WIFI = "wifi"
    STARLINK = "starlink"
    RACK = "rack"


class OperationalState(str, Enum):
    NORMAL = "NORMAL"
    WARNING = "WARNING"
    DEGRADED = "DEGRADED"
    CRITICAL = "CRITICAL"


class ControlMode(str, Enum):
    NORMAL_OPERATION = "NORMAL_OPERATION"
    DEGRADED_OPERATION = "DEGRADED_OPERATION"
    RECOVERY = "RECOVERY"
    SAFE_HOLD = "SAFE_HOLD"
    MANUAL_OPERATION = "MANUAL_OPERATION"


class GuardStatus(str, Enum):
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class ApprovalStatus(str, Enum):
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class ActionStatus(str, Enum):
    DRY_RUN = "DRY_RUN"
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


class VerificationStatus(str, Enum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"
    SKIPPED = "SKIPPED"


class TransactionOutcome(str, Enum):
    WAITING_APPROVAL = "WAITING_APPROVAL"
    REJECTED = "REJECTED"
    DRY_RUN = "DRY_RUN"
    VERIFIED = "VERIFIED"
    INCONCLUSIVE = "INCONCLUSIVE"
    ROLLED_BACK = "ROLLED_BACK"
    FAILED = "FAILED"


@dataclass
class Observation:
    target: str
    domain: str
    metric: str
    value: float
    unit: str
    source: str = "unknown"
    method: str = "unknown"
    observation_id: str = field(default_factory=lambda: new_id("obs"))
    timestamp: str = field(default_factory=utc_now)
    quality: Dict[str, Any] = field(default_factory=lambda: {"confidence": 1.0, "missing": False})
    labels: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Observation":
        return cls(**data)


@dataclass
class CollectionRun:
    """One invocation of an observation command, including its raw evidence."""

    agent: str
    target: str
    source: str
    command: List[str]
    returncode: int
    stdout: str = ""
    stderr: str = ""
    started_at: str = field(default_factory=utc_now)
    finished_at: str = field(default_factory=utc_now)
    metadata: Dict[str, Any] = field(default_factory=dict)
    run_id: str = field(default_factory=lambda: new_id("run"))

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CollectionRun":
        return cls(**data)


@dataclass
class CollectionResult:
    observations: List[Observation]
    run: CollectionRun


@dataclass
class StateEstimate:
    target: str
    state: str
    confidence: float
    evidence: List[str]
    reason: str
    control_mode: str
    state_id: str = field(default_factory=lambda: new_id("state"))
    timestamp: str = field(default_factory=utc_now)
    features: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "StateEstimate":
        return cls(**data)


@dataclass
class ActionProposal:
    target: str
    action: str
    parameters: Dict[str, Any]
    expected_effect: str
    rollback: Optional[Dict[str, Any]]
    source_state_id: str
    proposal_id: str = field(default_factory=lambda: new_id("action"))
    timestamp: str = field(default_factory=utc_now)
    risk_level: str = "low"
    preconditions: List[str] = field(default_factory=list)
    postconditions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ActionProposal":
        return cls(**data)


@dataclass
class GuardDecision:
    proposal_id: str
    status: str
    reasons: List[str]
    policy_version: str = "kansoku-guard-policy-v0.4"
    policy_id: Optional[str] = None
    decision_id: str = field(default_factory=lambda: new_id("guard"))
    timestamp: str = field(default_factory=utc_now)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GuardDecision":
        return cls(**data)


@dataclass
class ApprovalRecord:
    proposal_id: str
    status: str
    actor: str
    comment: str = ""
    approval_id: str = field(default_factory=lambda: new_id("approval"))
    timestamp: str = field(default_factory=utc_now)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ApprovalRecord":
        return cls(**data)


@dataclass
class ActionResult:
    proposal_id: str
    status: str
    command: str
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    adapter: str = "unknown"
    is_rollback: bool = False
    result_id: str = field(default_factory=lambda: new_id("result"))
    timestamp: str = field(default_factory=utc_now)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ActionResult":
        # v0.1-v0.3 payloads do not contain these fields.
        payload = {"adapter": "legacy", "is_rollback": False, **data}
        return cls(**payload)


@dataclass
class VerificationResult:
    proposal_id: str
    action_result_id: str
    status: str
    reason: str
    checks: List[Dict[str, Any]] = field(default_factory=list)
    verification_id: str = field(default_factory=lambda: new_id("verify"))
    timestamp: str = field(default_factory=utc_now)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "VerificationResult":
        return cls(**data)


@dataclass
class ControlTransaction:
    target: str
    proposal_id: str
    outcome: str
    guard_decision_id: Optional[str] = None
    approval_id: Optional[str] = None
    action_result_id: Optional[str] = None
    verification_id: Optional[str] = None
    rollback_result_id: Optional[str] = None
    message: str = ""
    transaction_id: str = field(default_factory=lambda: new_id("txn"))
    timestamp: str = field(default_factory=utc_now)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ControlTransaction":
        return cls(**data)


def dumps(data: Dict[str, Any]) -> str:
    return json.dumps(data, ensure_ascii=False, sort_keys=True)


def loads(data: str) -> Dict[str, Any]:
    return json.loads(data)
