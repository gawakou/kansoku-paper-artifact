from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
from typing import Any, Dict, List, Optional

from .models import new_id, utc_now


DEFAULT_ALLOWED_ACTIONS = [
    "increase_observation_rate",
    "restore_observation_rate",
    "switch_route",
    "safe_hold",
    "manual_release",
    "tc_netem_apply",
    "tc_netem_clear",
]

DEFAULT_AUTO_APPROVE_ACTIONS = [
    "increase_observation_rate",
    "restore_observation_rate",
]

DEFAULT_APPROVAL_REQUIRED_ACTIONS = [
    "switch_route",
    "safe_hold",
    "manual_release",
    "tc_netem_apply",
    "tc_netem_clear",
]

DEFAULT_ROLLBACK_REQUIRED_ACTIONS = [
    "increase_observation_rate",
    "switch_route",
    "tc_netem_apply",
]


@dataclass
class SafetyPolicy:
    """Target-scoped safety policy for KANSOKU Guard and Controller.

    A policy with target ``*`` acts as the default policy.  Target-specific
    policies override it.  System-changing adapters remain disabled unless
    both the policy and the controller invocation explicitly permit them.
    """

    target: str = "*"
    name: str = "default safe policy"
    allowed_actions: List[str] = field(default_factory=lambda: list(DEFAULT_ALLOWED_ACTIONS))
    auto_approve_actions: List[str] = field(default_factory=lambda: list(DEFAULT_AUTO_APPROVE_ACTIONS))
    approval_required_actions: List[str] = field(
        default_factory=lambda: list(DEFAULT_APPROVAL_REQUIRED_ACTIONS)
    )
    rollback_required_actions: List[str] = field(
        default_factory=lambda: list(DEFAULT_ROLLBACK_REQUIRED_ACTIONS)
    )
    blocked_actions: List[str] = field(default_factory=list)
    blocked_targets: List[str] = field(default_factory=list)
    minimum_observation_interval_sec: int = 2
    allow_system_changes: bool = False
    rollback_on_verification_failure: bool = True
    policy_id: str = field(default_factory=lambda: new_id("policy"))
    updated_at: str = field(default_factory=utc_now)
    version: str = "kansoku-safety-policy-v0.4"

    def validate(self) -> None:
        if not self.target.strip():
            raise ValueError("policy target must not be empty")
        if self.minimum_observation_interval_sec <= 0:
            raise ValueError("minimum_observation_interval_sec must be greater than zero")
        allowed = set(self.allowed_actions)
        for name, values in {
            "auto_approve_actions": self.auto_approve_actions,
            "approval_required_actions": self.approval_required_actions,
            "rollback_required_actions": self.rollback_required_actions,
        }.items():
            unknown = set(values) - allowed
            if unknown:
                raise ValueError(f"{name} contains actions not present in allowed_actions: {sorted(unknown)}")
        overlap = set(self.auto_approve_actions) & set(self.approval_required_actions)
        if overlap:
            raise ValueError(
                "actions cannot be both auto-approved and approval-required: "
                f"{sorted(overlap)}"
            )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SafetyPolicy":
        policy = cls(**data)
        policy.validate()
        return policy

    def updated(self, **changes: Any) -> "SafetyPolicy":
        policy = replace(self, **changes, updated_at=utc_now())
        policy.validate()
        return policy

    @property
    def allowed_action_set(self) -> set[str]:
        return set(self.allowed_actions)

    @property
    def auto_approve_action_set(self) -> set[str]:
        return set(self.auto_approve_actions)

    @property
    def approval_required_action_set(self) -> set[str]:
        return set(self.approval_required_actions)

    @property
    def rollback_required_action_set(self) -> set[str]:
        return set(self.rollback_required_actions)



def parse_action_list(value: Optional[str], default: Optional[List[str]] = None) -> List[str]:
    if value is None:
        return list(default or [])
    return [item.strip() for item in value.split(",") if item.strip()]
