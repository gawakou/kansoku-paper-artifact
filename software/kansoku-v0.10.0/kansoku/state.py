from __future__ import annotations

from statistics import mean
from typing import Dict, List, Optional, Tuple

from .models import (
    ActionProposal,
    ControlMode,
    Observation,
    OperationalState,
    StateEstimate,
)
from .profiles import TargetProfile


class RuleBasedStateEngine:
    """Explainable state estimation with target-relative evaluation.

    A target profile takes precedence for RTT/loss thresholds and enables
    throughput evaluation relative to an expected or learned baseline.  Without
    a profile, the v0.2 absolute thresholds remain active for compatibility.
    """

    def __init__(self, profile: Optional[TargetProfile] = None):
        self.profile = profile
        self.absolute_thresholds = {
            "rtt_warning_ms": 80.0,
            "rtt_degraded_ms": 120.0,
            "rtt_critical_ms": 300.0,
            "loss_warning_pct": 1.0,
            "loss_degraded_pct": 4.0,
            "loss_critical_pct": 15.0,
            "throughput_warning_mbps": 600.0,
            "throughput_degraded_mbps": 300.0,
            "throughput_critical_mbps": 80.0,
        }

    def estimate(self, target: str, observations: List[Observation]) -> StateEstimate:
        if not observations:
            return StateEstimate(
                target=target,
                state=OperationalState.CRITICAL.value,
                control_mode=ControlMode.SAFE_HOLD.value,
                confidence=0.5,
                evidence=[],
                reason="No observations are available for the target.",
                features={
                    "observation_count": 0,
                    "profile_mode": "relative" if self.profile else "absolute_fallback",
                },
            )

        features = self._extract_features(observations)
        score, reasons = self._score(features)

        if score >= 6:
            state = OperationalState.CRITICAL
            mode = ControlMode.SAFE_HOLD
            confidence = 0.92
        elif score >= 3:
            state = OperationalState.DEGRADED
            mode = ControlMode.DEGRADED_OPERATION
            confidence = 0.88
        elif score >= 1:
            state = OperationalState.WARNING
            mode = ControlMode.NORMAL_OPERATION
            confidence = 0.80
        else:
            state = OperationalState.NORMAL
            mode = ControlMode.NORMAL_OPERATION
            confidence = 0.88
            reasons = [self._normal_reason(features)]

        evidence = [obs.observation_id for obs in observations[-10:]]
        features["observation_count"] = len(observations)
        features["risk_score"] = score
        self._attach_profile_features(features)

        return StateEstimate(
            target=target,
            state=state.value,
            control_mode=mode.value,
            confidence=confidence,
            evidence=evidence,
            reason="; ".join(reasons),
            features=features,
        )

    def propose_action(
        self,
        state: StateEstimate,
        previous_state: Optional[StateEstimate] = None,
    ) -> Optional[ActionProposal]:
        normal_interval = self.profile.normal_interval_sec if self.profile else 30
        warning_interval = self.profile.warning_interval_sec if self.profile else 5

        if state.state == OperationalState.NORMAL.value:
            if previous_state and previous_state.state != OperationalState.NORMAL.value:
                return ActionProposal(
                    target=state.target,
                    action="restore_observation_rate",
                    parameters={"interval_sec": normal_interval},
                    expected_effect="Return observation frequency to the normal profile interval.",
                    rollback={
                        "action": "increase_observation_rate",
                        "parameters": {"interval_sec": warning_interval},
                    },
                    source_state_id=state.state_id,
                    risk_level="low",
                    preconditions=["target has returned to NORMAL"],
                    postconditions=[f"observation interval becomes {normal_interval} seconds"],
                )
            return None

        if state.state == OperationalState.WARNING.value:
            return ActionProposal(
                target=state.target,
                action="increase_observation_rate",
                parameters={"interval_sec": warning_interval},
                expected_effect="Increase visibility before applying network control changes.",
                rollback={
                    "action": "restore_observation_rate",
                    "parameters": {"interval_sec": normal_interval},
                },
                source_state_id=state.state_id,
                risk_level="low",
                preconditions=["target is observable"],
                postconditions=[f"new observations arrive within {max(10, warning_interval * 2)} seconds"],
            )

        if state.state == OperationalState.DEGRADED.value:
            return ActionProposal(
                target=state.target,
                action="switch_route",
                parameters={"route": "secondary", "dry_run_default": True},
                expected_effect="Move traffic away from the degraded path.",
                rollback={"action": "switch_route", "parameters": {"route": "primary"}},
                source_state_id=state.state_id,
                risk_level="medium",
                preconditions=["secondary route is configured", "rollback route is defined"],
                postconditions=["packet_loss_pct decreases", "rtt_ms does not increase"],
            )

        return ActionProposal(
            target=state.target,
            action="safe_hold",
            parameters={"reason": state.reason},
            expected_effect="Prevent unsafe automated changes and require human review.",
            rollback={"action": "manual_release", "parameters": {}},
            source_state_id=state.state_id,
            risk_level="high",
            preconditions=["operator notification channel is available"],
            postconditions=["operator receives state summary"],
        )

    def _extract_features(self, observations: List[Observation]) -> Dict[str, float]:
        by_metric: Dict[str, List[float]] = {}
        for obs in observations:
            by_metric.setdefault(obs.metric, []).append(float(obs.value))

        features: Dict[str, float] = {}
        mappings = {
            "rtt_ms": "rtt_ms",
            "packet_loss_pct": "packet_loss_pct",
            "throughput_mbps": "throughput_mbps",
        }
        for metric, suffix in mappings.items():
            if metric in by_metric:
                features[f"avg_{suffix}"] = mean(by_metric[metric])
                features[f"latest_{suffix}"] = by_metric[metric][-1]
        if "reachability" in by_metric:
            features["latest_reachability"] = by_metric["reachability"][-1]
        if "retransmits" in by_metric:
            features["latest_retransmits"] = by_metric["retransmits"][-1]
        return features

    def _threshold(self, name: str) -> float:
        if self.profile and hasattr(self.profile, name):
            return float(getattr(self.profile, name))
        return float(self.absolute_thresholds[name])

    def _score(self, features: Dict[str, float]) -> Tuple[int, List[str]]:
        score = 0
        reasons: List[str] = []

        rtt = features.get("latest_rtt_ms")
        if rtt is not None:
            if rtt >= self._threshold("rtt_critical_ms"):
                score += 6 if self.profile else 4
                reasons.append(f"RTT is critical: latest_rtt_ms={rtt:.1f}")
            elif rtt >= self._threshold("rtt_degraded_ms"):
                score += 3 if self.profile else 2
                reasons.append(f"RTT is degraded: latest_rtt_ms={rtt:.1f}")
            elif rtt >= self._threshold("rtt_warning_ms"):
                score += 1
                reasons.append(f"RTT is elevated: latest_rtt_ms={rtt:.1f}")

        loss = features.get("latest_packet_loss_pct")
        if loss is not None:
            if loss >= self._threshold("loss_critical_pct"):
                score += 6 if self.profile else 4
                reasons.append(f"Packet loss is critical: latest_packet_loss_pct={loss:.1f}")
            elif loss >= self._threshold("loss_degraded_pct"):
                score += 3 if self.profile else 2
                reasons.append(f"Packet loss is degraded: latest_packet_loss_pct={loss:.1f}")
            elif loss >= self._threshold("loss_warning_pct"):
                score += 1
                reasons.append(f"Packet loss is elevated: latest_packet_loss_pct={loss:.1f}")

        throughput = features.get("latest_throughput_mbps")
        reference = self.profile.throughput_reference_mbps if self.profile else None
        if throughput is not None and reference:
            ratio = throughput / reference
            features["throughput_ratio"] = ratio
            features["throughput_reference_mbps"] = reference
            if ratio < self.profile.throughput_degraded_ratio:
                score += 6
                reasons.append(
                    f"Throughput is critical: {throughput:.1f} Mbps is {ratio:.1%} of "
                    f"the {reference:.1f} Mbps {self.profile.throughput_reference_source}"
                )
            elif ratio < self.profile.throughput_warning_ratio:
                score += 3
                reasons.append(
                    f"Throughput is degraded: {throughput:.1f} Mbps is {ratio:.1%} of "
                    f"the {reference:.1f} Mbps {self.profile.throughput_reference_source}"
                )
            elif ratio < self.profile.throughput_normal_ratio:
                score += 1
                reasons.append(
                    f"Throughput is below the normal ratio: {throughput:.1f} Mbps is {ratio:.1%} of "
                    f"the {reference:.1f} Mbps {self.profile.throughput_reference_source}"
                )
        elif throughput is not None:
            # v0.2-compatible absolute fallback.
            if throughput <= self.absolute_thresholds["throughput_critical_mbps"]:
                score += 4
                reasons.append(f"Throughput is critical: latest_throughput_mbps={throughput:.1f}")
            elif throughput <= self.absolute_thresholds["throughput_degraded_mbps"]:
                score += 2
                reasons.append(f"Throughput is degraded: latest_throughput_mbps={throughput:.1f}")
            elif throughput <= self.absolute_thresholds["throughput_warning_mbps"]:
                score += 1
                reasons.append(f"Throughput is reduced: latest_throughput_mbps={throughput:.1f}")

        if features.get("latest_reachability") == 0.0:
            score += 6
            reasons.append("Target is unreachable.")

        return score, reasons

    def _normal_reason(self, features: Dict[str, float]) -> str:
        ratio = features.get("throughput_ratio")
        if self.profile and ratio is not None:
            return (
                f"RTT and packet loss are within profile thresholds; throughput is "
                f"{ratio:.1%} of the configured reference."
            )
        if self.profile:
            return "Observed metrics are within the target profile thresholds."
        return "RTT, packet loss, and throughput are within v0.2 absolute fallback thresholds."

    def _attach_profile_features(self, features: Dict[str, object]) -> None:
        if not self.profile:
            features["profile_mode"] = "absolute_fallback"
            features["profile_name"] = None
            return
        features["profile_mode"] = (
            "relative" if self.profile.throughput_reference_mbps is not None else "profile_thresholds"
        )
        features["profile_name"] = self.profile.name
        features["profile_id"] = self.profile.profile_id
        features["throughput_reference_source"] = self.profile.throughput_reference_source
