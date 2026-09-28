from __future__ import annotations

from dataclasses import asdict, dataclass, field
import ipaddress
import json
from pathlib import Path
import shlex
from typing import Any, Dict, Iterable, List, Optional, Sequence

from .capture import FlowRecord
from .models import new_id, utc_now
from .network_state import (
    FlowAssessment,
    NetworkInterface,
    PolicyRule,
    RouteEntry,
    VlanRecord,
    correlate_flow,
)


SUPPORTED_CATEGORIES = {"FIREWALL_POLICY", "ROUTE", "VLAN", "MANUAL_REVIEW"}
SUPPORTED_STATUSES = {"DRAFT", "REVIEWED", "REJECTED", "APPROVED"}
SIMULATION_STATUSES = {"PASSED", "FAILED", "INCONCLUSIVE", "NOT_RUN"}


def approval_issues(item: "ConfigurationRecommendation") -> List[str]:
    """Return reasons an item cannot cross the explicit lab-approval boundary."""
    issues: List[str] = []
    if item.category == "MANUAL_REVIEW":
        issues.append("MANUAL_REVIEW is not executable")
    if item.simulation_status != "PASSED" or item.simulated_verdict != "ALLOW":
        issues.append("a PASSED what-if result with ALLOW verdict is required")
    if any("<" in command and ">" in command for command in item.commands):
        issues.append("apply commands contain unresolved placeholders")
    return issues


def require_approval_eligible(item: "ConfigurationRecommendation") -> None:
    issues = approval_issues(item)
    if issues:
        raise ValueError("approval refused: " + "; ".join(issues))


@dataclass
class ConfigurationRecommendation:
    assessment_id: str
    flow_id: str
    capture_id: str
    target: str
    device_id: str
    category: str
    intent: str
    platform: str
    risk_level: str
    confidence: float
    summary: str
    rationale: str
    current_state: Dict[str, Any]
    desired_state: Dict[str, Any]
    commands: List[str]
    rollback_commands: List[str]
    preconditions: List[str]
    postconditions: List[str]
    impact: Dict[str, Any]
    simulation_status: str = "NOT_RUN"
    simulated_verdict: str = ""
    status: str = "DRAFT"
    recommendation_id: str = field(default_factory=lambda: new_id("recommendation"))
    generated_at: str = field(default_factory=utc_now)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        if not self.assessment_id or not self.flow_id or not self.target:
            raise ValueError("assessment_id, flow_id, and target are required")
        if self.category not in SUPPORTED_CATEGORIES:
            raise ValueError(f"unsupported recommendation category: {self.category}")
        if self.status not in SUPPORTED_STATUSES:
            raise ValueError(f"unsupported recommendation status: {self.status}")
        if self.simulation_status not in SIMULATION_STATUSES:
            raise ValueError(f"unsupported simulation status: {self.simulation_status}")
        if self.risk_level not in {"low", "medium", "high"}:
            raise ValueError("risk_level must be low, medium, or high")
        if not 0.0 <= float(self.confidence) <= 1.0:
            raise ValueError("confidence must be between 0 and 1")
        if self.category != "MANUAL_REVIEW" and not self.commands:
            raise ValueError("an actionable recommendation requires at least one command template")
        if self.commands and not self.rollback_commands:
            raise ValueError("actionable recommendations require rollback command templates")

    def to_dict(self) -> Dict[str, Any]:
        self.validate()
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ConfigurationRecommendation":
        defaults = {
            "current_state": {}, "desired_state": {}, "commands": [],
            "rollback_commands": [], "preconditions": [], "postconditions": [],
            "impact": {}, "metadata": {},
        }
        item = cls(**{**defaults, **data})
        item.validate()
        return item

    def to_markdown(self) -> str:
        self.validate()
        lines = [
            f"# Configuration Recommendation {self.recommendation_id}",
            "",
            f"- Status: `{self.status}`",
            f"- Category: `{self.category}`",
            f"- Device: `{self.device_id}` (`{self.platform}`)",
            f"- Risk: `{self.risk_level}`",
            f"- Confidence: `{self.confidence:.2f}`",
            f"- Simulation: `{self.simulation_status}` → `{self.simulated_verdict or '—'}`",
            f"- Assessment: `{self.assessment_id}`",
            "",
            "## Summary",
            "",
            self.summary,
            "",
            "## Rationale",
            "",
            self.rationale,
            "",
            "## Current state",
            "",
            "```json",
            json.dumps(self.current_state, ensure_ascii=False, indent=2, sort_keys=True),
            "```",
            "",
            "## Desired state",
            "",
            "```json",
            json.dumps(self.desired_state, ensure_ascii=False, indent=2, sort_keys=True),
            "```",
            "",
            "## Candidate commands",
            "",
            "```bash",
            *self.commands,
            "```",
            "",
            "## Rollback commands",
            "",
            "```bash",
            *self.rollback_commands,
            "```",
            "",
            "## Preconditions",
            "",
            *[f"- {item}" for item in self.preconditions],
            "",
            "## Postconditions",
            "",
            *[f"- {item}" for item in self.postconditions],
            "",
            "## Impact",
            "",
            "```json",
            json.dumps(self.impact, ensure_ascii=False, indent=2, sort_keys=True),
            "```",
            "",
            "> This is a reviewable plan. KANSOKU v0.10.0 never applies changes automatically or to production devices; explicit approval is required for virtual-lab execution.",
            "",
        ]
        return "\n".join(lines)


def _q(value: str) -> str:
    return shlex.quote(str(value))


def _host_prefix(address: str) -> str:
    ip = ipaddress.ip_address(address)
    return f"{ip}/{32 if ip.version == 4 else 128}"


def _flow_match(flow: FlowRecord) -> Dict[str, Any]:
    return {
        "src_ip": flow.src_ip,
        "dst_ip": flow.dst_ip,
        "protocol": flow.protocol.upper(),
        "src_port": flow.src_port,
        "dst_port": flow.dst_port,
        "vlan_id": flow.vlan_id,
    }


def _find_rule(rules: Sequence[PolicyRule], rule_id: Optional[str]) -> Optional[PolicyRule]:
    return next((item for item in rules if item.rule_id == rule_id), None)


def _find_interface(interfaces: Sequence[NetworkInterface], name: str) -> Optional[NetworkInterface]:
    return next((item for item in interfaces if item.name == name), None)


def _nft_address_tokens(flow: FlowRecord) -> List[str]:
    family = "ip6" if flow.ip_version == 6 else "ip"
    tokens = [family, "saddr", flow.src_ip, family, "daddr", flow.dst_ip]
    proto = flow.protocol.lower()
    if proto in {"tcp", "udp"}:
        tokens.extend([proto])
        if flow.dst_port is not None:
            tokens.extend(["dport", str(flow.dst_port)])
    return tokens


def _simulate(
    assessment: FlowAssessment,
    flow: FlowRecord,
    *,
    routes: Sequence[RouteEntry],
    policies: Sequence[PolicyRule],
    vlans: Sequence[VlanRecord],
    category: str,
    synthetic_route: Optional[RouteEntry] = None,
    synthetic_policy: Optional[PolicyRule] = None,
    synthetic_vlan: Optional[VlanRecord] = None,
) -> tuple[str, str, Dict[str, Any]]:
    trial_routes = list(routes)
    trial_policies = list(policies)
    trial_vlans = list(vlans)
    if synthetic_route:
        trial_routes.append(synthetic_route)
    if synthetic_policy:
        trial_policies.append(synthetic_policy)
    if synthetic_vlan:
        trial_vlans.append(synthetic_vlan)
    trial = correlate_flow(
        flow,
        ingress_device_id=assessment.ingress_device_id,
        routes=trial_routes,
        rules=trial_policies,
        vlans=trial_vlans,
        vrf=str(assessment.evidence.get("vrf") or "default"),
        in_interface=str(assessment.evidence.get("in_interface") or ""),
    )
    status = "PASSED" if trial.verdict == "ALLOW" else "FAILED"
    return status, trial.verdict, {
        "category": category,
        "before_verdict": assessment.verdict,
        "after_verdict": trial.verdict,
        "after_reason": trial.reason,
    }


class RecommendationEngine:
    """Generate reviewable, vendor-neutral configuration change plans.

    The engine never executes commands.  It produces narrow command templates,
    rollback templates, impact notes, and a model-level what-if result.
    """

    def generate(
        self,
        assessment: FlowAssessment,
        flow: FlowRecord,
        *,
        routes: Sequence[RouteEntry] = (),
        policies: Sequence[PolicyRule] = (),
        vlans: Sequence[VlanRecord] = (),
        interfaces: Sequence[NetworkInterface] = (),
        route_device_id: str = "",
        policy_device_id: str = "",
        vlan_device_id: str = "",
        destination_prefix: str = "",
        next_hop: str = "",
        out_interface: str = "",
        access_interface: str = "",
        trunk_interface: str = "",
    ) -> ConfigurationRecommendation:
        if assessment.flow_id != flow.flow_id:
            raise ValueError("assessment and flow do not match")
        if assessment.verdict == "DENY":
            return self._firewall(
                assessment, flow, policies=policies,
                device_id=policy_device_id or assessment.ingress_device_id,
                routes=routes, vlans=vlans,
            )
        if assessment.verdict == "UNROUTABLE":
            return self._route(
                assessment, flow, routes=routes, policies=policies, vlans=vlans,
                device_id=route_device_id or assessment.ingress_device_id,
                destination_prefix=destination_prefix, next_hop=next_hop,
                out_interface=out_interface,
            )
        if assessment.vlan_status == "UNKNOWN_VLAN":
            return self._vlan(
                assessment, flow, routes=routes, policies=policies, vlans=vlans,
                interfaces=interfaces,
                device_id=vlan_device_id or assessment.ingress_device_id,
                access_interface=access_interface,
                trunk_interface=trunk_interface,
            )
        return self._manual_review(assessment, flow)

    def generate_candidates(
        self,
        assessment: FlowAssessment,
        flow: FlowRecord,
        *,
        routes: Sequence[RouteEntry] = (),
        policies: Sequence[PolicyRule] = (),
        vlans: Sequence[VlanRecord] = (),
        interfaces: Sequence[NetworkInterface] = (),
        route_device_id: str = "",
        policy_device_id: str = "",
        vlan_device_id: str = "",
        destination_prefix: str = "",
        next_hop: str = "",
        out_interface: str = "",
        access_interface: str = "",
        trunk_interface: str = "",
    ) -> List[ConfigurationRecommendation]:
        """Generate a compact alternative set for ranking and human review.

        The set always includes the narrow primary candidate and an observation-only
        manual-review option. Route and VLAN assessments may include additional
        narrower or partial alternatives. All command-bearing candidates remain
        review-only until explicitly approved for the virtual-lab executor.
        """
        primary = self.generate(
            assessment,
            flow,
            routes=routes,
            policies=policies,
            vlans=vlans,
            interfaces=interfaces,
            route_device_id=route_device_id,
            policy_device_id=policy_device_id,
            vlan_device_id=vlan_device_id,
            destination_prefix=destination_prefix,
            next_hop=next_hop,
            out_interface=out_interface,
            access_interface=access_interface,
            trunk_interface=trunk_interface,
        )
        if primary.category == "MANUAL_REVIEW":
            return [primary]
        candidates: List[ConfigurationRecommendation] = [primary]

        if primary.category == "FIREWALL_POLICY" and flow.dst_port is not None:
            broader = ConfigurationRecommendation.from_dict(primary.to_dict())
            broader.recommendation_id = new_id("recommendation")
            broader.risk_level = "high"
            broader.confidence = max(0.0, primary.confidence - 0.18)
            broader.summary = (
                f"Allow the observed {flow.protocol} host pair without restricting the destination service."
            )
            broader.rationale = (
                "This alternative may restore the flow when the service port is dynamic, "
                "but it has a larger security impact than the host-and-service-specific candidate."
            )
            broader.commands = [
                command.replace(
                    f" {flow.protocol.lower()} dport {flow.dst_port}",
                    f" meta l4proto {flow.protocol.lower()}",
                )
                for command in primary.commands
            ]
            rule = dict(broader.desired_state.get("rule") or {})
            rule["dst_port"] = None
            broader.desired_state = {**broader.desired_state, "rule": rule}
            synthetic = PolicyRule.from_dict(rule)
            broader.simulation_status, broader.simulated_verdict, broad_sim = _simulate(
                assessment, flow, routes=routes, policies=policies, vlans=vlans,
                category="FIREWALL_POLICY", synthetic_policy=synthetic,
            )
            broader.impact = {
                **broader.impact,
                "scope": "single observed source/destination pair for all ports of the protocol",
                "broader_than_primary": True,
            }
            broader.metadata = {
                **broader.metadata,
                "candidate_variant": "host-pair-protocol",
                "what_if": broad_sim,
                "simulation_model_limitation": (
                    "The what-if model confirms the observed flow only; the broader rule may allow "
                    "additional services and therefore requires explicit security review."
                ),
            }
            broader.validate()
            candidates.append(broader)

        if primary.category == "ROUTE" and destination_prefix:
            host_prefix = _host_prefix(flow.dst_ip)
            supplied = str(ipaddress.ip_network(destination_prefix, strict=False))
            if supplied != host_prefix:
                host_route = self._route(
                    assessment,
                    flow,
                    routes=routes,
                    policies=policies,
                    vlans=vlans,
                    device_id=route_device_id or assessment.ingress_device_id,
                    destination_prefix=host_prefix,
                    next_hop=next_hop,
                    out_interface=out_interface,
                )
                host_route.summary = f"Add a host route for the observed destination {flow.dst_ip}."
                host_route.rationale += " A host route minimizes the affected destination scope."
                host_route.metadata = {**host_route.metadata, "candidate_variant": "host-route"}
                candidates.append(host_route)

        if primary.category == "VLAN" and access_interface and trunk_interface:
            access_only = self._vlan(
                assessment,
                flow,
                routes=routes,
                policies=policies,
                vlans=vlans,
                interfaces=interfaces,
                device_id=vlan_device_id or assessment.ingress_device_id,
                access_interface=access_interface,
                trunk_interface="",
            )
            access_only.confidence = max(0.0, access_only.confidence - 0.15)
            access_only.summary = f"Restore VLAN {flow.vlan_id} only on access port {access_interface}."
            access_only.metadata = {
                **access_only.metadata,
                "candidate_variant": "access-only",
                "simulation_model_limitation": "The normalized VLAN model does not prove trunk continuity.",
            }
            access_only.validate()
            candidates.append(access_only)

            trunk_only = self._vlan(
                assessment,
                flow,
                routes=routes,
                policies=policies,
                vlans=vlans,
                interfaces=interfaces,
                device_id=vlan_device_id or assessment.ingress_device_id,
                access_interface="",
                trunk_interface=trunk_interface,
            )
            trunk_only.confidence = max(0.0, trunk_only.confidence - 0.15)
            trunk_only.summary = f"Restore VLAN {flow.vlan_id} only on trunk port {trunk_interface}."
            trunk_only.metadata = {
                **trunk_only.metadata,
                "candidate_variant": "trunk-only",
                "simulation_model_limitation": "The normalized VLAN model does not prove access-port membership.",
            }
            trunk_only.validate()
            candidates.append(trunk_only)

        manual = self._manual_review(assessment, flow)
        manual.metadata = {
            **manual.metadata,
            "candidate_variant": "observation-only",
            "alternative_to": [item.recommendation_id for item in candidates],
        }
        candidates.append(manual)
        return candidates

    def _firewall(
        self,
        assessment: FlowAssessment,
        flow: FlowRecord,
        *,
        policies: Sequence[PolicyRule],
        routes: Sequence[RouteEntry],
        vlans: Sequence[VlanRecord],
        device_id: str,
    ) -> ConfigurationRecommendation:
        matched = _find_rule(policies, assessment.matched_rule_id)
        table = matched.table if matched else "filter"
        chain = matched.chain if matched else "forward"
        priority = max(0, (matched.priority if matched else 1) - 1)
        synthetic = PolicyRule(
            device_id=device_id,
            policy_type="firewall",
            table=table,
            chain=chain,
            action="ALLOW",
            priority=priority,
            protocol=flow.protocol,
            src_network=_host_prefix(flow.src_ip),
            dst_network=_host_prefix(flow.dst_ip),
            src_port=None,
            dst_port=str(flow.dst_port) if flow.dst_port is not None else None,
            comment="KANSOKU narrow exception candidate",
        )
        tokens = [
            "nft", "insert", "rule", "inet", table, chain,
            *_nft_address_tokens(flow), "counter", "accept", "comment",
            f'"kansoku {assessment.assessment_id}"',
        ]
        command = " ".join(tokens)
        rollback = f"nft delete rule inet {_q(table)} {_q(chain)} handle <new-rule-handle>"
        simulation_status, simulated_verdict, sim = _simulate(
            assessment, flow, routes=routes, policies=policies, vlans=vlans,
            category="FIREWALL_POLICY", synthetic_policy=synthetic,
        )
        confidence = 0.9 if matched else 0.72
        item = ConfigurationRecommendation(
            assessment_id=assessment.assessment_id,
            flow_id=flow.flow_id,
            capture_id=flow.capture_id,
            target=flow.target,
            device_id=device_id,
            category="FIREWALL_POLICY",
            intent="ALLOW_OBSERVED_FLOW",
            platform="nftables",
            risk_level="medium",
            confidence=confidence,
            summary=f"Insert a narrow allow rule before the denying rule for {flow.protocol} {flow.dst_ip}:{flow.dst_port or '*'}.",
            rationale=(
                f"The observed flow was denied by {assessment.matched_rule_id or 'a policy rule'}. "
                "A host- and service-specific exception minimizes the change scope; an operator must confirm the communication intent."
            ),
            current_state={
                "assessment": assessment.to_dict(),
                "matched_rule": matched.to_dict() if matched else None,
                "flow": _flow_match(flow),
            },
            desired_state={"rule": synthetic.to_dict(), "expected_verdict": "ALLOW"},
            commands=[command],
            rollback_commands=[rollback],
            preconditions=[
                "Confirm that the source, destination, protocol, and service are authorized by policy.",
                "Record the new nftables rule handle immediately after insertion.",
                "Ensure an out-of-band management path is available.",
            ],
            postconditions=[
                "The target flow is observed across the firewall and completes successfully.",
                "Unrelated denied traffic remains denied.",
                "Firewall counters and system load remain within expected bounds.",
            ],
            impact={
                "scope": "single observed source/destination/service tuple",
                "matched_flow": _flow_match(flow),
                "requires_human_policy_confirmation": True,
            },
            simulation_status=simulation_status,
            simulated_verdict=simulated_verdict,
            metadata={"what_if": sim, "requires_runtime_handle_capture": True},
        )
        item.validate()
        return item

    def _route(
        self,
        assessment: FlowAssessment,
        flow: FlowRecord,
        *,
        routes: Sequence[RouteEntry],
        policies: Sequence[PolicyRule],
        vlans: Sequence[VlanRecord],
        device_id: str,
        destination_prefix: str,
        next_hop: str,
        out_interface: str,
    ) -> ConfigurationRecommendation:
        prefix = str(ipaddress.ip_network(destination_prefix or _host_prefix(flow.dst_ip), strict=False))
        complete = bool(next_hop or out_interface)
        command_tail = " ".join(part for part in (prefix, next_hop, out_interface) if part)
        if not complete:
            command_tail = f"{prefix} <next-hop-or-interface>"
        command = f'vtysh -c "configure terminal" -c "ip route {command_tail}"'
        rollback = f'vtysh -c "configure terminal" -c "no ip route {command_tail}"'
        synthetic: Optional[RouteEntry] = None
        if complete:
            synthetic = RouteEntry(
                device_id=device_id,
                prefix=prefix,
                protocol="static",
                next_hop=next_hop,
                interface=out_interface,
                selected=True,
                installed=True,
            )
            simulation_status, simulated_verdict, sim = _simulate(
                assessment, flow, routes=routes, policies=policies, vlans=vlans,
                category="ROUTE", synthetic_route=synthetic,
            )
        else:
            simulation_status, simulated_verdict = "INCONCLUSIVE", assessment.verdict
            sim = {
                "category": "ROUTE",
                "before_verdict": assessment.verdict,
                "after_verdict": "NOT_SIMULATED",
                "missing_inputs": ["next_hop or out_interface"],
            }
        item = ConfigurationRecommendation(
            assessment_id=assessment.assessment_id,
            flow_id=flow.flow_id,
            capture_id=flow.capture_id,
            target=flow.target,
            device_id=device_id,
            category="ROUTE",
            intent="RESTORE_DESTINATION_REACHABILITY",
            platform="frr",
            risk_level="medium",
            confidence=0.88 if complete else 0.55,
            summary=f"Add a route for {prefix} on {device_id}.",
            rationale=(
                "No installed data-plane route matched the observed destination. "
                "The candidate is deliberately limited to the supplied destination prefix."
            ),
            current_state={"assessment": assessment.to_dict(), "flow": _flow_match(flow), "matching_route": None},
            desired_state={
                "route": synthetic.to_dict() if synthetic else {
                    "device_id": device_id, "prefix": prefix,
                    "next_hop": next_hop or "<required>",
                    "interface": out_interface or "<optional>",
                },
                "expected_verdict": "ALLOW",
            },
            commands=[command],
            rollback_commands=[rollback],
            preconditions=[
                "Confirm the destination prefix and next hop against the intended topology.",
                "Verify that the next hop is reachable through the selected interface.",
                "Check for overlapping or more-specific routes and routing-policy conflicts.",
            ],
            postconditions=[
                f"{flow.dst_ip} resolves to the intended data-plane route.",
                "End-to-end reachability and the target service succeed.",
                "No unintended destination prefixes change path.",
            ],
            impact={
                "scope": prefix,
                "next_hop": next_hop or None,
                "out_interface": out_interface or None,
                "requires_missing_input_resolution": not complete,
            },
            simulation_status=simulation_status,
            simulated_verdict=simulated_verdict,
            metadata={"what_if": sim},
        )
        item.validate()
        return item

    def _vlan(
        self,
        assessment: FlowAssessment,
        flow: FlowRecord,
        *,
        routes: Sequence[RouteEntry],
        policies: Sequence[PolicyRule],
        vlans: Sequence[VlanRecord],
        interfaces: Sequence[NetworkInterface],
        device_id: str,
        access_interface: str,
        trunk_interface: str,
    ) -> ConfigurationRecommendation:
        if flow.vlan_id is None:
            return self._manual_review(assessment, flow)
        vlan = int(flow.vlan_id)
        commands: List[str] = []
        rollback: List[str] = []
        current: Dict[str, Any] = {"known_vlans": [item.to_dict() for item in vlans]}
        if access_interface:
            commands.append(f"ovs-vsctl set Port {_q(access_interface)} tag={vlan}")
            existing = _find_interface(interfaces, access_interface)
            if existing and existing.access_vlan is not None:
                rollback.append(f"ovs-vsctl set Port {_q(access_interface)} tag={existing.access_vlan}")
            else:
                rollback.append(f"ovs-vsctl clear Port {_q(access_interface)} tag")
            current["access_interface"] = existing.to_dict() if existing else None
        if trunk_interface:
            commands.append(f"ovs-vsctl set Port {_q(trunk_interface)} trunks={vlan}")
            existing = _find_interface(interfaces, trunk_interface)
            if existing and existing.trunk_vlans:
                values = ",".join(str(item) for item in existing.trunk_vlans)
                rollback.append(f"ovs-vsctl set Port {_q(trunk_interface)} trunks={values}")
            else:
                rollback.append(f"ovs-vsctl clear Port {_q(trunk_interface)} trunks")
            current["trunk_interface"] = existing.to_dict() if existing else None
        if not commands:
            commands = ["ovs-vsctl set Port <affected-port> tag-or-trunks=<expected-vlan>"]
            rollback = ["ovs-vsctl restore Port <affected-port> <previous-vlan-state>"]
        synthetic = VlanRecord(device_id=device_id, vlan_id=vlan, name=f"VLAN {vlan}")
        simulation_status, simulated_verdict, sim = _simulate(
            assessment, flow, routes=routes, policies=policies, vlans=vlans,
            category="VLAN", synthetic_vlan=synthetic,
        )
        complete = bool(access_interface or trunk_interface)
        if not complete:
            simulation_status = "INCONCLUSIVE"
        item = ConfigurationRecommendation(
            assessment_id=assessment.assessment_id,
            flow_id=flow.flow_id,
            capture_id=flow.capture_id,
            target=flow.target,
            device_id=device_id,
            category="VLAN",
            intent="RESTORE_OBSERVED_VLAN_PATH",
            platform="openvswitch",
            risk_level="medium",
            confidence=0.86 if complete else 0.58,
            summary=f"Restore VLAN {vlan} membership on the affected Open vSwitch port or trunk.",
            rationale=(
                f"The captured flow carries VLAN {vlan}, but that VLAN was absent from the imported switch state. "
                "The affected ports must be confirmed before applying the candidate."
            ),
            current_state={"assessment": assessment.to_dict(), "flow": _flow_match(flow), **current},
            desired_state={
                "vlan_id": vlan,
                "access_interface": access_interface or "<confirm>",
                "trunk_interface": trunk_interface or "<confirm>",
                "expected_verdict": "ALLOW",
            },
            commands=commands,
            rollback_commands=rollback,
            preconditions=[
                "Confirm the intended access and trunk ports from the topology and cabling model.",
                "Check that restoring the VLAN will not bridge unrelated security zones.",
                "Capture the current OVS port configuration for rollback.",
            ],
            postconditions=[
                f"VLAN {vlan} is present on the intended access/trunk path.",
                "The target flow reaches the firewall and destination service.",
                "No unintended MAC learning or broadcast-domain expansion is observed.",
            ],
            impact={
                "scope": f"VLAN {vlan} on explicitly named ports" if complete else f"VLAN {vlan}; affected ports unresolved",
                "requires_port_confirmation": not complete,
            },
            simulation_status=simulation_status,
            simulated_verdict=simulated_verdict,
            metadata={"what_if": sim},
        )
        item.validate()
        return item

    def _manual_review(self, assessment: FlowAssessment, flow: FlowRecord) -> ConfigurationRecommendation:
        item = ConfigurationRecommendation(
            assessment_id=assessment.assessment_id,
            flow_id=flow.flow_id,
            capture_id=flow.capture_id,
            target=flow.target,
            device_id=assessment.ingress_device_id,
            category="MANUAL_REVIEW",
            intent="COLLECT_ADDITIONAL_EVIDENCE",
            platform="vendor-neutral",
            risk_level="low",
            confidence=0.4,
            summary="Collect additional route, policy, VLAN, and bidirectional flow evidence before proposing a configuration change.",
            rationale=f"The current assessment ({assessment.verdict}) does not map to a safely actionable configuration delta.",
            current_state={"assessment": assessment.to_dict(), "flow": _flow_match(flow)},
            desired_state={"expected_verdict": "DETERMINATE"},
            commands=[],
            rollback_commands=[],
            preconditions=[],
            postconditions=["A conclusive route, policy, or VLAN cause is identified."],
            impact={"scope": "observation only"},
            simulation_status="NOT_RUN",
            simulated_verdict=assessment.verdict,
        )
        item.validate()
        return item


def export_recommendation(
    recommendation: ConfigurationRecommendation,
    *,
    output: str | Path,
    format_name: str = "json",
) -> Path:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    if format_name == "json":
        content = json.dumps(recommendation.to_dict(), ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    elif format_name == "markdown":
        content = recommendation.to_markdown()
    else:
        raise ValueError(f"unsupported export format: {format_name}")
    path.write_text(content, encoding="utf-8")
    return path
