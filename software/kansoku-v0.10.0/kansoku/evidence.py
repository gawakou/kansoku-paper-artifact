from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

from .capture import FlowRecord
from .models import new_id, utc_now
from .network_state import FlowAssessment, NetworkInterface, PolicyRule, RouteEntry, VlanRecord


SUPPORTED_NODE_TYPES = {
    "FLOW", "ASSESSMENT", "DEVICE", "ROUTE", "POLICY_RULE", "VLAN",
    "INTERFACE", "EVIDENCE_GAP",
}
SUPPORTED_RELATIONS = {
    "ASSESSES", "OBSERVED_ON", "ROUTED_BY", "MATCHED_BY", "TAGGED_WITH",
    "LOCATED_ON", "ENTERS_VIA", "EXITS_VIA", "MISSING", "SUPPORTS",
}


@dataclass
class EvidenceNode:
    node_type: str
    label: str
    source_id: str = ""
    confidence: float = 1.0
    attributes: Dict[str, Any] = field(default_factory=dict)
    node_id: str = field(default_factory=lambda: new_id("evidence-node"))

    def validate(self) -> None:
        if self.node_type not in SUPPORTED_NODE_TYPES:
            raise ValueError(f"unsupported evidence node type: {self.node_type}")
        if not self.label.strip():
            raise ValueError("evidence node label is required")
        if not 0.0 <= float(self.confidence) <= 1.0:
            raise ValueError("evidence node confidence must be between 0 and 1")

    def to_dict(self) -> Dict[str, Any]:
        self.validate()
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "EvidenceNode":
        item = cls(**{"attributes": {}, **dict(data)})
        item.validate()
        return item


@dataclass
class EvidenceEdge:
    source_node_id: str
    target_node_id: str
    relation: str
    confidence: float = 1.0
    attributes: Dict[str, Any] = field(default_factory=dict)
    edge_id: str = field(default_factory=lambda: new_id("evidence-edge"))

    def validate(self) -> None:
        if not self.source_node_id or not self.target_node_id:
            raise ValueError("evidence edge endpoints are required")
        if self.relation not in SUPPORTED_RELATIONS:
            raise ValueError(f"unsupported evidence relation: {self.relation}")
        if not 0.0 <= float(self.confidence) <= 1.0:
            raise ValueError("evidence edge confidence must be between 0 and 1")

    def to_dict(self) -> Dict[str, Any]:
        self.validate()
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "EvidenceEdge":
        item = cls(**{"attributes": {}, **dict(data)})
        item.validate()
        return item


@dataclass
class EvidenceGraph:
    assessment_id: str
    flow_id: str
    nodes: List[EvidenceNode]
    edges: List[EvidenceEdge]
    graph_id: str = field(default_factory=lambda: new_id("evidence-graph"))
    generated_at: str = field(default_factory=utc_now)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        if not self.assessment_id or not self.flow_id:
            raise ValueError("assessment_id and flow_id are required")
        identifiers = [item.node_id for item in self.nodes]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("evidence graph contains duplicate node identifiers")
        known = set(identifiers)
        for node in self.nodes:
            node.validate()
        for edge in self.edges:
            edge.validate()
            if edge.source_node_id not in known or edge.target_node_id not in known:
                raise ValueError("evidence edge references an unknown node")

    def to_dict(self) -> Dict[str, Any]:
        self.validate()
        return {
            "graph_id": self.graph_id,
            "assessment_id": self.assessment_id,
            "flow_id": self.flow_id,
            "generated_at": self.generated_at,
            "nodes": [item.to_dict() for item in self.nodes],
            "edges": [item.to_dict() for item in self.edges],
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "EvidenceGraph":
        payload = dict(data)
        payload["nodes"] = [EvidenceNode.from_dict(item) for item in payload.get("nodes", [])]
        payload["edges"] = [EvidenceEdge.from_dict(item) for item in payload.get("edges", [])]
        payload.setdefault("metadata", {})
        item = cls(**payload)
        item.validate()
        return item

    @property
    def evidence_coverage(self) -> float:
        expected = int(self.metadata.get("expected_evidence_slots") or 0)
        observed = int(self.metadata.get("observed_evidence_slots") or 0)
        if expected <= 0:
            return 0.0
        return max(0.0, min(1.0, observed / expected))

    def to_dot(self) -> str:
        self.validate()
        lines = ["digraph kansoku_evidence {", "  rankdir=LR;", "  node [shape=box];"]
        for node in self.nodes:
            label = f"{node.node_type}\\n{node.label}".replace('"', r'\"')
            style = "dashed" if node.node_type == "EVIDENCE_GAP" else "solid"
            lines.append(f'  "{node.node_id}" [label="{label}", style="{style}"];')
        for edge in self.edges:
            relation = edge.relation.replace('"', r'\"')
            lines.append(
                f'  "{edge.source_node_id}" -> "{edge.target_node_id}" '
                f'[label="{relation}"];'
            )
        lines.append("}")
        return "\n".join(lines) + "\n"


def _find_by_id(rows: Iterable[Any], attribute: str, identifier: Optional[str]) -> Optional[Any]:
    if not identifier:
        return None
    return next((item for item in rows if getattr(item, attribute, None) == identifier), None)


def build_evidence_graph(
    assessment: FlowAssessment,
    flow: FlowRecord,
    *,
    routes: Sequence[RouteEntry] = (),
    policies: Sequence[PolicyRule] = (),
    vlans: Sequence[VlanRecord] = (),
    interfaces: Sequence[NetworkInterface] = (),
) -> EvidenceGraph:
    if assessment.flow_id != flow.flow_id:
        raise ValueError("assessment and flow do not match")

    nodes: List[EvidenceNode] = []
    edges: List[EvidenceEdge] = []
    index: Dict[str, EvidenceNode] = {}

    def add_node(key: str, node_type: str, label: str, *, source_id: str = "", confidence: float = 1.0,
                 attributes: Optional[Dict[str, Any]] = None) -> EvidenceNode:
        if key in index:
            return index[key]
        node = EvidenceNode(
            node_id=key,
            node_type=node_type,
            label=label,
            source_id=source_id,
            confidence=confidence,
            attributes=dict(attributes or {}),
        )
        nodes.append(node)
        index[key] = node
        return node

    def add_edge(source: EvidenceNode, target: EvidenceNode, relation: str, *, confidence: float = 1.0,
                 attributes: Optional[Dict[str, Any]] = None) -> None:
        edges.append(EvidenceEdge(
            source_node_id=source.node_id,
            target_node_id=target.node_id,
            relation=relation,
            confidence=confidence,
            attributes=dict(attributes or {}),
        ))

    flow_node = add_node(
        f"flow:{flow.flow_id}", "FLOW",
        f"{flow.protocol} {flow.src_ip}:{flow.src_port or '*'} → {flow.dst_ip}:{flow.dst_port or '*'}",
        source_id=flow.flow_id,
        attributes=flow.to_dict(),
    )
    assessment_node = add_node(
        f"assessment:{assessment.assessment_id}", "ASSESSMENT",
        f"{assessment.verdict}: {assessment.reason or 'no reason recorded'}",
        source_id=assessment.assessment_id,
        attributes=assessment.to_dict(),
    )
    add_edge(assessment_node, flow_node, "ASSESSES")

    route_device = str(assessment.evidence.get("route_device") or assessment.ingress_device_id)
    policy_device = str(assessment.evidence.get("policy_device") or assessment.ingress_device_id)
    vlan_device = str(assessment.evidence.get("vlan_device") or assessment.ingress_device_id)
    devices: Dict[str, EvidenceNode] = {}
    for device_id, role in ((route_device, "route"), (policy_device, "policy"), (vlan_device, "vlan")):
        if not device_id:
            continue
        devices[device_id] = add_node(
            f"device:{device_id}", "DEVICE", device_id, source_id=device_id,
            attributes={"roles": sorted({role})},
        )
        roles = set(devices[device_id].attributes.get("roles", []))
        roles.add(role)
        devices[device_id].attributes["roles"] = sorted(roles)

    expected_slots = 4  # flow, assessment, route, policy
    observed_slots = 2

    route = _find_by_id(routes, "route_id", assessment.route_id)
    if route:
        route_node = add_node(
            f"route:{route.route_id}", "ROUTE", f"{route.prefix} via {route.next_hop or route.interface}",
            source_id=route.route_id, attributes=route.to_dict(),
        )
        add_edge(flow_node, route_node, "ROUTED_BY")
        if route.device_id in devices:
            add_edge(route_node, devices[route.device_id], "LOCATED_ON")
        observed_slots += 1
    else:
        gap = add_node(
            "gap:route", "EVIDENCE_GAP", "No installed matching route",
            confidence=1.0 if assessment.route_status == "NO_ROUTE" else 0.65,
            attributes={"route_status": assessment.route_status, "destination": flow.dst_ip},
        )
        add_edge(flow_node, gap, "MISSING")
        if assessment.route_status == "NO_ROUTE":
            observed_slots += 1

    rule = _find_by_id(policies, "rule_id", assessment.matched_rule_id)
    if rule:
        rule_node = add_node(
            f"policy:{rule.rule_id}", "POLICY_RULE",
            f"{rule.action} {rule.protocol} {rule.src_network or '*'} → {rule.dst_network or '*'}",
            source_id=rule.rule_id, attributes=rule.to_dict(),
        )
        add_edge(flow_node, rule_node, "MATCHED_BY")
        if rule.device_id in devices:
            add_edge(rule_node, devices[rule.device_id], "LOCATED_ON")
        observed_slots += 1
    else:
        gap = add_node(
            "gap:policy", "EVIDENCE_GAP", "No conclusive matching policy rule",
            confidence=0.85 if assessment.policy_status == "NO_MATCH" else 0.6,
            attributes={"policy_status": assessment.policy_status},
        )
        add_edge(flow_node, gap, "MISSING")
        if assessment.policy_status == "NO_MATCH":
            observed_slots += 1

    if flow.vlan_id is not None:
        expected_slots += 1
        vlan = next((item for item in vlans if item.vlan_id == flow.vlan_id), None)
        if vlan:
            vlan_node = add_node(
                f"vlan:{vlan.device_id}:{vlan.vlan_id}", "VLAN", f"VLAN {vlan.vlan_id}",
                source_id=vlan.record_id, attributes=vlan.to_dict(),
            )
            add_edge(flow_node, vlan_node, "TAGGED_WITH")
            if vlan.device_id in devices:
                add_edge(vlan_node, devices[vlan.device_id], "LOCATED_ON")
            observed_slots += 1
        else:
            gap = add_node(
                f"gap:vlan:{flow.vlan_id}", "EVIDENCE_GAP", f"VLAN {flow.vlan_id} absent from imported state",
                confidence=1.0 if assessment.vlan_status == "UNKNOWN_VLAN" else 0.65,
                attributes={"vlan_id": flow.vlan_id, "vlan_status": assessment.vlan_status},
            )
            add_edge(flow_node, gap, "MISSING")
            if assessment.vlan_status == "UNKNOWN_VLAN":
                observed_slots += 1

    in_name = str(assessment.evidence.get("in_interface") or "")
    out_name = str(assessment.evidence.get("out_interface") or "")
    for interface, relation in ((in_name, "ENTERS_VIA"), (out_name, "EXITS_VIA")):
        if not interface:
            continue
        item = next((row for row in interfaces if row.name == interface), None)
        device_id = item.device_id if item else assessment.ingress_device_id
        interface_node = add_node(
            f"interface:{device_id}:{interface}", "INTERFACE", f"{device_id}:{interface}",
            source_id=item.interface_id if item else "",
            confidence=1.0 if item else 0.6,
            attributes=item.to_dict() if item else {"device_id": device_id, "name": interface},
        )
        add_edge(flow_node, interface_node, relation, confidence=interface_node.confidence)
        if device_id in devices:
            add_edge(interface_node, devices[device_id], "LOCATED_ON")

    graph = EvidenceGraph(
        assessment_id=assessment.assessment_id,
        flow_id=flow.flow_id,
        nodes=nodes,
        edges=edges,
        metadata={
            "verdict": assessment.verdict,
            "expected_evidence_slots": expected_slots,
            "observed_evidence_slots": observed_slots,
            "evidence_coverage": observed_slots / expected_slots,
            "source_devices": {
                "route_device": route_device,
                "policy_device": policy_device,
                "vlan_device": vlan_device,
            },
        },
    )
    graph.validate()
    return graph


def export_evidence_graph(graph: EvidenceGraph, *, output: str | Path, format_name: str = "json") -> Path:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    if format_name == "json":
        content = json.dumps(graph.to_dict(), ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    elif format_name == "dot":
        content = graph.to_dot()
    else:
        raise ValueError(f"unsupported evidence graph format: {format_name}")
    path.write_text(content, encoding="utf-8")
    return path
