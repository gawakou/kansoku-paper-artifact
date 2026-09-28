from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import shlex
import subprocess
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .capture import FlowRecord
from .models import CollectionRun, new_id, utc_now


def _load_json(source: str | Path | Dict[str, Any] | List[Any]) -> Any:
    if isinstance(source, (dict, list)):
        return source
    return json.loads(Path(source).read_text(encoding="utf-8"))


def _sha256_json(value: Any) -> str:
    blob = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _as_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value).strip().lower() in {"1", "true", "yes", "up", "active", "enabled", "selected", "installed"}


def _normalize_action(value: str) -> str:
    text = value.upper().replace("-", "_")
    aliases = {"ACCEPT": "ALLOW", "PASS": "ALLOW", "DROP": "DENY", "REJECT": "DENY"}
    return aliases.get(text, text)


@dataclass
class NetworkDevice:
    device_id: str
    name: str
    device_type: str
    platform: str
    management_address: str = ""
    enabled: bool = True
    labels: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=utc_now)
    updated_at: str = field(default_factory=utc_now)

    def validate(self) -> None:
        if not self.device_id.strip():
            raise ValueError("device_id must not be empty")
        if not self.name.strip():
            raise ValueError("device name must not be empty")
        if self.device_type not in {"router", "l2_switch", "l3_switch", "firewall", "host", "generic"}:
            raise ValueError(f"unsupported device_type: {self.device_type}")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "NetworkDevice":
        item = cls(**{"labels": {}, "metadata": {}, **data})
        item.validate()
        return item

    def updated(self, **changes: Any) -> "NetworkDevice":
        item = replace(self, updated_at=utc_now(), **changes)
        item.validate()
        return item


@dataclass
class NetworkInterface:
    device_id: str
    name: str
    kind: str = "physical"
    admin_up: bool = True
    oper_up: bool = True
    mac_address: str = ""
    mtu: int = 1500
    addresses: List[str] = field(default_factory=list)
    vrf: str = "default"
    vlan_mode: str = "none"
    access_vlan: Optional[int] = None
    trunk_vlans: List[int] = field(default_factory=list)
    bridge: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    interface_id: str = field(default_factory=lambda: new_id("if"))
    observed_at: str = field(default_factory=utc_now)

    def validate(self) -> None:
        if not self.device_id or not self.name:
            raise ValueError("device_id and interface name are required")
        if self.mtu <= 0:
            raise ValueError("mtu must be positive")
        for address in self.addresses:
            ipaddress.ip_interface(address)
        for vlan in self.trunk_vlans:
            if not 1 <= int(vlan) <= 4094:
                raise ValueError(f"invalid VLAN: {vlan}")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "NetworkInterface":
        item = cls(**{"addresses": [], "trunk_vlans": [], "metadata": {}, **data})
        item.validate()
        return item


@dataclass
class VlanRecord:
    device_id: str
    vlan_id: int
    name: str = ""
    interfaces: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    record_id: str = field(default_factory=lambda: new_id("vlan"))
    observed_at: str = field(default_factory=utc_now)

    def validate(self) -> None:
        if not 1 <= int(self.vlan_id) <= 4094:
            raise ValueError("vlan_id must be between 1 and 4094")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "VlanRecord":
        item = cls(**{"interfaces": [], "metadata": {}, **data})
        item.validate()
        return item


@dataclass
class L2Link:
    device_a: str
    interface_a: str
    device_b: str
    interface_b: str
    status: str = "UP"
    discovery: str = "configured"
    metadata: Dict[str, Any] = field(default_factory=dict)
    link_id: str = field(default_factory=lambda: new_id("link"))
    observed_at: str = field(default_factory=utc_now)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "L2Link":
        return cls(**{"metadata": {}, **data})


@dataclass
class RouteEntry:
    device_id: str
    prefix: str
    protocol: str
    next_hop: str = ""
    interface: str = ""
    vrf: str = "default"
    address_family: str = "ipv4"
    metric: int = 0
    distance: int = 0
    selected: bool = True
    installed: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)
    route_id: str = field(default_factory=lambda: new_id("route"))
    observed_at: str = field(default_factory=utc_now)

    def validate(self) -> None:
        network = ipaddress.ip_network(self.prefix, strict=False)
        expected = "ipv6" if network.version == 6 else "ipv4"
        if self.address_family not in {"ipv4", "ipv6"}:
            self.address_family = expected

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RouteEntry":
        item = cls(**{"metadata": {}, **data})
        item.validate()
        return item


@dataclass
class PolicyRule:
    device_id: str
    policy_type: str
    table: str
    chain: str
    action: str
    family: str = "inet"
    priority: int = 0
    protocol: str = "ANY"
    src_network: str = ""
    dst_network: str = ""
    src_port: Optional[str] = None
    dst_port: Optional[str] = None
    in_interface: str = ""
    out_interface: str = ""
    state: List[str] = field(default_factory=list)
    comment: str = ""
    counters: Dict[str, int] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    rule_id: str = field(default_factory=lambda: new_id("rule"))
    observed_at: str = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        self.action = _normalize_action(self.action)
        self.protocol = self.protocol.upper()
        if self.src_network:
            ipaddress.ip_network(self.src_network, strict=False)
        if self.dst_network:
            ipaddress.ip_network(self.dst_network, strict=False)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PolicyRule":
        item = cls(**{"state": [], "counters": {}, "metadata": {}, **data})
        item.validate()
        return item


@dataclass
class NetworkSnapshot:
    device_id: str
    collector: str
    source: str
    status: str
    raw_sha256: str
    interface_count: int = 0
    vlan_count: int = 0
    link_count: int = 0
    route_count: int = 0
    policy_count: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)
    snapshot_id: str = field(default_factory=lambda: new_id("snapshot"))
    started_at: str = field(default_factory=utc_now)
    finished_at: str = field(default_factory=utc_now)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "NetworkSnapshot":
        return cls(**{"metadata": {}, **data})


@dataclass
class FlowAssessment:
    flow_id: str
    capture_id: str
    target: str
    ingress_device_id: str
    route_status: str
    policy_status: str
    verdict: str
    route_id: Optional[str] = None
    matched_rule_id: Optional[str] = None
    vlan_status: str = "NOT_APPLICABLE"
    reason: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    assessment_id: str = field(default_factory=lambda: new_id("assessment"))
    timestamp: str = field(default_factory=utc_now)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FlowAssessment":
        return cls(**{"evidence": {}, **data})


@dataclass
class NetworkImportResult:
    snapshot: NetworkSnapshot
    interfaces: List[NetworkInterface] = field(default_factory=list)
    vlans: List[VlanRecord] = field(default_factory=list)
    links: List[L2Link] = field(default_factory=list)
    routes: List[RouteEntry] = field(default_factory=list)
    policies: List[PolicyRule] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "snapshot": self.snapshot.to_dict(),
            "interfaces": [item.to_dict() for item in self.interfaces],
            "vlans": [item.to_dict() for item in self.vlans],
            "links": [item.to_dict() for item in self.links],
            "routes": [item.to_dict() for item in self.routes],
            "policies": [item.to_dict() for item in self.policies],
        }


def _snapshot(device_id: str, collector: str, source: str, raw: Any, result: NetworkImportResult | None = None) -> NetworkSnapshot:
    return NetworkSnapshot(
        device_id=device_id,
        collector=collector,
        source=source,
        status="COLLECTED",
        raw_sha256=_sha256_json(raw),
        interface_count=len(result.interfaces) if result else 0,
        vlan_count=len(result.vlans) if result else 0,
        link_count=len(result.links) if result else 0,
        route_count=len(result.routes) if result else 0,
        policy_count=len(result.policies) if result else 0,
    )


def filter_network_import(
    result: NetworkImportResult,
    *,
    exclude_interfaces: Sequence[str] = (),
    exclude_prefixes: Sequence[str] = (),
) -> NetworkImportResult:
    """Remove management-plane routes from a normalized import result.

    Containerized network devices commonly have an out-of-band management
    interface (typically ``eth0``) and a management default route. Those routes
    must not be used when correlating captured data-plane traffic. Filtering is
    explicit and recorded in snapshot metadata so the evidence remains auditable.
    """
    interface_set = {str(item).strip() for item in exclude_interfaces if str(item).strip()}
    prefix_set: set[str] = set()
    for prefix in exclude_prefixes:
        value = str(prefix).strip()
        if not value:
            continue
        prefix_set.add(str(ipaddress.ip_network(value, strict=False)))

    original = len(result.routes)
    result.routes = [
        route for route in result.routes
        if route.interface not in interface_set and route.prefix not in prefix_set
    ]
    excluded = original - len(result.routes)
    result.snapshot.route_count = len(result.routes)
    result.snapshot.metadata = {
        **result.snapshot.metadata,
        "route_filter": {
            "exclude_interfaces": sorted(interface_set),
            "exclude_prefixes": sorted(prefix_set),
            "excluded_route_count": excluded,
        },
    }
    return result


def parse_frr_json(source: str | Path | Dict[str, Any], *, device_id: str, source_name: str = "offline") -> NetworkImportResult:
    raw = _load_json(source)
    result = NetworkImportResult(snapshot=NetworkSnapshot(device_id=device_id, collector="frr", source=source_name, status="COLLECTING", raw_sha256=""))
    observed = utc_now()

    interfaces_raw: Any = {}
    route_only_raw: Any = raw
    if isinstance(raw, dict) and "interfaces" in raw:
        interfaces_raw = raw.get("interfaces", {})
        route_only_raw = raw.get("routes", {})
    elif isinstance(raw, dict) and raw and any(
        isinstance(item, dict) and ({"interfaceName", "flags", "mtu", "ipAddresses"} & set(item))
        for item in raw.values()
    ):
        # Native `show interface json` output is keyed directly by interface name.
        interfaces_raw = raw
        route_only_raw = {}

    if isinstance(interfaces_raw, list):
        interfaces_iter = [(str(item.get("name") or item.get("interfaceName")), item) for item in interfaces_raw]
    else:
        interfaces_iter = list(interfaces_raw.items())
    for name, item in interfaces_iter:
        if not isinstance(item, dict) or not name:
            continue
        flags = str(item.get("flags", "")).upper()
        addresses: List[str] = []
        for addr in item.get("ipAddresses", item.get("addresses", [])) or []:
            value = addr.get("address") if isinstance(addr, dict) else addr
            if value:
                addresses.append(str(value))
        result.interfaces.append(NetworkInterface(
            device_id=device_id,
            name=str(item.get("interfaceName") or name),
            kind="loopback" if str(name).lower().startswith("lo") else "physical",
            admin_up=_as_bool(item.get("adminUp"), "UP" in flags or True),
            oper_up=_as_bool(item.get("operUp"), "RUNNING" in flags or "UP" in flags),
            mac_address=str(item.get("hardwareAddress") or item.get("mac") or ""),
            mtu=int(item.get("mtu") or 1500),
            addresses=addresses,
            vrf=str(item.get("vrfName") or item.get("vrf") or "default"),
            metadata={"description": item.get("description", "")},
            observed_at=observed,
        ))

    routes_raw = route_only_raw if isinstance(route_only_raw, dict) else {}
    if isinstance(routes_raw, dict):
        for prefix, entries in routes_raw.items():
            try:
                network = ipaddress.ip_network(prefix, strict=False)
            except ValueError:
                continue
            if isinstance(entries, dict):
                entries = [entries]
            for entry in entries or []:
                if not isinstance(entry, dict):
                    continue
                nexthops = entry.get("nexthops") or [{}]
                if not isinstance(nexthops, list):
                    nexthops = [nexthops]
                for nh in nexthops or [{}]:
                    if not isinstance(nh, dict):
                        nh = {}
                    result.routes.append(RouteEntry(
                        device_id=device_id,
                        prefix=str(network),
                        protocol=str(entry.get("protocol") or entry.get("type") or "unknown").lower(),
                        next_hop=str(nh.get("ip") or nh.get("gateway") or ""),
                        interface=str(nh.get("interfaceName") or nh.get("interface") or entry.get("interface") or ""),
                        vrf=str(entry.get("vrfName") or entry.get("vrf") or "default"),
                        address_family="ipv6" if network.version == 6 else "ipv4",
                        metric=int(entry.get("metric") or 0),
                        distance=int(entry.get("distance") or entry.get("adminDistance") or 0),
                        selected=_as_bool(entry.get("selected"), True),
                        installed=_as_bool(entry.get("installed"), _as_bool(nh.get("active"), True)),
                        metadata={"tag": entry.get("tag"), "active": nh.get("active")},
                        observed_at=observed,
                    ))

    result.snapshot = _snapshot(device_id, "frr", source_name, raw, result)
    return result


def _ovs_value(value: Any) -> Any:
    if isinstance(value, list) and len(value) == 2 and value[0] == "set":
        return value[1]
    if isinstance(value, list) and len(value) == 2 and value[0] in {"uuid", "named-uuid"}:
        return value[1]
    return value


def parse_ovs_json(source: str | Path | Dict[str, Any], *, device_id: str, source_name: str = "offline") -> NetworkImportResult:
    raw = _load_json(source)
    result = NetworkImportResult(snapshot=NetworkSnapshot(device_id=device_id, collector="ovs", source=source_name, status="COLLECTING", raw_sha256=""))
    observed = utc_now()
    vlan_map: Dict[int, set[str]] = {}

    bridges = raw.get("bridges", []) if isinstance(raw, dict) else []
    for bridge in bridges:
        bridge_name = str(bridge.get("name") or "br0")
        for port in bridge.get("ports", []) or []:
            name = str(port.get("name") or "")
            if not name:
                continue
            tag = port.get("tag")
            trunks = [int(v) for v in (port.get("trunks") or [])]
            if tag is not None:
                tag = int(tag)
                vlan_map.setdefault(tag, set()).add(name)
            for vlan in trunks:
                vlan_map.setdefault(vlan, set()).add(name)
            interfaces = port.get("interfaces") or [{}]
            first = interfaces[0] if interfaces and isinstance(interfaces[0], dict) else {}
            result.interfaces.append(NetworkInterface(
                device_id=device_id,
                name=name,
                kind="bridge" if name == bridge_name else str(first.get("type") or "virtual"),
                admin_up=not _as_bool(port.get("disabled"), False),
                oper_up=str(first.get("link_state") or first.get("linkState") or "up").lower() != "down",
                mac_address=str(first.get("mac_in_use") or first.get("mac") or ""),
                mtu=int(first.get("mtu") or 1500),
                addresses=[str(x) for x in port.get("addresses", []) if "/" in str(x)],
                vlan_mode="access" if tag is not None else ("trunk" if trunks else "none"),
                access_vlan=tag,
                trunk_vlans=trunks,
                bridge=bridge_name,
                metadata={"ovs_interface_type": first.get("type", "system")},
                observed_at=observed,
            ))
            peer = port.get("peer")
            if isinstance(peer, dict) and peer.get("device") and peer.get("interface"):
                result.links.append(L2Link(
                    device_a=device_id,
                    interface_a=name,
                    device_b=str(peer["device"]),
                    interface_b=str(peer["interface"]),
                    status="UP" if result.interfaces[-1].oper_up else "DOWN",
                    discovery="ovs-peer",
                    observed_at=observed,
                ))

    # Accept ovs-vsctl --format=json table output for Port rows.
    if isinstance(raw, dict) and raw.get("headings") and raw.get("data"):
        headings = list(raw["headings"])
        for values in raw["data"]:
            row = {key: _ovs_value(value) for key, value in zip(headings, values)}
            name = str(row.get("name") or "")
            if not name:
                continue
            tag = row.get("tag")
            if isinstance(tag, list):
                tag = tag[0] if tag else None
            trunks = row.get("trunks") or []
            if not isinstance(trunks, list):
                trunks = [trunks]
            tag = int(tag) if tag not in {None, ""} else None
            trunks = [int(v) for v in trunks]
            result.interfaces.append(NetworkInterface(
                device_id=device_id,
                name=name,
                kind="virtual",
                vlan_mode="access" if tag is not None else ("trunk" if trunks else "none"),
                access_vlan=tag,
                trunk_vlans=trunks,
                metadata={"ovs_table": "Port"},
                observed_at=observed,
            ))
            if tag is not None:
                vlan_map.setdefault(tag, set()).add(name)
            for vlan in trunks:
                vlan_map.setdefault(vlan, set()).add(name)

    for vlan_id, interfaces in sorted(vlan_map.items()):
        result.vlans.append(VlanRecord(
            device_id=device_id,
            vlan_id=vlan_id,
            name=f"VLAN {vlan_id}",
            interfaces=sorted(interfaces),
            observed_at=observed,
        ))
    result.snapshot = _snapshot(device_id, "ovs", source_name, raw, result)
    return result


def _normalize_nft_match_value(value: Any) -> Any:
    """Normalize native nftables JSON match operands.

    `nft -j list ruleset` represents CIDR prefixes and ranges as structured
    objects, for example::

        {"prefix": {"addr": "10.10.10.0", "len": 24}}
        {"range": [1000, 2000]}

    Offline fixtures often use their textual equivalents.  Normalize both
    forms before PolicyRule validation so live collection and fixture import
    have identical semantics.
    """
    if isinstance(value, dict):
        prefix = value.get("prefix")
        if isinstance(prefix, dict):
            address = prefix.get("addr")
            length = prefix.get("len")
            if address not in {None, ""} and length not in {None, ""}:
                return f"{address}/{length}"
        range_value = value.get("range")
        if isinstance(range_value, list) and len(range_value) == 2:
            start = _normalize_nft_match_value(range_value[0])
            end = _normalize_nft_match_value(range_value[1])
            return f"{start}-{end}"
        set_value = value.get("set")
        if isinstance(set_value, list):
            return [_normalize_nft_match_value(item) for item in set_value]
    if isinstance(value, list):
        return [_normalize_nft_match_value(item) for item in value]
    return value


def _single_nft_match_value(value: Any) -> str:
    normalized = _normalize_nft_match_value(value)
    if isinstance(normalized, list):
        if len(normalized) != 1:
            raise ValueError(
                "nftables set-valued address/port matches are not yet supported "
                f"by the single-value policy model: {normalized!r}"
            )
        normalized = normalized[0]
    if normalized is None:
        return ""
    return str(normalized)


def _nft_match_to_fields(expr: Dict[str, Any], fields: Dict[str, Any]) -> None:
    match = expr.get("match")
    if not isinstance(match, dict):
        return
    left = match.get("left", {})
    right = match.get("right")
    if isinstance(left, dict) and "payload" in left:
        payload = left["payload"]
        proto = str(payload.get("protocol") or "").lower()
        field_name = str(payload.get("field") or "").lower()
        if proto in {"ip", "ip6"} and field_name in {"saddr", "daddr"}:
            fields["src_network" if field_name == "saddr" else "dst_network"] = _single_nft_match_value(right)
        elif proto in {"tcp", "udp"} and field_name in {"sport", "dport"}:
            fields["src_port" if field_name == "sport" else "dst_port"] = _single_nft_match_value(right)
            fields["protocol"] = proto.upper()
    if isinstance(left, dict) and "meta" in left:
        key = str(left["meta"].get("key") or "")
        if key == "l4proto":
            fields["protocol"] = _single_nft_match_value(right).upper()
        elif key in {"iifname", "iif"}:
            fields["in_interface"] = _single_nft_match_value(right)
        elif key in {"oifname", "oif"}:
            fields["out_interface"] = _single_nft_match_value(right)
    if isinstance(left, dict) and "ct" in left and str(left["ct"].get("key")) == "state":
        normalized = _normalize_nft_match_value(right)
        if isinstance(normalized, list):
            fields["state"] = [str(x).lower() for x in normalized]
        elif normalized is not None and normalized != "":
            fields["state"] = [str(normalized).lower()]


def parse_nft_json(source: str | Path | Dict[str, Any], *, device_id: str, source_name: str = "offline") -> NetworkImportResult:
    raw = _load_json(source)
    result = NetworkImportResult(snapshot=NetworkSnapshot(device_id=device_id, collector="nftables", source=source_name, status="COLLECTING", raw_sha256=""))
    observed = utc_now()
    chains: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    entries = raw.get("nftables", []) if isinstance(raw, dict) else []
    for item in entries:
        if "chain" in item:
            chain = item["chain"]
            chains[(str(chain.get("family", "inet")), str(chain.get("table", "filter")), str(chain.get("name", "")))] = chain
    sequence = 0
    for item in entries:
        rule = item.get("rule")
        if not isinstance(rule, dict):
            continue
        sequence += 1
        fields: Dict[str, Any] = {
            "protocol": "ANY", "src_network": "", "dst_network": "", "src_port": None,
            "dst_port": None, "in_interface": "", "out_interface": "", "state": [],
        }
        action = "CONTINUE"
        counters: Dict[str, int] = {}
        for expr in rule.get("expr", []) or []:
            if not isinstance(expr, dict):
                continue
            _nft_match_to_fields(expr, fields)
            for candidate in ("accept", "drop", "reject", "masquerade", "snat", "dnat", "redirect", "return"):
                if candidate in expr:
                    action = candidate
            if "counter" in expr and isinstance(expr["counter"], dict):
                counters = {
                    "packets": int(expr["counter"].get("packets") or 0),
                    "bytes": int(expr["counter"].get("bytes") or 0),
                }
        family = str(rule.get("family") or "inet")
        table = str(rule.get("table") or "filter")
        chain = str(rule.get("chain") or "forward")
        chain_data = chains.get((family, table, chain), {})
        # JSON output is emitted in chain evaluation order. Handles are stable
        # identifiers, not guaranteed ordering keys after insert/replace operations.
        priority = sequence
        result.policies.append(PolicyRule(
            device_id=device_id,
            policy_type="firewall",
            table=table,
            chain=chain,
            action=action,
            family=family,
            priority=priority,
            protocol=fields["protocol"],
            src_network=fields["src_network"],
            dst_network=fields["dst_network"],
            src_port=fields["src_port"],
            dst_port=fields["dst_port"],
            in_interface=fields["in_interface"],
            out_interface=fields["out_interface"],
            state=fields["state"],
            comment=str(rule.get("comment") or ""),
            counters=counters,
            metadata={
                "chain_hook": chain_data.get("hook"),
                "chain_policy": chain_data.get("policy"),
                "raw_handle": rule.get("handle"),
                "chain_sequence": sequence,
            },
            observed_at=observed,
        ))
    result.snapshot = _snapshot(device_id, "nftables", source_name, raw, result)
    return result


def _port_matches(value: Optional[int], rule_value: Optional[str]) -> bool:
    if not rule_value:
        return True
    if value is None:
        return False
    text = str(rule_value)
    try:
        if "-" in text:
            start, end = text.split("-", 1)
            return int(start) <= int(value) <= int(end)
        if ":" in text:
            start, end = text.split(":", 1)
            return int(start) <= int(value) <= int(end)
        return int(value) == int(text)
    except ValueError:
        return False


def _network_matches(address: str, rule_network: str) -> bool:
    if not rule_network:
        return True
    try:
        return ipaddress.ip_address(address) in ipaddress.ip_network(rule_network, strict=False)
    except ValueError:
        return False


def select_route(routes: Iterable[RouteEntry], destination: str, *, vrf: str = "default") -> Optional[RouteEntry]:
    try:
        address = ipaddress.ip_address(destination)
    except ValueError:
        return None
    candidates: List[Tuple[int, int, int, RouteEntry]] = []
    for route in routes:
        if route.vrf != vrf or not route.installed:
            continue
        try:
            network = ipaddress.ip_network(route.prefix, strict=False)
        except ValueError:
            continue
        if network.version == address.version and address in network:
            candidates.append((network.prefixlen, int(route.selected), -route.metric, route))
    return max(candidates, key=lambda item: item[:3])[3] if candidates else None


def _flow_connection_states(flow: FlowRecord) -> set[str]:
    """Infer conservative conntrack-like states from aggregated flow metadata.

    This is intentionally approximate. It prevents an established-only nftables
    rule from matching a captured initial SYN while retaining explainable behavior
    for header-only flow records.
    """
    if flow.protocol.upper() == "TCP":
        flags = {str(k).lower(): int(v) for k, v in (flow.tcp_flags or {}).items()}
        states: set[str] = set()
        if flags.get("syn", 0) > 0 and flags.get("ack", 0) == 0:
            states.add("new")
        if flags.get("ack", 0) > 0 or flow.packets > 1:
            states.add("established")
        if flags.get("rst", 0) > 0:
            states.add("invalid")
        return states or {"new"}
    if flow.protocol.upper() == "UDP":
        # A unidirectional aggregate cannot prove establishment. Treat it as new.
        return {"new"}
    return {"new"}


def _state_matches(flow: FlowRecord, states: Sequence[str]) -> bool:
    if not states:
        return True
    wanted = {str(item).lower() for item in states}
    return bool(wanted & _flow_connection_states(flow))


def match_policy_rule(flow: FlowRecord, rules: Sequence[PolicyRule], *, in_interface: str = "", out_interface: str = "") -> Optional[PolicyRule]:
    for rule in sorted(rules, key=lambda item: (item.priority, item.rule_id)):
        if rule.protocol not in {"ANY", flow.protocol.upper()}:
            continue
        if not _network_matches(flow.src_ip, rule.src_network) or not _network_matches(flow.dst_ip, rule.dst_network):
            continue
        if not _port_matches(flow.src_port, rule.src_port) or not _port_matches(flow.dst_port, rule.dst_port):
            continue
        if rule.in_interface and in_interface and rule.in_interface != in_interface:
            continue
        if rule.out_interface and out_interface and rule.out_interface != out_interface:
            continue
        if not _state_matches(flow, rule.state):
            continue
        return rule
    return None


def correlate_flow(
    flow: FlowRecord,
    *,
    ingress_device_id: str,
    routes: Sequence[RouteEntry],
    rules: Sequence[PolicyRule],
    vlans: Sequence[VlanRecord] = (),
    vrf: str = "default",
    in_interface: str = "",
) -> FlowAssessment:
    route = select_route(routes, flow.dst_ip, vrf=vrf)
    out_interface = route.interface if route else ""
    rule = match_policy_rule(flow, rules, in_interface=in_interface, out_interface=out_interface)
    route_status = "FOUND" if route else "NO_ROUTE"
    policy_status = "NO_MATCH"
    if rule:
        policy_status = _normalize_action(rule.action)
    vlan_status = "NOT_APPLICABLE"
    if flow.vlan_id is not None:
        vlan_status = "KNOWN" if any(item.vlan_id == flow.vlan_id for item in vlans) else "UNKNOWN_VLAN"
    if policy_status == "DENY":
        verdict = "DENY"
        reason = f"flow matches denying rule {rule.rule_id}"
    elif not route:
        verdict = "UNROUTABLE"
        reason = "no installed route matches the destination"
    elif policy_status == "ALLOW":
        verdict = "ALLOW"
        reason = f"route {route.prefix} and allowing rule {rule.rule_id} match"
    else:
        verdict = "UNKNOWN"
        reason = f"route {route.prefix} exists but no conclusive policy rule matched"
    if vlan_status == "UNKNOWN_VLAN" and verdict == "ALLOW":
        verdict = "UNKNOWN"
        reason += "; captured VLAN is not present in the imported VLAN state"
    return FlowAssessment(
        flow_id=flow.flow_id,
        capture_id=flow.capture_id,
        target=flow.target,
        ingress_device_id=ingress_device_id,
        route_status=route_status,
        policy_status=policy_status,
        verdict=verdict,
        route_id=route.route_id if route else None,
        matched_rule_id=rule.rule_id if rule else None,
        vlan_status=vlan_status,
        reason=reason,
        evidence={
            "destination": flow.dst_ip,
            "protocol": flow.protocol,
            "out_interface": out_interface,
            "vrf": vrf,
        },
    )


class OpenSourceNetworkCollector:
    """Execute read-only commands for supported open-source network components."""

    COMMANDS = {
        "frr-routes": ["vtysh", "-c", "show ip route json"],
        "frr-interfaces": ["vtysh", "-c", "show interface json"],
        "ovs-ports": ["ovs-vsctl", "--format=json", "--columns=name,tag,trunks,interfaces", "list", "Port"],
        "nft-ruleset": ["nft", "-j", "list", "ruleset"],
    }

    def collect(
        self,
        kind: str,
        *,
        timeout: float = 15.0,
        container: Optional[str] = None,
        runtime: str = "docker",
    ) -> Tuple[Any, CollectionRun]:
        if kind not in self.COMMANDS:
            raise ValueError(f"unsupported collector kind: {kind}")
        if runtime not in {"docker", "podman"}:
            raise ValueError(f"unsupported container runtime: {runtime}")
        inner_command = list(self.COMMANDS[kind])
        command = [runtime, "exec", container, *inner_command] if container else inner_command
        source = f"{runtime}://{container}" if container else "localhost"
        started = utc_now()
        proc = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
        run = CollectionRun(
            agent="network-state",
            target=kind,
            source=source,
            command=command,
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            started_at=started,
            finished_at=utc_now(),
            metadata={
                "read_only": True,
                "collector_kind": kind,
                "container": container or "",
                "container_runtime": runtime if container else "",
                "inner_command": inner_command,
            },
        )
        if proc.returncode != 0:
            raise RuntimeError(f"collector failed ({proc.returncode}): {proc.stderr.strip()}")
        try:
            return json.loads(proc.stdout), run
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"collector returned invalid JSON: {exc}") from exc
