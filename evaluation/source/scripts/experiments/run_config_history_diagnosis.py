#!/usr/bin/env python3
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import time
from typing import Any, Iterable

from kansoku.diagnostic_eval import (
    ConfigStateView,
    ConfigurationOnlyDiagnoser,
    EvidenceLeakageChecker,
    FlowEvidenceView,
    TargetFlowSpec,
)
from kansoku.hub import Hub


def load_json(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json(path: str | Path, value: Any) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


def sha256_json(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def latest_snapshot_id(hub: Hub, device_id: str, collector: str) -> str:
    for row in hub.list_network_snapshots(limit=100, device_id=device_id):
        if row.collector == collector:
            return row.snapshot_id
    raise ValueError(f"no {collector} snapshot found for {device_id}")


def sanitize_route(item):
    data = item.to_dict()
    data["metadata"] = {}
    return type(item).from_dict(data)


def sanitize_policy(item):
    data = item.to_dict()
    data["comment"] = ""
    data["counters"] = {}
    data["metadata"] = {}
    return type(item).from_dict(data)


def sanitize_vlan(item):
    data = item.to_dict()
    data["metadata"] = {}
    return type(item).from_dict(data)


def sanitize_interface(item):
    data = item.to_dict()
    data["metadata"] = {}
    return type(item).from_dict(data)


def build_config_view(
    db: str,
    *,
    target: TargetFlowSpec,
    ingress_device_id: str,
    route_device_id: str,
    policy_device_id: str,
    vlan_device_id: str,
    vrf: str,
    in_interface: str,
) -> ConfigStateView:
    hub = Hub(db)
    route_snapshot = latest_snapshot_id(hub, route_device_id, "frr")
    policy_snapshot = latest_snapshot_id(hub, policy_device_id, "nftables")
    vlan_snapshot = latest_snapshot_id(hub, vlan_device_id, "ovs")
    view = ConfigStateView(
        query_id=target.query_id,
        ingress_device_id=ingress_device_id,
        route_device_id=route_device_id,
        policy_device_id=policy_device_id,
        vlan_device_id=vlan_device_id,
        vrf=vrf,
        in_interface=in_interface,
        routes=tuple(
            sanitize_route(item)
            for item in hub.list_network_routes(device_id=route_device_id, snapshot_id=route_snapshot, limit=20_000)
        ),
        policies=tuple(
            sanitize_policy(item)
            for item in hub.list_network_policies(device_id=policy_device_id, snapshot_id=policy_snapshot, limit=20_000)
        ),
        vlans=tuple(
            sanitize_vlan(item)
            for item in hub.list_network_vlans(device_id=vlan_device_id, snapshot_id=vlan_snapshot, limit=10_000)
        ),
        interfaces=tuple(
            sanitize_interface(item)
            for item in hub.list_network_interfaces(device_id=vlan_device_id, snapshot_id=vlan_snapshot, limit=10_000)
        ),
    )
    # Reuse the paper leakage checker. The flow view is intentionally empty.
    EvidenceLeakageChecker().validate_views(FlowEvidenceView(query_id=target.query_id, flows=()), view)
    return view


def route_sig(item) -> tuple:
    return (
        item.device_id, item.prefix, item.protocol, item.next_hop, item.interface,
        item.vrf, item.address_family, int(item.metric), int(item.distance),
        bool(item.selected), bool(item.installed),
    )


def policy_sig(item) -> tuple:
    return (
        item.device_id, item.policy_type, item.table, item.chain, item.action,
        item.family, int(item.priority), item.protocol, item.src_network,
        item.dst_network, item.src_port, item.dst_port, item.in_interface,
        item.out_interface, tuple(sorted(str(x) for x in item.state)),
    )


def vlan_sig(item) -> tuple:
    return (item.device_id, int(item.vlan_id), tuple(sorted(str(x) for x in item.interfaces)))


def interface_vlan_sig(item) -> tuple:
    return (
        item.device_id, item.name, item.vlan_mode,
        None if item.access_vlan is None else int(item.access_vlan),
        tuple(sorted(int(x) for x in item.trunk_vlans)), item.bridge,
    )


def interface_non_vlan_sig(item) -> tuple:
    return (
        item.device_id, item.name, item.kind, bool(item.admin_up), bool(item.oper_up),
        item.mac_address, int(item.mtu), tuple(sorted(str(x) for x in item.addresses)), item.vrf,
    )


def multiset_diff(before: Iterable[tuple], after: Iterable[tuple]) -> dict[str, list[list[Any]]]:
    b = Counter(before)
    a = Counter(after)
    removed: list[list[Any]] = []
    added: list[list[Any]] = []
    for sig, count in sorted((b - a).items(), key=lambda x: repr(x[0])):
        removed.extend([list(sig)] * count)
    for sig, count in sorted((a - b).items(), key=lambda x: repr(x[0])):
        added.extend([list(sig)] * count)
    return {"removed": removed, "added": added}


def changed(diff: dict[str, list[list[Any]]]) -> bool:
    return bool(diff["removed"] or diff["added"])


def diagnose(target: TargetFlowSpec, pre: ConfigStateView, post: ConfigStateView) -> tuple[dict[str, Any], dict[str, Any]]:
    if target.query_id != pre.query_id or target.query_id != post.query_id:
        raise ValueError("target/pre/post query_id mismatch")
    started = time.perf_counter_ns()
    current = ConfigurationOnlyDiagnoser().diagnose(target, post).to_dict()

    delta = {
        "routes": multiset_diff((route_sig(x) for x in pre.routes), (route_sig(x) for x in post.routes)),
        "policies": multiset_diff((policy_sig(x) for x in pre.policies), (policy_sig(x) for x in post.policies)),
        "vlans": multiset_diff((vlan_sig(x) for x in pre.vlans), (vlan_sig(x) for x in post.vlans)),
        "interface_vlan": multiset_diff(
            (interface_vlan_sig(x) for x in pre.interfaces),
            (interface_vlan_sig(x) for x in post.interfaces),
        ),
        "interface_non_vlan": multiset_diff(
            (interface_non_vlan_sig(x) for x in pre.interfaces),
            (interface_non_vlan_sig(x) for x in post.interfaces),
        ),
    }
    delta["changed_domains"] = [
        name for name in ("routes", "policies", "vlans", "interface_vlan", "interface_non_vlan")
        if changed(delta[name])
    ]

    # Current-state diagnosis wins when it already identifies a represented cause.
    if current["verdict"] != "ALLOW" or current["fault_domain"] != "NONE":
        verdict = current["verdict"]
        fault_domain = current["fault_domain"]
        affected_device = current["affected_device"]
        affected_element_type = current["affected_element_type"]
        affected_element_ref = current["affected_element_ref"]
        abstained = current["abstained"]
        reason = "post-fault Configuration-only diagnosis was already conclusive; history fallback not used"
    else:
        l2_changed = changed(delta["vlans"]) or changed(delta["interface_vlan"])
        other_changed = (
            changed(delta["routes"])
            or changed(delta["policies"])
            or changed(delta["interface_non_vlan"])
        )
        if l2_changed and not other_changed:
            verdict = "UNKNOWN"
            fault_domain = "VLAN"
            affected_device = post.vlan_device_id
            affected_element_type = "VLAN"
            affected_element_ref = "config-history:vlan-delta"
            abstained = False
            reason = (
                "post-fault current-state model found no represented blocker, but sanitized "
                "pre/post configuration history contains an isolated VLAN/interface-VLAN delta"
            )
        else:
            verdict = "UNKNOWN"
            fault_domain = "UNKNOWN"
            affected_device = "UNKNOWN"
            affected_element_type = "UNKNOWN"
            affected_element_ref = "unknown"
            abstained = True
            reason = "configuration history did not isolate a single VLAN-domain temporal delta"

    elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000.0
    result = {
        "query_id": target.query_id,
        "method": "CONFIG_HISTORY_ONLY",
        "verdict": verdict,
        "fault_domain": fault_domain,
        "affected_device": affected_device,
        "affected_element_type": affected_element_type,
        "affected_element_ref": affected_element_ref,
        "abstained": abstained,
        "reason": reason,
        "elapsed_ms": elapsed_ms,
        "post_fault_config_only": current,
    }
    return result, delta


def main() -> int:
    ap = argparse.ArgumentParser(description="Run the frozen CONFIG_HISTORY_ONLY post-hoc control.")
    ap.add_argument("--pre-db", required=True)
    ap.add_argument("--post-db", required=True)
    ap.add_argument("--target-spec", required=True)
    ap.add_argument("--output-dir", required=True)
    ap.add_argument("--ingress-device", default="fw1")
    ap.add_argument("--route-device", default="r1")
    ap.add_argument("--policy-device", default="fw1")
    ap.add_argument("--vlan-device", default="sw1")
    ap.add_argument("--vrf", default="default")
    ap.add_argument("--in-interface", default="")
    args = ap.parse_args()

    target = TargetFlowSpec.from_dict(load_json(args.target_spec))
    common = dict(
        target=target,
        ingress_device_id=args.ingress_device,
        route_device_id=args.route_device,
        policy_device_id=args.policy_device,
        vlan_device_id=args.vlan_device,
        vrf=args.vrf,
        in_interface=args.in_interface,
    )
    pre = build_config_view(args.pre_db, **common)
    post = build_config_view(args.post_db, **common)
    result, delta = diagnose(target, pre, post)

    out = Path(args.output_dir)
    pre_json = pre.to_dict()
    post_json = post.to_dict()
    write_json(out / "views" / "target.json", target.to_dict())
    write_json(out / "views" / "pre-config.json", pre_json)
    write_json(out / "views" / "post-config.json", post_json)
    write_json(out / "config-delta.json", delta)
    write_json(out / "diagnostics.json", {
        "query_id": target.query_id,
        "result": result,
        "view_checksums": {
            "target_sha256": sha256_json(target.to_dict()),
            "pre_config_sha256": sha256_json(pre_json),
            "post_config_sha256": sha256_json(post_json),
            "delta_sha256": sha256_json(delta),
        },
    })
    print(json.dumps({"result": result, "delta": delta}, indent=2, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
