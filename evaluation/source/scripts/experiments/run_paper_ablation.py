#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from kansoku.diagnostic_eval import (
    EvidenceAblationRunner,
    EvidenceViewBuilder,
    TargetFlowSpec,
    view_checksums,
)
from kansoku.hub import Hub


def _write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _load_target(path: str) -> TargetFlowSpec:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("target spec must contain a JSON object")
    return TargetFlowSpec.from_dict(payload)


def _latest_capture_id(hub: Hub) -> str:
    rows = hub.list_capture_sessions(limit=1)
    if not rows:
        raise ValueError("no capture session found in database; provide --capture-id after importing a capture")
    return rows[0].capture_id


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build leakage-controlled evidence views and run the three paper diagnosis methods."
    )
    parser.add_argument("--db", required=True, help="KANSOKU SQLite database containing capture and normalized state")
    parser.add_argument("--target-spec", required=True, help="TargetFlowSpec JSON file")
    parser.add_argument("--capture-id", help="Capture ID; defaults to the latest capture in --db")
    parser.add_argument("--ingress-device", default="fw1")
    parser.add_argument("--route-device", default="r1")
    parser.add_argument("--policy-device", default="fw1")
    parser.add_argument("--vlan-device", default="sw1")
    parser.add_argument("--vrf", default="default")
    parser.add_argument("--in-interface", default="")
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()

    target = _load_target(args.target_spec)
    hub = Hub(args.db)
    capture_id = args.capture_id or _latest_capture_id(hub)

    flow_view, config_view = EvidenceViewBuilder(hub).build(
        target=target,
        capture_id=capture_id,
        ingress_device_id=args.ingress_device,
        route_device_id=args.route_device,
        policy_device_id=args.policy_device,
        vlan_device_id=args.vlan_device,
        vrf=args.vrf,
        in_interface=args.in_interface,
    )
    result = EvidenceAblationRunner().run(target, flow_view, config_view)
    checksums = view_checksums(target, flow_view, config_view)

    out = Path(args.output_dir)
    _write_json(out / "views" / "target.json", target.to_dict())
    _write_json(out / "views" / "flow.json", flow_view.to_dict())
    _write_json(out / "views" / "config.json", config_view.to_dict())
    _write_json(out / "views" / "checksums.json", checksums)

    diagnostics = {
        "capture_id": capture_id,
        "query_id": target.query_id,
        "view_checksums": checksums,
        **result.to_dict(),
    }
    _write_json(out / "diagnostics.json", diagnostics)
    print(json.dumps(diagnostics, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
