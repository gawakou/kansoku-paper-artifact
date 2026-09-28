#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "$0")/.." && pwd)/lib.sh"

SCENARIO="route-blackhole-host"
DB="$DB_DIR/$SCENARIO.db"
PCAP="$PCAP_DIR/$SCENARIO.pcap"
REPORT="$REPORT_DIR/$SCENARIO.json"
rm -f "$DB" "$PCAP" "$REPORT"
reset_network
trap 'reset_network >/dev/null 2>&1 || true' EXIT

run_node r1 vtysh \
  -c 'configure terminal' \
  -c 'ip route 10.20.20.10/32 blackhole'
sleep 2

ROUTE_JSON="$(run_node r1 vtysh -c 'show ip route 10.20.20.10/32 json')"
"$KANSOKU_PYTHON" - "$ROUTE_JSON" <<'PY'
import json, sys
payload = json.loads(sys.argv[1])
entries = payload.get("10.20.20.10/32", [])
if len(entries) != 1:
    raise SystemExit(f"expected exactly one active /32 route, got {len(entries)}")
route = entries[0]
if route.get("installed") is not True or route.get("selected") is not True:
    raise SystemExit(f"expected installed selected blackhole route, got {route}")
nexthops = route.get("nexthops") or []
if not any(
    nh.get("blackhole") is True
    and nh.get("unreachable") is True
    and nh.get("active") is True
    for nh in nexthops
):
    raise SystemExit(f"expected active blackhole/unreachable nexthop, got {nexthops}")
PY

capture_https_on_fw "$PCAP" no
collect_live_state "$DB"
CAPTURE_JSON="$(summarize_capture "$DB" "$PCAP" "lab-route-blackhole-host")"
CAPTURE_ID="$(capture_id_from_json <<<"$CAPTURE_JSON")"
CORRELATION="$(correlate_capture "$DB" "$CAPTURE_ID")"

"$KANSOKU_PYTHON" - "$CORRELATION" > "$REPORT" <<'PY'
import json, sys
payload = json.loads(sys.argv[1])
print(json.dumps({
  "scenario": "route-blackhole-host",
  "status": "PASS",
  "live_condition": {
    "target_http": "FAIL",
    "frr_route_installed": True,
    "frr_prefix": "10.20.20.10/32",
    "frr_blackhole": True,
    "frr_unreachable": True
  },
  "correlation_verdicts": payload.get("summary", {}).get("verdicts", {})
}, indent=2, sort_keys=True))
PY

echo "[PASS] route-blackhole-host installed /32 blackhole while target HTTP failed"
