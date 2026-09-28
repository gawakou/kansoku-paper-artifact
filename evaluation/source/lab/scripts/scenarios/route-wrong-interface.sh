#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "$0")/.." && pwd)/lib.sh"

SCENARIO="route-wrong-interface"
DB="$DB_DIR/$SCENARIO.db"
PCAP="$PCAP_DIR/$SCENARIO.pcap"
REPORT="$REPORT_DIR/$SCENARIO.json"
rm -f "$DB" "$PCAP" "$REPORT"
reset_network
trap 'reset_network >/dev/null 2>&1 || true' EXIT

run_node r1 vtysh \
  -c 'configure terminal' \
  -c 'no ip route 10.20.20.0/24 172.16.1.2' \
  -c 'ip route 10.20.20.0/24 eth1'
sleep 2

ROUTE_JSON="$(run_node r1 vtysh -c 'show ip route 10.20.20.0/24 json')"
"$KANSOKU_PYTHON" - "$ROUTE_JSON" <<'PY'
import json, sys
payload = json.loads(sys.argv[1])
entries = payload.get("10.20.20.0/24", [])
if len(entries) != 1:
    raise SystemExit(f"expected exactly one active route, got {len(entries)}")
route = entries[0]
if route.get("installed") is not True or route.get("selected") is not True:
    raise SystemExit(f"expected installed selected route, got {route}")
nexthops = route.get("nexthops") or []
if not any(nh.get("interfaceName") == "eth1" and nh.get("active") is True for nh in nexthops):
    raise SystemExit(f"expected active wrong-interface nexthop eth1, got {nexthops}")
PY

capture_https_on_fw "$PCAP" no
collect_live_state "$DB"
CAPTURE_JSON="$(summarize_capture "$DB" "$PCAP" "lab-route-wrong-interface")"
CAPTURE_ID="$(capture_id_from_json <<<"$CAPTURE_JSON")"
CORRELATION="$(correlate_capture "$DB" "$CAPTURE_ID")"

"$KANSOKU_PYTHON" - "$CORRELATION" > "$REPORT" <<'PY'
import json, sys
payload = json.loads(sys.argv[1])
print(json.dumps({
  "scenario": "route-wrong-interface",
  "status": "PASS",
  "live_condition": {
    "target_http": "FAIL",
    "frr_route_installed": True,
    "frr_output_interface": "eth1"
  },
  "correlation_verdicts": payload.get("summary", {}).get("verdicts", {})
}, indent=2, sort_keys=True))
PY

echo "[PASS] route-wrong-interface installed via eth1 while target HTTP failed"
