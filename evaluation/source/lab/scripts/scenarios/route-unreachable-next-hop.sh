#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "$0")/.." && pwd)/lib.sh"

SCENARIO="route-unreachable-next-hop"
DB="$DB_DIR/$SCENARIO.db"
PCAP="$PCAP_DIR/$SCENARIO.pcap"
REPORT="$REPORT_DIR/$SCENARIO.json"
rm -f "$DB" "$PCAP" "$REPORT"
reset_network
trap 'reset_network >/dev/null 2>&1 || true' EXIT

run_node r1 vtysh \
  -c 'configure terminal' \
  -c 'no ip route 10.20.20.0/24 172.16.1.2' \
  -c 'ip route 10.20.20.0/24 172.16.1.254'
sleep 2

FRR_ROUTE_JSON="$(run_node r1 vtysh -c 'show ip route 10.20.20.0/24 json')"
"$KANSOKU_PYTHON" - "$FRR_ROUTE_JSON" <<'PY'
import json, sys
payload = json.loads(sys.argv[1])
if payload:
    raise SystemExit(f"expected unresolved next-hop route to be absent from active FRR RIB, got: {payload}")
PY

capture_https_on_fw "$PCAP" no
collect_live_state "$DB"
CAPTURE_JSON="$(summarize_capture "$DB" "$PCAP" "paper-route-unreachable-next-hop")"
CAPTURE_ID="$(capture_id_from_json <<<"$CAPTURE_JSON")"
CORRELATION="$(correlate_capture "$DB" "$CAPTURE_ID")"
assert_verdict "$CORRELATION" UNROUTABLE >/dev/null

"$KANSOKU_PYTHON" - "$CORRELATION" "$FRR_ROUTE_JSON" > "$REPORT" <<'PY'
import json, sys
payload = json.loads(sys.argv[1])
frr_route = json.loads(sys.argv[2])
print(json.dumps({
  "scenario": "route-unreachable-next-hop",
  "status": "PASS",
  "frr_active_route": bool(frr_route),
  "observed_verdicts": payload["summary"]["verdicts"],
}, indent=2, sort_keys=True))
PY

echo "[PASS] route-unreachable-next-hop absent from active FRR RIB and produced UNROUTABLE"
