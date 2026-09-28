#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "$0")/.." && pwd)/lib.sh"

SCENARIO="vlan-mismatch"
DB="$DB_DIR/$SCENARIO.db"
PCAP="$PCAP_DIR/$SCENARIO.pcap"
REPORT="$REPORT_DIR/$SCENARIO.json"
rm -f "$DB" "$PCAP" "$REPORT"
reset_network
trap 'reset_network >/dev/null 2>&1 || true' EXIT

# Capture a known-good tagged VLAN 10 flow, then introduce configuration drift.
capture_https_on_fw "$PCAP" yes
run_node sw1 ovs-vsctl set Port eth1 tag=30
run_node sw1 ovs-vsctl set Port eth2 trunks=30
sleep 1

if run_node client-a curl -fsS --connect-timeout 2 --max-time 4 http://10.20.20.10:443/ >/dev/null 2>&1; then
  echo "[FAIL] VLAN mismatch did not interrupt connectivity" >&2
  exit 1
fi

collect_live_state "$DB"
CAPTURE_JSON="$(summarize_capture "$DB" "$PCAP" "lab-vlan-mismatch")"
CAPTURE_ID="$(capture_id_from_json <<<"$CAPTURE_JSON")"
CORRELATION="$(correlate_capture "$DB" "$CAPTURE_ID")"
assert_verdict "$CORRELATION" UNKNOWN >/dev/null
assert_vlan_status "$DB" "$CAPTURE_ID" UNKNOWN_VLAN >/dev/null

"$KANSOKU_PYTHON" - "$CORRELATION" > "$REPORT" <<'PY'
import json, sys
payload = json.loads(sys.argv[1])
print(json.dumps({
  "scenario": "vlan-mismatch",
  "status": "PASS",
  "expected": "UNKNOWN",
  "vlan_status": "UNKNOWN_VLAN",
  "verdicts": payload["summary"]["verdicts"],
}, indent=2, sort_keys=True))
PY

echo "[PASS] vlan-mismatch → UNKNOWN / UNKNOWN_VLAN"
