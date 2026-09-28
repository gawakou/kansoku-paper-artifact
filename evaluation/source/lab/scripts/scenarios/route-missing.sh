#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "$0")/.." && pwd)/lib.sh"

SCENARIO="route-missing"
DB="$DB_DIR/$SCENARIO.db"
PCAP="$PCAP_DIR/$SCENARIO.pcap"
REPORT="$REPORT_DIR/$SCENARIO.json"
rm -f "$DB" "$PCAP" "$REPORT"
reset_network
trap 'reset_network >/dev/null 2>&1 || true' EXIT

run_node r1 vtysh -c 'configure terminal' -c 'no ip route 10.20.20.0/24 172.16.1.2'
sleep 1

capture_https_on_fw "$PCAP" no
collect_live_state "$DB"
CAPTURE_JSON="$(summarize_capture "$DB" "$PCAP" "lab-route-missing")"
CAPTURE_ID="$(capture_id_from_json <<<"$CAPTURE_JSON")"
CORRELATION="$(correlate_capture "$DB" "$CAPTURE_ID")"
assert_verdict "$CORRELATION" UNROUTABLE >/dev/null

"$KANSOKU_PYTHON" - "$CORRELATION" > "$REPORT" <<'PY'
import json, sys
payload = json.loads(sys.argv[1])
print(json.dumps({
  "scenario": "route-missing",
  "status": "PASS",
  "expected": "UNROUTABLE",
  "verdicts": payload["summary"]["verdicts"],
}, indent=2, sort_keys=True))
PY

echo "[PASS] route-missing → UNROUTABLE"
