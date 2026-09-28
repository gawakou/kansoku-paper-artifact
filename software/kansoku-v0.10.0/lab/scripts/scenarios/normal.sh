#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "$0")/.." && pwd)/lib.sh"

SCENARIO="normal"
DB="$DB_DIR/$SCENARIO.db"
PCAP="$PCAP_DIR/$SCENARIO.pcap"
REPORT="$REPORT_DIR/$SCENARIO.json"
rm -f "$DB" "$PCAP" "$REPORT"
reset_network
ensure_server_services

run_node client-a ping -c 2 -W 2 10.20.20.10 >/dev/null
if ! run_node client-a curl -fsS --connect-timeout 2 --max-time 4 http://10.20.20.10:443/ >/dev/null; then
  echo "[FAIL] normal scenario HTTP request failed" >&2
  dump_server_diagnostics
  exit 1
fi
IPERF_JSON="$(run_node client-a iperf3 -c 10.20.20.10 -t 2 -J)"
"$KANSOKU_PYTHON" - "$IPERF_JSON" <<'PY'
import json, sys
payload = json.loads(sys.argv[1])
value = payload.get("end", {}).get("sum_received", {}).get("bits_per_second", 0)
assert value > 0, payload
PY

capture_https_on_fw "$PCAP" yes
collect_live_state "$DB"
CAPTURE_JSON="$(summarize_capture "$DB" "$PCAP" "lab-normal")"
CAPTURE_ID="$(capture_id_from_json <<<"$CAPTURE_JSON")"
CORRELATION="$(correlate_capture "$DB" "$CAPTURE_ID")"
assert_verdict "$CORRELATION" ALLOW >/dev/null

"$KANSOKU_PYTHON" - "$CAPTURE_JSON" "$CORRELATION" > "$REPORT" <<'PY'
import json, sys
capture = json.loads(sys.argv[1])
correlation = json.loads(sys.argv[2])
print(json.dumps({
  "scenario": "normal",
  "status": "PASS",
  "capture_id": capture["capture"]["capture_id"],
  "packets": capture["capture"]["packet_count"],
  "flows": correlation["summary"]["flows"],
  "verdicts": correlation["summary"]["verdicts"],
}, indent=2, sort_keys=True))
PY

echo "[PASS] normal → ALLOW"
