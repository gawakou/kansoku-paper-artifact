#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "$0")/.." && pwd)/lib.sh"

SCENARIO="firewall-deny"
DB="$DB_DIR/$SCENARIO.db"
PCAP="$PCAP_DIR/$SCENARIO.pcap"
REPORT="$REPORT_DIR/$SCENARIO.json"
rm -f "$DB" "$PCAP" "$REPORT"
reset_network
trap 'reset_network >/dev/null 2>&1 || true' EXIT

run_node fw1 nft insert rule inet filter forward \
  ip saddr 10.10.10.0/24 ip daddr 10.20.20.10 tcp dport 443 \
  counter drop comment '"kansoku fault deny"'

capture_https_on_fw "$PCAP" no
collect_live_state "$DB"
CAPTURE_JSON="$(summarize_capture "$DB" "$PCAP" "lab-firewall-deny")"
CAPTURE_ID="$(capture_id_from_json <<<"$CAPTURE_JSON")"
CORRELATION="$(correlate_capture "$DB" "$CAPTURE_ID")"
assert_verdict "$CORRELATION" DENY >/dev/null

"$KANSOKU_PYTHON" - "$CORRELATION" > "$REPORT" <<'PY'
import json, sys
payload = json.loads(sys.argv[1])
print(json.dumps({
  "scenario": "firewall-deny",
  "status": "PASS",
  "expected": "DENY",
  "verdicts": payload["summary"]["verdicts"],
}, indent=2, sort_keys=True))
PY

echo "[PASS] firewall-deny → DENY"
