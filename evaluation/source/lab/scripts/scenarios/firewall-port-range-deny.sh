#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "$0")/.." && pwd)/lib.sh"

SCENARIO="firewall-port-range-deny"
DB="$DB_DIR/$SCENARIO.db"
PCAP="$PCAP_DIR/$SCENARIO.pcap"
REPORT="$REPORT_DIR/$SCENARIO.json"
rm -f "$DB" "$PCAP" "$REPORT"
reset_network
trap 'reset_network >/dev/null 2>&1 || true' EXIT

# Port 443 is inside this range; this also exercises nftables range normalization.
run_node fw1 nft insert rule inet filter forward \
  tcp dport 400-500 counter drop

capture_https_on_fw "$PCAP" no
collect_live_state "$DB"
CAPTURE_JSON="$(summarize_capture "$DB" "$PCAP" "paper-fw-port-range")"
CAPTURE_ID="$(capture_id_from_json <<<"$CAPTURE_JSON")"
CORRELATION="$(correlate_capture "$DB" "$CAPTURE_ID")"
assert_verdict "$CORRELATION" DENY >/dev/null

"$KANSOKU_PYTHON" - "$CORRELATION" > "$REPORT" <<'PY'
import json, sys
payload = json.loads(sys.argv[1])
print(json.dumps({
  "scenario": "firewall-port-range-deny",
  "status": "PASS",
  "observed_verdicts": payload["summary"]["verdicts"],
}, indent=2, sort_keys=True))
PY

echo "[PASS] firewall-port-range-deny live injection produced DENY"
