#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "$0")/.." && pwd)/lib.sh"

SCENARIO="vlan-trunk-only-drift"
DB="$DB_DIR/$SCENARIO.db"
PCAP="$PCAP_DIR/$SCENARIO.pcap"
REPORT="$REPORT_DIR/$SCENARIO.json"
rm -f "$DB" "$PCAP" "$REPORT"
reset_network
trap 'reset_network >/dev/null 2>&1 || true' EXIT

# Preserve a known-good VLAN 10 observation, then drift only the trunk side.
capture_https_on_fw "$PCAP" yes
run_node sw1 ovs-vsctl set Port eth2 trunks=30
sleep 1

ACCESS_TAG="$(run_node sw1 ovs-vsctl get Port eth1 tag | tr -d '[:space:]')"
TRUNK_VLANS="$(run_node sw1 ovs-vsctl get Port eth2 trunks | tr -d '[:space:]')"
if [[ "$ACCESS_TAG" != "10" || "$TRUNK_VLANS" != "[30]" ]]; then
  echo "[FAIL] unexpected OVS state after trunk-only drift: eth1 tag=$ACCESS_TAG eth2 trunks=$TRUNK_VLANS" >&2
  exit 1
fi

if run_node client-a curl -fsS --connect-timeout 2 --max-time 4 http://10.20.20.10:443/ >/dev/null 2>&1; then
  echo "[FAIL] trunk-only VLAN drift did not interrupt connectivity" >&2
  exit 1
fi

collect_live_state "$DB"
CAPTURE_JSON="$(summarize_capture "$DB" "$PCAP" "lab-vlan-trunk-only-drift")"
CAPTURE_ID="$(capture_id_from_json <<<"$CAPTURE_JSON")"
CORRELATION="$(correlate_capture "$DB" "$CAPTURE_ID")"

"$KANSOKU_PYTHON" - "$CORRELATION" "$ACCESS_TAG" "$TRUNK_VLANS" > "$REPORT" <<'PY'
import json, sys
payload = json.loads(sys.argv[1])
print(json.dumps({
  "scenario": "vlan-trunk-only-drift",
  "status": "PASS",
  "live_fault": {
    "eth1_access_vlan": sys.argv[2],
    "eth2_trunk_vlans": sys.argv[3],
    "target_http": "FAIL",
  },
  "verdicts": payload["summary"]["verdicts"],
}, indent=2, sort_keys=True))
PY

echo "[PASS] vlan-trunk-only-drift preserved access VLAN 10 while trunk moved to VLAN 30 and target HTTP failed"
