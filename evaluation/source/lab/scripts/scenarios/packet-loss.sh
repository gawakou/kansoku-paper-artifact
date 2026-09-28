#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "$0")/.." && pwd)/lib.sh"

SCENARIO="packet-loss"
REPORT="$REPORT_DIR/$SCENARIO.json"
rm -f "$REPORT"
reset_network
trap 'reset_network >/dev/null 2>&1 || true' EXIT

run_node r1 tc qdisc replace dev eth2 root netem loss 100%
if run_node client-a ping -c 3 -W 1 10.20.20.10 >/dev/null 2>&1; then
  echo "[FAIL] packet-loss fault did not interrupt connectivity" >&2
  exit 1
fi
run_node r1 tc qdisc del dev eth2 root
sleep 1
run_node client-a ping -c 2 -W 2 10.20.20.10 >/dev/null

cat > "$REPORT" <<'JSON'
{
  "scenario": "packet-loss",
  "status": "PASS",
  "fault": "tc netem loss 100%",
  "recovery": "ping restored after qdisc removal"
}
JSON

echo "[PASS] packet-loss injection and recovery"
