#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

if [[ -n "${KANSOKU_PYTHON:-}" ]]; then
  PYTHON_BIN="$KANSOKU_PYTHON"
elif [[ -x "$ROOT_DIR/.lab-venv/bin/python" ]]; then
  PYTHON_BIN="$ROOT_DIR/.lab-venv/bin/python"
elif [[ -x "$ROOT_DIR/.venv/bin/python" ]]; then
  PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="$(command -v python3)"
else
  echo "ERROR: Python interpreter not found" >&2
  exit 1
fi

python() { "$PYTHON_BIN" "$@"; }
TMP_CHECK="$(mktemp -d)"
trap 'rm -rf "$TMP_CHECK"' EXIT
DB="$TMP_CHECK/v09.db"
PCAP="$TMP_CHECK/sample.pcap"

python scripts/generate_sample_pcap.py "$PCAP" >/dev/null
python -m kansoku --db "$DB" init >/dev/null
python -m kansoku --db "$DB" network import frr --device-id r1 --file scenarios/virtual-lab/frr-r1.json >/dev/null
python -m kansoku --db "$DB" network import ovs --device-id sw1 --file scenarios/virtual-lab/ovs-sw1.json >/dev/null
python -m kansoku --db "$DB" network import nft --device-id fw1 --file scenarios/virtual-lab/nft-fw1.json >/dev/null
CAPTURE_JSON="$(python -m kansoku --db "$DB" capture summarize --pcap "$PCAP" --target virtual-lab-path --source virtual-lab)"
CAPTURE_ID="$(python -c 'import json,sys; print(json.load(sys.stdin)["capture"]["capture_id"])' <<<"$CAPTURE_JSON")"
python -m kansoku --db "$DB" network correlate \
  --capture-id "$CAPTURE_ID" --ingress-device fw1 \
  --route-device r1 --policy-device fw1 --vlan-device sw1 >/dev/null
ASSESSMENT_ID="$(python - "$DB" <<'PY'
import sqlite3, sys
with sqlite3.connect(sys.argv[1]) as conn:
    row=conn.execute("SELECT assessment_id FROM flow_assessments WHERE verdict='DENY' ORDER BY timestamp LIMIT 1").fetchone()
assert row
print(row[0])
PY
)"
RECOMMENDATION="$(python -m kansoku --db "$DB" recommend generate \
  --assessment-id "$ASSESSMENT_ID" --route-device r1 --policy-device fw1 --vlan-device sw1)"
python - "$DB" "$RECOMMENDATION" <<'PY'
import json, sqlite3, sys
payload=json.loads(sys.argv[2])
assert payload['category']=='FIREWALL_POLICY', payload
assert payload['simulation_status']=='PASSED', payload
assert payload['simulated_verdict']=='ALLOW', payload
assert payload['status']=='DRAFT', payload
assert payload['commands'] and payload['rollback_commands'], payload
with sqlite3.connect(sys.argv[1]) as conn:
    count=conn.execute('SELECT COUNT(*) FROM configuration_recommendations').fetchone()[0]
assert count == 1, count
print('verified v0.9 reviewable configuration recommendation and what-if result')
PY
