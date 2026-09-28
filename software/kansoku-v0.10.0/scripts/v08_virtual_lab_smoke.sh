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
elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="$(command -v python)"
else
    echo "ERROR: Python interpreter not found" >&2
    exit 1
fi

python() {
    "$PYTHON_BIN" "$@"
}

echo "[INFO] Python: $PYTHON_BIN"
TMP_CHECK="$(mktemp -d)"
trap 'rm -rf "$TMP_CHECK"' EXIT
DB="$TMP_CHECK/v08.db"
PCAP="$TMP_CHECK/sample.pcap"

python scripts/generate_sample_pcap.py "$PCAP" >/dev/null
python -m kansoku --db "$DB" init >/dev/null
python -m kansoku --db "$DB" network import frr --device-id r1 --file scenarios/virtual-lab/frr-r1.json >/dev/null
python -m kansoku --db "$DB" network import ovs --device-id sw1 --file scenarios/virtual-lab/ovs-sw1.json >/dev/null
python -m kansoku --db "$DB" network import nft --device-id fw1 --file scenarios/virtual-lab/nft-fw1.json >/dev/null
CAPTURE_JSON="$(python -m kansoku --db "$DB" capture summarize --pcap "$PCAP" --target virtual-lab-path --source virtual-lab)"
CAPTURE_ID="$(python -c 'import json,sys; print(json.load(sys.stdin)["capture"]["capture_id"])' <<<"$CAPTURE_JSON")"
CORRELATION="$(python -m kansoku --db "$DB" network correlate \
  --capture-id "$CAPTURE_ID" \
  --ingress-device fw1 \
  --route-device r1 \
  --policy-device fw1 \
  --vlan-device sw1)"
python - "$DB" "$CORRELATION" <<'PY'
import json, sqlite3, sys
payload=json.loads(sys.argv[2])
assert payload['summary']['flows'] == 3, payload
assert payload['summary']['verdicts'].get('ALLOW') == 1, payload
assert payload['summary']['verdicts'].get('DENY') == 2, payload
with sqlite3.connect(sys.argv[1]) as conn:
    tables={r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    expected={'network_devices','network_snapshots','network_interfaces','network_vlans','network_links','network_routes','network_policy_rules','flow_assessments'}
    assert expected <= tables, expected-tables
    counts={
      'devices': conn.execute('SELECT COUNT(*) FROM network_devices').fetchone()[0],
      'snapshots': conn.execute('SELECT COUNT(*) FROM network_snapshots').fetchone()[0],
      'routes': conn.execute('SELECT COUNT(*) FROM network_routes').fetchone()[0],
      'policies': conn.execute('SELECT COUNT(*) FROM network_policy_rules').fetchone()[0],
      'assessments': conn.execute('SELECT COUNT(*) FROM flow_assessments').fetchone()[0],
    }
assert counts == {'devices':3,'snapshots':3,'routes':2,'policies':2,'assessments':3}, counts
print('verified v0.8 virtual network state and flow correlation')
PY
