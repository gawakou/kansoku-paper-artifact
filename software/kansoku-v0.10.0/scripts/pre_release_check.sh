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

python -m compileall -q kansoku
python -m pytest -q
VERSION="$(python -c "import importlib.metadata as m; print(m.version('kansoku'))")"
[[ "$VERSION" == "0.10.0" ]] || { echo "unexpected package version: $VERSION" >&2; exit 1; }

python -m kansoku --help >/dev/null
python -m kansoku profile --help >/dev/null
python -m kansoku policy --help >/dev/null
python -m kansoku approval --help >/dev/null
python -m kansoku controller --help >/dev/null
python -m kansoku controller process --help >/dev/null
python -m kansoku agent watch --help >/dev/null
python -m kansoku target --help >/dev/null
python -m kansoku service --help >/dev/null
python -m kansoku service once --help >/dev/null
python -m kansoku service run --help >/dev/null
python -m kansoku remote-agent --help >/dev/null
python -m kansoku remote-agent create --help >/dev/null
python -m kansoku ingest serve --help >/dev/null
python -m kansoku edge --help >/dev/null
python -m kansoku edge flush --help >/dev/null
python -m kansoku capture --help >/dev/null
python -m kansoku network --help >/dev/null
python -m kansoku network import --help >/dev/null
python -m kansoku network correlate --help >/dev/null
python -m kansoku network collect --help >/dev/null
python -m kansoku recommend --help >/dev/null
python -m kansoku recommend generate --help >/dev/null
python -m kansoku recommend validate --help >/dev/null
python -m kansoku recommend export --help >/dev/null
python -m kansoku recommend candidates --help >/dev/null
python -m kansoku recommend evidence --help >/dev/null
python -m kansoku recommend review --help >/dev/null
python -m kansoku recommend apply-lab --help >/dev/null
python -m kansoku recommend executions --help >/dev/null
python -m kansoku experiment --help >/dev/null
python -m kansoku experiment create --help >/dev/null
python -m kansoku experiment record --help >/dev/null
python -m kansoku experiment import-lab --help >/dev/null
python -m kansoku experiment summarize --help >/dev/null
python -m kansoku experiment export --help >/dev/null
python -m kansoku experiment manifest --help >/dev/null
python -m kansoku experiment validate-catalog --help >/dev/null
python -m kansoku capture summarize --help >/dev/null
python -m kansoku capture run --help >/dev/null
python -m kansoku edge pcap --help >/dev/null
python -m kansoku edge capture --help >/dev/null

python - <<'PY'
import json
from pathlib import Path
for path in Path('schemas').glob('*.json'):
    json.loads(path.read_text())
print('verified JSON schemas')
PY

TMP_CHECK="$(mktemp -d)"
trap 'rm -rf "$TMP_CHECK"' EXIT
python scripts/generate_sample_pcap.py "$TMP_CHECK/sample.pcap" >/dev/null
python -m kansoku --db "$TMP_CHECK/check.db" init >/dev/null
FIRST_IMPORT="$(python -m kansoku --db "$TMP_CHECK/check.db" capture summarize \
  --pcap "$TMP_CHECK/sample.pcap" \
  --target pre-release-pcap \
  --source pre-release-sensor \
  --flow-limit 3)"
SECOND_IMPORT="$(python -m kansoku --db "$TMP_CHECK/check.db" capture summarize \
  --pcap "$TMP_CHECK/sample.pcap" \
  --target pre-release-pcap \
  --source pre-release-sensor \
  --flow-limit 3)"
FORCED_IMPORT="$(python -m kansoku --db "$TMP_CHECK/check.db" capture summarize \
  --pcap "$TMP_CHECK/sample.pcap" \
  --target pre-release-pcap \
  --source pre-release-sensor \
  --flow-limit 3 \
  --force-reimport)"
python - "$TMP_CHECK/check.db" "$FIRST_IMPORT" "$SECOND_IMPORT" "$FORCED_IMPORT" <<'PY'
import json
import sqlite3
import sys
first, second, forced = map(json.loads, sys.argv[2:5])
assert first["import_status"] == "IMPORTED", first
assert second["import_status"] == "DUPLICATE", second
assert second["duplicate_of"] == first["capture"]["capture_id"], second
assert forced["import_status"] == "FORCE_IMPORTED", forced
with sqlite3.connect(sys.argv[1]) as conn:
    captures = conn.execute("SELECT COUNT(*) FROM capture_sessions").fetchone()[0]
    flows = conn.execute("SELECT COUNT(*) FROM flow_records").fetchone()[0]
    observations = conn.execute("SELECT COUNT(*) FROM observations").fetchone()[0]
assert captures == 2, captures
assert flows == 6, flows
assert observations == 16, observations
print('verified idempotent pcap import and explicit force-reimport')
PY
python - "$TMP_CHECK/sample.pcap" <<'PY'
import struct
import sys
from pathlib import Path
from kansoku.sample_pcap import internet_checksum

path = Path(sys.argv[1])
packets = []
with path.open("rb") as handle:
    assert handle.read(4) == b"\xd4\xc3\xb2\xa1"
    handle.read(20)
    while True:
        header = handle.read(16)
        if not header:
            break
        _, _, captured, _ = struct.unpack("<IIII", header)
        packets.append(handle.read(captured))
assert len(packets) == 4
for frame in packets:
    ethertype = struct.unpack("!H", frame[12:14])[0]
    offset = 14
    if ethertype == 0x8100:
        ethertype = struct.unpack("!H", frame[16:18])[0]
        offset = 18
    assert ethertype == 0x0800
    ip = frame[offset:]
    ihl = (ip[0] & 0x0F) * 4
    assert internet_checksum(ip[:ihl]) == 0
    protocol = ip[9]
    transport = ip[ihl:]
    pseudo = ip[12:16] + ip[16:20] + struct.pack("!BBH", 0, protocol, len(transport))
    assert internet_checksum(pseudo + transport) == 0
udp_payload = packets[-1][18 + 20 + 8:]
assert len(udp_payload) >= 12
assert struct.unpack("!H", udp_payload[4:6])[0] == 1
print('verified sample pcap checksums and DNS question')
PY
if command -v tcpdump >/dev/null 2>&1; then
  TCPDUMP_OUTPUT="$(tcpdump -nn -vvv -r "$TMP_CHECK/sample.pcap" 2>&1)"
  if printf '%s' "$TCPDUMP_OUTPUT" | grep -Ei 'bad cksum|incorrect|invalid' >/dev/null; then
    printf '%s\n' "$TCPDUMP_OUTPUT" >&2
    echo "sample pcap failed tcpdump validation" >&2
    exit 1
  fi
  echo "verified sample pcap with tcpdump"
fi
rm -rf "$TMP_CHECK"
trap - EXIT

if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  for path in .venv kansoku.db artifacts/lab/reports/summary.json artifacts/raw/example.json artifacts/pcap/test.pcap artifacts/network-state/frr.json artifacts/config/running.json capture-test.pcap .env .kansoku/spool/batch-test.json agent-token-test; do
    git check-ignore "$path" >/dev/null || {
      echo "expected Git ignore rule is missing for: $path" >&2
      exit 1
    }
  done
  if git ls-files | grep -E '(^|/)(\.env|.*\.(db|sqlite|sqlite3)|artifacts/raw/.*\.json|.*\.(pcap|pcapng)|.*\.agent-token|agent-token.*|\.kansoku/.*)$' >/dev/null; then
    echo "runtime or secret-like files are already tracked" >&2
    exit 1
  fi

  GIT_NAME="$(git config user.name || true)"
  GIT_EMAIL="$(git config user.email || true)"
  if [[ -z "$GIT_NAME" || -z "$GIT_EMAIL" || "$GIT_EMAIL" == *.local ]]; then
    cat >&2 <<EOF
Git author identity is not release-ready.
Current name:  ${GIT_NAME:-<unset>}
Current email: ${GIT_EMAIL:-<unset>}
Set an explicit GitHub email or GitHub noreply address before committing:
  git config --global user.name "Kohichi Ogawa"
  git config --global user.email "YOUR_GITHUB_EMAIL_OR_NOREPLY"
EOF
    exit 1
  fi
fi

KANSOKU_PYTHON="$PYTHON_BIN" ./scripts/v08_virtual_lab_smoke.sh
KANSOKU_PYTHON="$PYTHON_BIN" ./scripts/v09_recommendation_smoke.sh
KANSOKU_PYTHON="$PYTHON_BIN" ./scripts/v091_experiment_smoke.sh
KANSOKU_PYTHON="$PYTHON_BIN" ./scripts/v100_remediation_smoke.sh
./lab/scripts/lab-selftest.sh
echo "KANSOKU v0.10.0 pre-release checks passed"
