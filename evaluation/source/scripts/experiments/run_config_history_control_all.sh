#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT_DIR"
PYTHON_BIN="${KANSOKU_PYTHON:-${ROOT_DIR}/.venv-paper/bin/python}"
[[ -x "$PYTHON_BIN" ]] || PYTHON_BIN="${KANSOKU_PYTHON:-python3}"
SPEC="scenarios/paper/config_history_control_v1.json"
REPETITIONS="${1:-1}"
if ! [[ "$REPETITIONS" =~ ^[1-5]$ ]]; then
  echo "usage: $0 [number-of-repetitions:1..5]" >&2
  exit 2
fi
mapfile -t INSTANCES < <("$PYTHON_BIN" - "$SPEC" <<'PY'
import json, sys
for iid in json.load(open(sys.argv[1], encoding='utf-8'))['instances']:
    print(iid)
PY
)
for iid in "${INSTANCES[@]}"; do
  for ((rep=1; rep<=REPETITIONS; rep++)); do
    scripts/experiments/run_config_history_control_instance.sh "$iid" "$rep"
  done
done
