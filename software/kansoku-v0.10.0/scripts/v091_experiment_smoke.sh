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
  PYTHON_BIN="$(command -v python)"
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
DB="$TMP_DIR/experiment.db"
EXPORT_DIR="$TMP_DIR/export"

"$PYTHON_BIN" -m kansoku --db "$DB" init >/dev/null
EXPERIMENT_JSON="$("$PYTHON_BIN" -m kansoku --db "$DB" experiment create \
  --name "pre-release experiment" \
  --scenario normal --scenario firewall-deny \
  --repetitions 2 --base-seed 100 \
  --baseline flow-only --baseline configuration-only \
  --tag suite=pre-release)"
EXPERIMENT_ID="$("$PYTHON_BIN" - "$EXPERIMENT_JSON" <<'PY'
import json, sys
print(json.loads(sys.argv[1])["experiment_id"])
PY
)"

"$PYTHON_BIN" -m kansoku --db "$DB" experiment record \
  --experiment-id "$EXPERIMENT_ID" --scenario-id normal \
  --repetition 1 --seed 101 --status PASS \
  --expected-verdict ALLOW --observed-verdict ALLOW \
  --timing diagnosis=12.5 --timing total=30 \
  --counter observation_bytes=2048 >/dev/null
"$PYTHON_BIN" -m kansoku --db "$DB" experiment record \
  --experiment-id "$EXPERIMENT_ID" --scenario-id firewall-deny \
  --repetition 1 --seed 102 --status PASS \
  --expected-verdict DENY --observed-verdict DENY \
  --expected-category FIREWALL_POLICY --observed-category FIREWALL_POLICY \
  --timing diagnosis=14 --timing recommendation=8 >/dev/null
"$PYTHON_BIN" -m kansoku --db "$DB" experiment status \
  --experiment-id "$EXPERIMENT_ID" --status COMPLETED >/dev/null
"$PYTHON_BIN" -m kansoku --db "$DB" experiment export \
  --experiment-id "$EXPERIMENT_ID" --output-dir "$EXPORT_DIR" >/dev/null
"$PYTHON_BIN" -m kansoku experiment validate-catalog \
  --file scenarios/evaluation/catalog.json >/dev/null

"$PYTHON_BIN" - "$EXPORT_DIR/summary.json" "$EXPORT_DIR/trials.csv" <<'PY'
import csv, json, sys
summary = json.load(open(sys.argv[1], encoding="utf-8"))
assert summary["trial_count"] == 2, summary
assert summary["status_counts"]["PASS"] == 2, summary
assert summary["verdict"]["accuracy"] == 1.0, summary
assert summary["recommendation"]["accuracy"] == 1.0, summary
with open(sys.argv[2], newline="", encoding="utf-8") as handle:
    rows = list(csv.DictReader(handle))
assert len(rows) == 2, rows
assert {row["scenario_id"] for row in rows} == {"normal", "firewall-deny"}
PY

echo "verified v0.9.1 reproducible experiment definition, metrics, CSV, and catalog"
