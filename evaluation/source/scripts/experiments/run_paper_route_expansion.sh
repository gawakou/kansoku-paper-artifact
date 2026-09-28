#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT_DIR"

export KANSOKU_PYTHON="${KANSOKU_PYTHON:-$ROOT_DIR/.venv-paper/bin/python}"
[[ -x "$KANSOKU_PYTHON" ]] || {
  echo "[FAIL] KANSOKU_PYTHON is not executable: $KANSOKU_PYTHON" >&2
  exit 1
}

source "$ROOT_DIR/lab/scripts/lib.sh"
for node in client-a sw1 fw1 r1 r2 sw2 server-a; do
  assert_container_running "$node"
done

# Start with the empirically gated core Route case. Boundary Route cases are
# intentionally added only after their live FRR/parser semantics are inspected.
SCENARIOS=(
  route-unreachable-next-hop
)

for scenario in "${SCENARIOS[@]}"; do
  echo "=== paper planned scenario: $scenario ==="
  bash "$ROOT_DIR/lab/scripts/scenarios/$scenario.sh"
  "$KANSOKU_PYTHON" "$ROOT_DIR/scripts/experiments/run_paper_ablation.py" \
    --db "$ROOT_DIR/artifacts/lab/db/$scenario.db" \
    --target-spec "$ROOT_DIR/scenarios/paper/target_https.json" \
    --output-dir "$ROOT_DIR/artifacts/paper/$scenario"
done

"$KANSOKU_PYTHON" - "$ROOT_DIR/artifacts/paper" "${SCENARIOS[@]}" <<'PY'
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
for scenario in sys.argv[2:]:
    data = json.loads((root / scenario / "diagnostics.json").read_text(encoding="utf-8"))
    print(f"\n=== {scenario} ===")
    for method in ("FLOW_ONLY", "CONFIG_ONLY", "PROPOSED"):
        row = data["results"][method]
        print(
            f"{method:12s} verdict={row['verdict']:12s} "
            f"domain={row['fault_domain']:10s} "
            f"abstained={str(row['abstained']):5s} "
            f"element={row['affected_element_ref']}"
        )
PY
