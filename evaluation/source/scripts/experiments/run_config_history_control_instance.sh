#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT_DIR"
source lab/scripts/lib.sh

SPEC="scenarios/paper/config_history_control_v1.json"
PLAN="scenarios/paper/parameterized_instances.json"
FREEZE_TAG="${KANSOKU_CONFIG_HISTORY_FREEZE_TAG:-paper-config-history-control-v1.1-freeze}"
RUNNER="scripts/experiments/run_config_history_control_instance.sh"
DIAG="scripts/experiments/run_config_history_diagnosis.py"
EVAL="scripts/experiments/evaluate_config_history_control.py"

INSTANCE_ID="${1:?usage: run_config_history_control_instance.sh INSTANCE_ID [REPETITION]}"
REPETITION="${2:-1}"
if ! [[ "$REPETITION" =~ ^[1-5]$ ]]; then
  echo "[FAIL] repetition must be 1..5" >&2
  exit 2
fi

# Require the protocol, runner, diagnoser, evaluator, and source plan to match
# the pre-execution freeze tag. This is version freezing, not external preregistration.
git rev-parse -q --verify "refs/tags/$FREEZE_TAG" >/dev/null || {
  echo "[FAIL] freeze tag not found: $FREEZE_TAG" >&2
  exit 2
}
for path in "$SPEC" "$PLAN" "$RUNNER" "$DIAG" "$EVAL"; do
  if ! git diff --quiet "$FREEZE_TAG" -- "$path"; then
    echo "[FAIL] $path differs from freeze tag $FREEZE_TAG" >&2
    exit 2
  fi
done

FREEZE_SHA="$(git rev-list -n 1 "$FREEZE_TAG")"
EXECUTION_SHA="$(git rev-parse HEAD)"
OUT_ROOT="${KANSOKU_CONFIG_HISTORY_OUT:-$ROOT_DIR/artifacts/paper/config-history-control-v1.1}"
OUT="$OUT_ROOT/$INSTANCE_ID/rep-$(printf '%02d' "$REPETITION")"
if [[ -e "$OUT" && "${KANSOKU_CONFIG_HISTORY_OVERWRITE:-0}" != "1" ]]; then
  echo "[FAIL] output already exists: $OUT" >&2
  exit 2
fi
rm -rf "$OUT"
mkdir -p "$OUT"

PRE_DB="$OUT/pre-state.db"
POST_DB="$OUT/post-state.db"
TARGET_SPEC="$OUT/target.json"

# Load the execution instance and fault parameter from the source plan. The
# diagnoser never sees DRIFT_VLAN or the ground-truth manifest.
eval "$(
"$KANSOKU_PYTHON" - "$SPEC" "$PLAN" "$INSTANCE_ID" "$TARGET_SPEC" <<'PY'
import json, shlex, sys
spec_path, plan_path, iid, target_out = sys.argv[1:]
spec = json.load(open(spec_path, encoding='utf-8'))
plan = json.load(open(plan_path, encoding='utf-8'))
if iid not in spec['instances']:
    raise SystemExit(f'instance not allowed by frozen control spec: {iid}')
row = plan['instances'][iid]
if row.get('prototype_id') != 'vlan-mismatch':
    raise SystemExit(f'control accepts only vlan-mismatch instances: {iid}')
target = dict(row['target'])

# The runtime query ID must not encode the prototype/fault family.
# Example: vlan-mismatch-v01 -> config-history-01.
variant = iid.rsplit('-v', 1)[-1]
if not variant.isdigit():
    raise SystemExit(f'cannot derive opaque runtime query ID from instance: {iid}')
target['query_id'] = f'config-history-{variant}'
with open(target_out, 'w', encoding='utf-8') as f:
    json.dump(target, f, indent=2, sort_keys=True)
    f.write('\n')
print('DRIFT_VLAN=' + shlex.quote(str(row['parameters']['drift_vlan'])))
print('DST_IP=' + shlex.quote(str(target['dst_ip'])))
PY
)"

reset_and_verify() {
  reset_network >/dev/null
  run_node client-a curl -fsS --connect-timeout 2 --max-time 4 \
    "http://${DST_IP}:443/" >/dev/null || {
      echo "[FAIL] canonical healthy target connectivity not restored" >&2
      return 1
    }
}

cleanup() {
  set +e
  reset_network >/dev/null 2>&1 || true
}
trap cleanup EXIT

printf '===== CONFIG_HISTORY_ONLY control =====\n'
printf 'instance    : %s\n' "$INSTANCE_ID"
printf 'repetition  : %s\n' "$REPETITION"
printf 'drift VLAN  : %s (runner-only injection parameter)\n' "$DRIFT_VLAN"
printf 'freeze tag  : %s\n' "$FREEZE_TAG"
printf 'freeze SHA  : %s\n' "$FREEZE_SHA"
printf 'exec SHA    : %s\n' "$EXECUTION_SHA"
printf 'output      : %s\n' "$OUT"

printf '[1/7] reset and verify healthy baseline\n'
reset_and_verify

printf '[2/7] collect pre-fault normalized configuration\n'
collect_live_state "$PRE_DB"

printf '[3/7] inject VLAN drift\n'
run_node sw1 ovs-vsctl set Port eth1 tag="$DRIFT_VLAN"
run_node sw1 ovs-vsctl set Port eth2 trunks="$DRIFT_VLAN"
sleep 1

printf '[4/7] verify target fault effect\n'
if run_node client-a curl -fsS --connect-timeout 2 --max-time 4 \
    "http://${DST_IP}:443/" >/dev/null 2>&1; then
  echo "[FAIL] target remained reachable after VLAN drift" >&2
  exit 1
fi

printf '[5/7] collect post-fault normalized configuration\n'
collect_live_state "$POST_DB"

printf '[6/7] run CONFIG_HISTORY_ONLY diagnosis (no packet/flow input)\n'
"$KANSOKU_PYTHON" "$DIAG" \
  --pre-db "$PRE_DB" \
  --post-db "$POST_DB" \
  --target-spec "$TARGET_SPEC" \
  --output-dir "$OUT" \
  > "$OUT/diagnosis.stdout.json"

"$KANSOKU_PYTHON" - "$OUT/trial.json" "$INSTANCE_ID" "$REPETITION" "$FREEZE_TAG" "$FREEZE_SHA" "$EXECUTION_SHA" <<'PY'
import datetime, json, sys
out, iid, rep, tag, freeze_sha, exec_sha = sys.argv[1:]
payload = {
    'schema_version': 1,
    'control_id': 'config-history-v1.1',
    'instance_id': iid,
    'repetition': int(rep),
    'method': 'CONFIG_HISTORY_ONLY',
    'freeze_tag': tag,
    'freeze_commit': freeze_sha,
    'execution_commit': exec_sha,
    'packet_or_flow_input_used': False,
    'ground_truth_consumed_by_runner_or_diagnoser': False,
    'completed_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
}
with open(out, 'w', encoding='utf-8') as f:
    json.dump(payload, f, indent=2, sort_keys=True)
    f.write('\n')
PY

printf '[7/7] restore and verify canonical healthy baseline\n'
reset_and_verify
trap - EXIT

echo "[PASS] $INSTANCE_ID repetition $REPETITION"
echo "diagnostics: $OUT/diagnostics.json"
