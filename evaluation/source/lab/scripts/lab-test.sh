#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "$0")" && pwd)/lib.sh"

for node in client-a sw1 fw1 r1 r2 sw2 server-a; do
  assert_container_running "$node"
done

rm -rf "$ARTIFACT_DIR"
mkdir -p "$DB_DIR" "$PCAP_DIR" "$REPORT_DIR"

SCENARIOS=(normal firewall-deny route-missing vlan-mismatch packet-loss)
PASSED=0
for scenario in "${SCENARIOS[@]}"; do
  echo "=== scenario: $scenario ==="
  "$LAB_DIR/scripts/scenarios/$scenario.sh"
  PASSED=$((PASSED + 1))
done
reset_network

recommendation_test() {
  local scenario="$1"
  local expected_category="$2"
  shift 2
  local db="$DB_DIR/$scenario.db"
  local assessment_id
  assessment_id="$("$KANSOKU_PYTHON" - "$db" "$scenario" <<'PY'
import json, sqlite3, sys
scenario = sys.argv[2]
with sqlite3.connect(sys.argv[1]) as conn:
    if scenario == "firewall-deny":
        row = conn.execute(
            "SELECT assessment_id FROM flow_assessments WHERE verdict='DENY' ORDER BY timestamp LIMIT 1"
        ).fetchone()
    elif scenario == "route-missing":
        row = conn.execute(
            "SELECT assessment_id FROM flow_assessments WHERE verdict='UNROUTABLE' ORDER BY timestamp LIMIT 1"
        ).fetchone()
    else:
        row = None
        for assessment_id, raw in conn.execute(
            "SELECT assessment_id, payload FROM flow_assessments ORDER BY timestamp"
        ):
            if json.loads(raw).get("vlan_status") == "UNKNOWN_VLAN":
                row = (assessment_id,)
                break
assert row, scenario
print(row[0])
PY
)"
  local payload
  payload="$(ks --db "$db" recommend generate \
    --assessment-id "$assessment_id" \
    --route-device r1 --policy-device fw1 --vlan-device sw1 "$@")"
  "$KANSOKU_PYTHON" - "$expected_category" "$payload" > "$REPORT_DIR/$scenario-recommendation.json" <<'PY'
import json, sys
expected=sys.argv[1]
payload=json.loads(sys.argv[2])
assert payload["category"] == expected, payload
assert payload["simulation_status"] == "PASSED", payload
assert payload["simulated_verdict"] == "ALLOW", payload
assert payload["status"] == "DRAFT", payload
assert payload["commands"] and payload["rollback_commands"], payload
print(json.dumps(payload, indent=2, sort_keys=True))
PY
  echo "[PASS] $scenario recommendation → $expected_category / ALLOW"
}

echo "=== configuration recommendations ==="
recommendation_test firewall-deny FIREWALL_POLICY
recommendation_test route-missing ROUTE \
  --destination-prefix 10.20.20.0/24 --next-hop 172.16.1.2 --out-interface eth2
recommendation_test vlan-mismatch VLAN \
  --access-interface eth1 --trunk-interface eth2

recommendation_id_for() {
  local scenario="$1"
  "$KANSOKU_PYTHON" - "$REPORT_DIR/$scenario-recommendation.json" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["recommendation_id"])
PY
}

inject_fault() {
  local scenario="$1"
  case "$scenario" in
    firewall-deny)
      run_node fw1 nft insert rule inet filter forward \
        ip saddr 10.10.10.0/24 ip daddr 10.20.20.10 tcp dport 443 \
        counter drop comment '"kansoku fault deny"'
      ;;
    route-missing)
      run_node r1 vtysh -c 'configure terminal' -c 'no ip route 10.20.20.0/24 172.16.1.2'
      ;;
    vlan-mismatch)
      run_node sw1 ovs-vsctl set Port eth1 tag=30
      run_node sw1 ovs-vsctl set Port eth2 trunks=30
      ;;
    *)
      echo "unknown remediation scenario: $scenario" >&2
      return 1
      ;;
  esac
  sleep 1
}

remediation_test() {
  local scenario="$1"
  local db="$DB_DIR/$scenario.db"
  local recommendation_id
  recommendation_id="$(recommendation_id_for "$scenario")"
  reset_network
  inject_fault "$scenario"
  if run_node client-a curl -fsS --connect-timeout 2 --max-time 4 http://10.20.20.10:443/ >/dev/null 2>&1; then
    echo "[FAIL] $scenario fault was not active before remediation" >&2
    return 1
  fi
  ks --db "$db" recommend review \
    --recommendation-id "$recommendation_id" \
    --status APPROVED --reviewed-by virtual-lab-test \
    --note "automated containerlab-only approval" >/dev/null
  local execution
  execution="$(ks --db "$db" recommend apply-lab \
    --recommendation-id "$recommendation_id" \
    --environment virtual-lab \
    --approved-by virtual-lab-test \
    --lab-name "$LAB_NAME")"
  "$KANSOKU_PYTHON" - "$scenario" "$execution" > "$REPORT_DIR/$scenario-remediation.json" <<'PY'
import json, sys
scenario = sys.argv[1]
payload = json.loads(sys.argv[2])
assert payload["status"] == "ROLLED_BACK", payload
assert payload["verification"]["passed"] is True, payload
assert payload["verification"]["observed_success"] is True, payload
assert payload["rollback_verification"]["passed"] is True, payload
assert payload["rollback_verification"]["observed_success"] is False, payload
payload["scenario"] = scenario
payload["recovered"] = True
print(json.dumps(payload, indent=2, sort_keys=True))
PY
  reset_network
  echo "[PASS] $scenario approved lab remediation → verify → rollback"
}

echo "=== guarded virtual-lab remediation ==="
remediation_test firewall-deny
remediation_test route-missing
remediation_test vlan-mismatch

"$KANSOKU_PYTHON" - "$REPORT_DIR" "$PASSED" "${#SCENARIOS[@]}" > "$REPORT_DIR/summary.json" <<'PY'
import json
from pathlib import Path
import sys
report_dir = Path(sys.argv[1])
reports = []
for path in sorted(report_dir.glob("*.json")):
    if path.name != "summary.json":
        reports.append(json.loads(path.read_text()))
print(json.dumps({
    "suite": "kansoku-v0.10.0-containerlab",
    "passed": int(sys.argv[2]),
    "total": int(sys.argv[3]),
    "scenarios": reports,
}, indent=2, sort_keys=True))
PY

EVALUATION_DB="$ARTIFACT_DIR/evaluation.db"
EVALUATION_DIR="$ARTIFACT_DIR/evaluation"
mkdir -p "$EVALUATION_DIR"
ks --db "$EVALUATION_DB" init >/dev/null
EXPERIMENT_JSON="$(ks --db "$EVALUATION_DB" experiment create \
  --name "KANSOKU v0.10.0 virtual-lab evaluation" \
  --description "Five fault scenarios, three recommendation what-if checks, and three guarded lab remediations" \
  --scenario normal \
  --scenario firewall-deny \
  --scenario route-missing \
  --scenario vlan-mismatch \
  --scenario packet-loss \
  --scenario firewall-deny-recommendation \
  --scenario route-missing-recommendation \
  --scenario vlan-mismatch-recommendation \
  --scenario firewall-deny-remediation \
  --scenario route-missing-remediation \
  --scenario vlan-mismatch-remediation \
  --repetitions 1 --base-seed 1 \
  --baseline flow-only --baseline configuration-only \
  --tag environment=containerlab --tag release=v0.10.0)"
EXPERIMENT_ID="$("$KANSOKU_PYTHON" - "$EXPERIMENT_JSON" <<'PY'
import json, sys
print(json.loads(sys.argv[1])["experiment_id"])
PY
)"
ks experiment manifest \
  --output "$EVALUATION_DIR/environment.json" \
  --label topology=kansoku-v100 \
  --label suite=virtual-lab >/dev/null
ks --db "$EVALUATION_DB" experiment import-lab \
  --experiment-id "$EXPERIMENT_ID" \
  --summary "$REPORT_DIR/summary.json" \
  --repetition 1 --seed 1 \
  --environment-manifest "$EVALUATION_DIR/environment.json" >/dev/null
ks --db "$EVALUATION_DB" experiment status \
  --experiment-id "$EXPERIMENT_ID" --status COMPLETED >/dev/null
ks --db "$EVALUATION_DB" experiment export \
  --experiment-id "$EXPERIMENT_ID" \
  --output-dir "$EVALUATION_DIR/export" >/dev/null
"$KANSOKU_PYTHON" - "$EVALUATION_DIR/export/summary.json" <<'PY'
import json, sys
payload = json.load(open(sys.argv[1], encoding="utf-8"))
assert payload["trial_count"] == 11, payload
assert payload["status_counts"]["PASS"] == 11, payload
assert payload["verdict"]["accuracy"] == 1.0, payload
assert payload["recommendation"]["accuracy"] == 1.0, payload
assert payload["recovery"]["accuracy"] == 1.0, payload
PY

echo "[PASS] $PASSED/${#SCENARIOS[@]} virtual-lab scenarios, 3/3 recommendation checks, and 3/3 guarded remediations"
echo "[PASS] reproducible experiment import/export → 11 trials"
echo "report: $REPORT_DIR/summary.json"
echo "evaluation: $EVALUATION_DIR/export/summary.json"
