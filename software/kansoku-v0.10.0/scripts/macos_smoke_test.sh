#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 2; }
command -v ping >/dev/null || { echo "ping is required" >&2; exit 2; }
command -v iperf3 >/dev/null || { echo "iperf3 is required: brew install iperf3" >&2; exit 2; }
command -v curl >/dev/null || { echo "curl is required" >&2; exit 2; }

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
python -m compileall -q kansoku
python -m pytest -q

DB="${TMPDIR:-/tmp}/kansoku-v08-macos-smoke.db"
RAW="${TMPDIR:-/tmp}/kansoku-v08-macos-raw"
PORT=55201
WEB_PORT=58085
rm -f "$DB"
rm -rf "$RAW"

kansoku --db "$DB" init
kansoku --db "$DB" profile set \
  --target 127.0.0.1 \
  --name "macOS loopback smoke profile" \
  --expected-bandwidth 100 \
  --normal-interval 30 \
  --warning-interval 5
kansoku --db "$DB" policy set \
  --target 127.0.0.1 \
  --name "macOS loopback safe policy" \
  --minimum-interval 2 \
  --no-allow-system-changes
kansoku --db "$DB" target set \
  --target 127.0.0.1 \
  --name "macOS loopback managed target" \
  --ping-enabled \
  --ping-count 2 \
  --ping-timeout 2 \
  --iperf3-enabled \
  --iperf3-port "$PORT" \
  --iperf3-duration 2 \
  --iperf3-every 1 \
  --raw-dir "$RAW"

IPERF_LOG="${TMPDIR:-/tmp}/kansoku-v08-iperf3-server.log"
iperf3 -s -1 -p "$PORT" >"$IPERF_LOG" 2>&1 &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null || true' EXIT
sleep 1
kansoku --db "$DB" service once \
  --target 127.0.0.1 \
  --force \
  --no-auto-control \
  --owner-id macos-smoke-service
wait "$SERVER_PID"
trap - EXIT

kansoku --db "$DB" service status --target 127.0.0.1
kansoku --db "$DB" service cycles --target 127.0.0.1 --limit 5

SAMPLE_PCAP="${TMPDIR:-/tmp}/kansoku-v08-sample.pcap"
python scripts/generate_sample_pcap.py "$SAMPLE_PCAP"
kansoku --db "$DB" capture summarize \
  --pcap "$SAMPLE_PCAP" \
  --target 127.0.0.1 \
  --source macos-smoke-pcap \
  --flow-limit 10
kansoku --db "$DB" capture list --target 127.0.0.1
kansoku --db "$DB" capture flows --target 127.0.0.1 --limit 10

LOW_PROPOSAL_ID="$(python - "$DB" <<'PY'
import sys
from kansoku.hub import Hub
from kansoku.models import ActionProposal
hub=Hub(sys.argv[1])
proposal=ActionProposal(
    target='127.0.0.1',
    action='increase_observation_rate',
    parameters={'interval_sec': 5},
    expected_effect='Increase observation frequency for smoke verification.',
    rollback={'action':'restore_observation_rate','parameters':{'interval_sec':30}},
    source_state_id=(hub.latest_state('127.0.0.1').state_id),
    risk_level='low',
    preconditions=['target is observable'],
    postconditions=['observation interval becomes 5 seconds'],
)
hub.add_proposal(proposal)
print(proposal.proposal_id)
PY
)"

kansoku --db "$DB" controller process \
  --proposal-id "$LOW_PROPOSAL_ID" \
  --execute

ROUTE_PROPOSAL_ID="$(python - "$DB" <<'PY'
import sys
from kansoku.hub import Hub
from kansoku.models import ActionProposal
hub=Hub(sys.argv[1])
proposal=ActionProposal(
    target='127.0.0.1',
    action='switch_route',
    parameters={'route':'secondary'},
    expected_effect='Exercise the approval workflow without changing a route.',
    rollback={'action':'switch_route','parameters':{'route':'primary'}},
    source_state_id=hub.latest_state('127.0.0.1').state_id,
    risk_level='medium',
    preconditions=['secondary route exists'],
    postconditions=['packet loss decreases'],
)
hub.add_proposal(proposal)
print(proposal.proposal_id)
PY
)"

kansoku --db "$DB" controller process --proposal-id "$ROUTE_PROPOSAL_ID"
kansoku --db "$DB" approval set \
  --proposal-id "$ROUTE_PROPOSAL_ID" \
  --decision approve \
  --actor macos-smoke \
  --comment "Dry-run approval workflow test"
kansoku --db "$DB" controller process --proposal-id "$ROUTE_PROPOSAL_ID"

AGENT_TOKEN_FILE="${TMPDIR:-/tmp}/kansoku-v08-agent-token"
SPOOL_DIR="${TMPDIR:-/tmp}/kansoku-v08-spool"
INGEST_PORT=58090
rm -f "$AGENT_TOKEN_FILE"
rm -rf "$SPOOL_DIR"
kansoku --db "$DB" remote-agent create \
  --name "macOS remote smoke agent" \
  --agent-id macos-remote-smoke \
  --capabilities ping,simulation,pcap,flow \
  --label site=loopback \
  --token-file "$AGENT_TOKEN_FILE"

kansoku --db "$DB" ingest serve --host 127.0.0.1 --port "$INGEST_PORT" >"${TMPDIR:-/tmp}/kansoku-v08-ingest.log" 2>&1 &
INGEST_PID=$!
trap 'kill "$INGEST_PID" 2>/dev/null || true' EXIT
sleep 1
kansoku edge simulate \
  --hub-url "http://127.0.0.1:${INGEST_PORT}" \
  --agent-id macos-remote-smoke \
  --token-file "$AGENT_TOKEN_FILE" \
  --spool-dir "$SPOOL_DIR" \
  --target remote-smoke \
  --profile warning \
  --count 2
kansoku edge pcap \
  --hub-url "http://127.0.0.1:${INGEST_PORT}" \
  --agent-id macos-remote-smoke \
  --token-file "$AGENT_TOKEN_FILE" \
  --spool-dir "$SPOOL_DIR" \
  --pcap "$SAMPLE_PCAP" \
  --target remote-pcap-smoke \
  --source macos-remote-pcap \
  --send-flow-limit 20
kansoku edge heartbeat \
  --hub-url "http://127.0.0.1:${INGEST_PORT}" \
  --agent-id macos-remote-smoke \
  --token-file "$AGENT_TOKEN_FILE" \
  --spool-dir "$SPOOL_DIR"
kansoku edge status --spool-dir "$SPOOL_DIR"
kill "$INGEST_PID" 2>/dev/null || true
wait "$INGEST_PID" 2>/dev/null || true
trap - EXIT

kansoku --db "$DB" view --target 127.0.0.1 --limit 20
kansoku --db "$DB" view --target remote-smoke --limit 20
kansoku --db "$DB" view --target remote-pcap-smoke --limit 20

kansoku --db "$DB" web --host 127.0.0.1 --port "$WEB_PORT" >"${TMPDIR:-/tmp}/kansoku-v08-web.log" 2>&1 &
WEB_PID=$!
trap 'kill "$WEB_PID" 2>/dev/null || true' EXIT
sleep 1
curl --fail --silent "http://127.0.0.1:${WEB_PORT}/api/targets" | python -m json.tool
curl --fail --silent "http://127.0.0.1:${WEB_PORT}/api/fleet" >"${TMPDIR:-/tmp}/kansoku-v08-fleet.json"
curl --fail --silent "http://127.0.0.1:${WEB_PORT}/api/agents" >"${TMPDIR:-/tmp}/kansoku-v08-agents.json"
curl --fail --silent "http://127.0.0.1:${WEB_PORT}/api/snapshot?target=127.0.0.1" >"${TMPDIR:-/tmp}/kansoku-v08-snapshot.json"
kill "$WEB_PID" 2>/dev/null || true
wait "$WEB_PID" 2>/dev/null || true
trap - EXIT

python - "$DB" "${TMPDIR:-/tmp}/kansoku-v08-snapshot.json" "${TMPDIR:-/tmp}/kansoku-v08-fleet.json" "${TMPDIR:-/tmp}/kansoku-v08-agents.json" <<'PY'
import json
import sqlite3
import sys

db, snapshot_path, fleet_path, agents_path = sys.argv[1:]
with sqlite3.connect(db) as conn:
    state_count = conn.execute("SELECT COUNT(*) FROM states WHERE target='127.0.0.1'").fetchone()[0]
    target_count = conn.execute("SELECT COUNT(*) FROM managed_targets WHERE target='127.0.0.1'").fetchone()[0]
    cycle_count = conn.execute("SELECT COUNT(*) FROM scheduler_cycles WHERE target='127.0.0.1'").fetchone()[0]
    lease_count = conn.execute("SELECT COUNT(*) FROM scheduler_leases").fetchone()[0]
    policy_count = conn.execute("SELECT COUNT(*) FROM safety_policies WHERE target='127.0.0.1'").fetchone()[0]
    approval_count = conn.execute("SELECT COUNT(*) FROM approvals").fetchone()[0]
    verification_count = conn.execute("SELECT COUNT(*) FROM verifications").fetchone()[0]
    transaction_count = conn.execute("SELECT COUNT(*) FROM control_transactions").fetchone()[0]
    remote_agent_count = conn.execute("SELECT COUNT(*) FROM remote_agents").fetchone()[0]
    heartbeat_count = conn.execute("SELECT COUNT(*) FROM agent_heartbeats").fetchone()[0]
    ingest_count = conn.execute("SELECT COUNT(*) FROM ingest_batches").fetchone()[0]
    capture_count = conn.execute("SELECT COUNT(*) FROM capture_sessions").fetchone()[0]
    flow_count = conn.execute("SELECT COUNT(*) FROM flow_records").fetchone()[0]
assert state_count >= 1, state_count
assert target_count == 1, target_count
assert cycle_count >= 1, cycle_count
assert lease_count == 0, lease_count
assert policy_count == 1, policy_count
assert approval_count == 1, approval_count
assert verification_count >= 2, verification_count
assert transaction_count >= 3, transaction_count
assert remote_agent_count == 1, remote_agent_count
assert heartbeat_count == 1, heartbeat_count
assert ingest_count >= 2, ingest_count
assert capture_count >= 2, capture_count
assert flow_count >= 6, flow_count
snapshot = json.load(open(snapshot_path))
fleet = json.load(open(fleet_path))
agents = json.load(open(agents_path))
assert snapshot['managed_target']['name'] == 'macOS loopback managed target'
assert snapshot['scheduler_cycles'], snapshot
assert snapshot['safety_policy']['name'] == 'macOS loopback safe policy'
assert snapshot['action_lifecycle'], snapshot
assert snapshot['captures'], snapshot
assert snapshot['flows'], snapshot
assert fleet['fleet'][0]['target']['target'] == '127.0.0.1'
assert agents['agents'][0]['agent']['agent_id'] == 'macos-remote-smoke'
assert agents['agents'][0]['latest_heartbeat']['queue_depth'] == 0
print(
    f"verified states={state_count}, targets={target_count}, cycles={cycle_count}, "
    f"policies={policy_count}, approvals={approval_count}, "
    f"verifications={verification_count}, transactions={transaction_count}, "
    f"remote_agents={remote_agent_count}, heartbeats={heartbeat_count}, ingests={ingest_count}, "
    f"captures={capture_count}, flows={flow_count}"
)
PY

./scripts/v08_virtual_lab_smoke.sh

echo
echo "macOS v0.8 smoke test completed"
echo "database: $DB"
echo "raw artifacts: $RAW"
echo "dashboard: kansoku --db '$DB' web --host 127.0.0.1 --port 8080"
