#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LAB_DIR="$ROOT_DIR/lab"
TOPOLOGY="$LAB_DIR/containerlab/kansoku.clab.yml"
LAB_NAME="kansoku-v100"
DOCKER_BIN="${DOCKER_BIN:-docker}"
ARTIFACT_DIR="${KANSOKU_LAB_ARTIFACT_DIR:-$ROOT_DIR/artifacts/lab}"
DB_DIR="$ARTIFACT_DIR/db"
PCAP_DIR="$ARTIFACT_DIR/pcap"
REPORT_DIR="$ARTIFACT_DIR/reports"
KANSOKU_TCPDUMP_BIN="${KANSOKU_TCPDUMP_BIN:-/usr/local/libexec/kansoku-tcpdump}"

mkdir -p "$DB_DIR" "$PCAP_DIR" "$REPORT_DIR"

if [[ -n "${KANSOKU_PYTHON:-}" ]]; then
  KANSOKU_PYTHON="$KANSOKU_PYTHON"
elif [[ -x "$ROOT_DIR/.lab-venv/bin/python" ]]; then
  KANSOKU_PYTHON="$ROOT_DIR/.lab-venv/bin/python"
elif [[ -x "$ROOT_DIR/.venv/bin/python" ]]; then
  KANSOKU_PYTHON="$ROOT_DIR/.venv/bin/python"
else
  KANSOKU_PYTHON="$(command -v python3 || command -v python)"
fi

container_name() {
  printf 'clab-%s-%s\n' "$LAB_NAME" "$1"
}

run_node() {
  local node="$1"
  shift
  "$DOCKER_BIN" exec "$(container_name "$node")" "$@"
}

run_node_shell() {
  local node="$1"
  shift
  "$DOCKER_BIN" exec "$(container_name "$node")" bash -lc "$*"
}

run_node_detached() {
  local node="$1"
  shift
  "$DOCKER_BIN" exec -d "$(container_name "$node")" "$@"
}

dump_server_diagnostics() {
  echo "--- server-a diagnostics ---" >&2
  run_node server-a ip -brief address show 2>&1 >&2 || true
  run_node server-a ip route show 2>&1 >&2 || true
  run_node server-a ss -lntp 2>&1 >&2 || true
  run_node server-a ps -ef 2>&1 >&2 || true
  run_node server-a sh -c 'cat /var/log/kansoku-http.log 2>/dev/null || true' 2>&1 >&2 || true
  echo "--- end diagnostics ---" >&2
}

start_server_services() {
  run_node server-a sh -c "pkill -f '^python3 .*http.server 443 ' 2>/dev/null || true; pkill -x iperf3 2>/dev/null || true; rm -f /var/log/kansoku-http.log"
  run_node_detached server-a sh -c "exec python3 -u -m http.server 443 --bind 10.20.20.10 --directory /srv/kansoku >/var/log/kansoku-http.log 2>&1"
  run_node server-a iperf3 -s -D
}

wait_for_server_services() {
  wait_for_command 30 1 run_node server-a sh -c "ss -lnt | grep -Eq '[:.]443[[:space:]]'" || {
    echo "[FAIL] server-a HTTP listener did not become ready" >&2
    dump_server_diagnostics
    return 1
  }
  wait_for_command 30 1 run_node server-a sh -c "ss -lnt | grep -Eq '[:.]5201[[:space:]]'" || {
    echo "[FAIL] server-a iperf3 listener did not become ready" >&2
    dump_server_diagnostics
    return 1
  }
  wait_for_command 30 1 run_node server-a curl -fsS --connect-timeout 1 --max-time 2 http://10.20.20.10:443/ || {
    echo "[FAIL] server-a local HTTP health check failed" >&2
    dump_server_diagnostics
    return 1
  }
}

ensure_server_services() {
  if ! run_node server-a sh -c "ss -lnt | grep -Eq '[:.]443[[:space:]]'" >/dev/null 2>&1 || \
     ! run_node server-a sh -c "ss -lnt | grep -Eq '[:.]5201[[:space:]]'" >/dev/null 2>&1; then
    start_server_services
  fi
  wait_for_server_services
}

ks() {
  "$KANSOKU_PYTHON" -m kansoku "$@"
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "[FAIL] required command not found: $1" >&2
    return 1
  }
}

assert_container_running() {
  local node="$1"
  local name
  name="$(container_name "$node")"
  [[ "$("$DOCKER_BIN" inspect -f '{{.State.Running}}' "$name" 2>/dev/null || true)" == "true" ]] || {
    echo "[FAIL] container is not running: $name" >&2
    return 1
  }
}

wait_for_command() {
  local attempts="$1"
  local sleep_seconds="$2"
  shift 2
  local i
  for ((i=1; i<=attempts; i++)); do
    if "$@" >/dev/null 2>&1; then
      return 0
    fi
    sleep "$sleep_seconds"
  done
  return 1
}

reset_network() {
  run_node sw1 ovs-vsctl set Port eth1 tag=10
  run_node sw1 ovs-vsctl clear Port eth1 trunks
  run_node sw1 ovs-vsctl clear Port eth2 tag
  run_node sw1 ovs-vsctl set Port eth2 trunks=10
  run_node fw1 nft -f /etc/kansoku/ruleset.nft

  # Restore the target route to one canonical healthy configuration.  Purge
  # every route variant used by the paper fault scenarios first so that a
  # previous trial cannot survive in FRR running-config as an inactive static
  # route and contaminate the next nominally single-fault trial.
  run_node r1 vtysh \
    -c 'configure terminal' \
    -c 'no ip route 10.20.20.0/24 172.16.1.2' \
    -c 'no ip route 10.20.20.0/24 172.16.1.254' \
    -c 'no ip route 10.20.20.0/24 eth1' \
    -c 'no ip route 10.20.20.10/32 blackhole' \
    -c 'ip route 10.20.20.0/24 172.16.1.2' >/dev/null

  run_node r1 sh -c 'tc qdisc del dev eth2 root 2>/dev/null || true'
  ensure_server_services
  sleep 1
}

collect_state_or_fail() {
  local label="$1"
  shift
  local output
  if ! output="$(ks "$@" 2>&1)"; then
    echo "[FAIL] $label" >&2
    printf '%s\n' "$output" >&2
    return 1
  fi
  echo "[PASS] $label"
}

collect_live_state() {
  local db="$1"
  collect_state_or_fail "initialize KANSOKU state database" \
    --db "$db" init
  collect_state_or_fail "collect FRRouting routes" \
    --db "$db" network collect frr-routes \
    --device-id r1 --container "$(container_name r1)" \
    --exclude-interface eth0
  collect_state_or_fail "collect Open vSwitch ports" \
    --db "$db" network collect ovs-ports \
    --device-id sw1 --container "$(container_name sw1)"
  collect_state_or_fail "collect nftables ruleset" \
    --db "$db" network collect nft-ruleset \
    --device-id fw1 --container "$(container_name fw1)"
}

capture_https_on_fw() {
  local output="$1"
  local should_succeed="${2:-yes}"
  local remote="/tmp/kansoku-$(basename "$output")"
  rm -f "$output"
  run_node fw1 rm -f "$remote" /tmp/kansoku-tcpdump.log
  if ! run_node fw1 test -x "$KANSOKU_TCPDUMP_BIN"; then
    echo "[FAIL] KANSOKU tcpdump helper is not executable: $KANSOKU_TCPDUMP_BIN" >&2
    return 1
  fi
  run_node fw1 sh -c "timeout 6 '$KANSOKU_TCPDUMP_BIN' -U -nn -s 96 -i eth1 -w '$remote' 'vlan 10 and tcp dst port 443' >/tmp/kansoku-tcpdump.log 2>&1" &
  local capture_pid=$!
  sleep 1
  local curl_rc=0
  run_node client-a curl -fsS --connect-timeout 2 --max-time 4 http://10.20.20.10:443/ >/dev/null 2>&1 || curl_rc=$?
  local tcpdump_rc=0
  wait "$capture_pid" || tcpdump_rc=$?
  if [[ "$tcpdump_rc" -ne 0 && "$tcpdump_rc" -ne 124 ]]; then
    echo "[FAIL] tcpdump capture failed (rc=$tcpdump_rc)" >&2
    run_node fw1 sh -c 'cat /tmp/kansoku-tcpdump.log 2>/dev/null || true' >&2 || true
    return 1
  fi
  if ! run_node fw1 test -s "$remote"; then
    echo "[FAIL] remote capture file is missing or empty: $remote" >&2
    run_node fw1 sh -c 'cat /tmp/kansoku-tcpdump.log 2>/dev/null || true' >&2 || true
    return 1
  fi
  "$DOCKER_BIN" cp "$(container_name fw1):$remote" "$output" >/dev/null
  [[ -s "$output" ]] || {
    echo "[FAIL] capture file is empty: $output" >&2
    return 1
  }
  if [[ "$should_succeed" == "yes" && "$curl_rc" -ne 0 ]]; then
    echo "[FAIL] HTTP test was expected to succeed (curl rc=$curl_rc)" >&2
    dump_server_diagnostics
    return 1
  fi
  if [[ "$should_succeed" == "no" && "$curl_rc" -eq 0 ]]; then
    echo "[FAIL] HTTP test was expected to fail" >&2
    return 1
  fi
}

summarize_capture() {
  local db="$1"
  local pcap="$2"
  local target="$3"
  ks --db "$db" capture summarize \
    --pcap "$pcap" --target "$target" --source containerlab
}

capture_id_from_json() {
  "$KANSOKU_PYTHON" -c 'import json,sys; print(json.load(sys.stdin)["capture"]["capture_id"])'
}

correlate_capture() {
  local db="$1"
  local capture_id="$2"
  ks --db "$db" network correlate \
    --capture-id "$capture_id" \
    --ingress-device fw1 \
    --route-device r1 \
    --policy-device fw1 \
    --vlan-device sw1
}

assert_verdict() {
  local payload="$1"
  local expected="$2"
  "$KANSOKU_PYTHON" - "$expected" "$payload" <<'PY'
import json, sys
expected = sys.argv[1]
payload = json.loads(sys.argv[2])
verdicts = payload.get("summary", {}).get("verdicts", {})
if verdicts.get(expected, 0) < 1:
    raise SystemExit(f"expected verdict {expected}, got {verdicts}")
print(json.dumps({"expected": expected, "verdicts": verdicts}, sort_keys=True))
PY
}

assert_vlan_status() {
  local db="$1"
  local capture_id="$2"
  local expected="$3"
  "$KANSOKU_PYTHON" - "$db" "$capture_id" "$expected" <<'PY'
import json
import sqlite3
import sys

with sqlite3.connect(sys.argv[1]) as conn:
    payloads = [row[0] for row in conn.execute(
        "SELECT payload FROM flow_assessments WHERE capture_id=?", (sys.argv[2],)
    )]
statuses = [json.loads(payload).get("vlan_status") for payload in payloads]
if sys.argv[3] not in statuses:
    raise SystemExit(f"expected VLAN status {sys.argv[3]}, got {statuses}")
print(sys.argv[3])
PY
}
