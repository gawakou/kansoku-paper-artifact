#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT_DIR"

source lab/scripts/lib.sh

PLAN="scenarios/paper/parameterized_instances.json"
PREREG_TAG="paper-phase2-parameterized-prereg-v1"

INSTANCE_ID="${1:?usage: run_phase2_instance.sh INSTANCE_ID [REPETITION]}"
REPETITION="${2:-1}"

if ! [[ "$REPETITION" =~ ^[1-5]$ ]]; then
  echo "[FAIL] repetition must be 1..5" >&2
  exit 2
fi

# The execution plan itself must still match the frozen preregistration.
if ! git diff --quiet "$PREREG_TAG" -- "$PLAN"; then
  echo "[FAIL] parameterized_instances.json differs from preregistration" >&2
  exit 2
fi

PREREG_SHA="$(git rev-list -n 1 "$PREREG_TAG")"
EXECUTION_SHA="$(git rev-parse HEAD)"

OUT_ROOT="${KANSOKU_PHASE2_OUT:-$ROOT_DIR/artifacts/paper/phase2-parameterized}"
OUT="$OUT_ROOT/$INSTANCE_ID/rep-$(printf '%02d' "$REPETITION")"

if [[ -e "$OUT" && "${KANSOKU_PHASE2_OVERWRITE:-0}" != "1" ]]; then
  echo "[FAIL] output already exists: $OUT" >&2
  echo "       Set KANSOKU_PHASE2_OVERWRITE=1 only for development reruns." >&2
  exit 2
fi

rm -rf "$OUT"
mkdir -p "$OUT"

DB="$OUT/state.db"
PCAP="$OUT/capture.pcap"
TARGET_SPEC="$OUT/target.json"

# Read only the execution plan. Ground truth is deliberately not read here.
eval "$(
"$KANSOKU_PYTHON" - "$PLAN" "$INSTANCE_ID" <<'PY'
import json
import shlex
import sys

path, iid = sys.argv[1:]
doc = json.load(open(path, encoding="utf-8"))

try:
    row = doc["instances"][iid]
except KeyError:
    raise SystemExit(f"unknown instance_id: {iid}")

target = row["target"]
p = row["parameters"]

values = {
    "PROTO": row["prototype_id"],
    "FAMILY": row["family"],
    "PREREG_QUERY_ID": target["query_id"],
    "SRC_IP": target["src_ip"],
    "DST_IP": target["dst_ip"],
    "DST_PORT": target["dst_port"],
    "P_TARGET_ALIAS": p.get("target_alias", ""),
    "P_DENY_DST": p.get("deny_dst_ip", ""),
    "P_SOURCE_SUBNET": p.get("source_subnet", ""),
    "P_PORT_RANGE": p.get("destination_port_range", ""),
    "P_SHADOW_PREFIX": p.get("shadowing_destination_prefix", ""),
    "P_REMOVED_PREFIX": p.get("removed_prefix", ""),
    "P_NEXT_HOP": p.get("unreachable_next_hop", ""),
    "P_ROUTE_PREFIX": p.get("route_prefix", ""),
    "P_WRONG_IF": p.get("wrong_interface", ""),
    "P_BLACKHOLE_PREFIX": p.get("blackhole_prefix", ""),
    "P_DRIFT_VLAN": p.get("drift_vlan", ""),
    "P_ACCESS_VLAN": p.get("access_drift_vlan", ""),
    "P_TRUNK_VLAN": p.get("trunk_drift_vlan", ""),
}

for key, value in values.items():
    print(f"{key}={shlex.quote(str(value))}")
PY
)"

RUNTIME_QUERY_ID="$(
"$KANSOKU_PYTHON" - "$PREREG_SHA" "$INSTANCE_ID" <<'PY'
import hashlib
import sys

prereg_sha, iid = sys.argv[1:]
raw = f"{prereg_sha}:{iid}".encode("utf-8")
print("q-" + hashlib.sha256(raw).hexdigest()[:20])
PY
)"

"$KANSOKU_PYTHON" - \
  "$PLAN" \
  "$INSTANCE_ID" \
  "$RUNTIME_QUERY_ID" \
  "$TARGET_SPEC" <<'PY'
import json
import sys

plan_path, iid, runtime_query_id, output = sys.argv[1:]
doc = json.load(open(plan_path, encoding="utf-8"))

target = dict(doc["instances"][iid]["target"])
target["query_id"] = runtime_query_id

with open(output, "w", encoding="utf-8") as f:
    json.dump(
        target,
        f,
        indent=2,
        sort_keys=True,
    )
    f.write("\n")
PY

phase2_cleanup() {
  set +e

  # Stop any evaluation-only wildcard HTTP server.
  run_node server-a sh -c \
    "pkill -f '^python3 .*http.server 443 ' 2>/dev/null || true" \
    >/dev/null 2>&1 || true

  # Remove all target aliases used by Phase 2.
  for host in 11 12 13 14; do
    run_node server-a ip addr del "10.20.20.${host}/24" dev eth1 \
      >/dev/null 2>&1 || true
  done

  # Remove all Phase-2 wrong-interface / blackhole variants.
  for prefix in \
    10.20.20.0/25 \
    10.20.20.0/26 \
    10.20.20.0/27 \
    10.20.20.0/28 \
    10.20.20.10/32
  do
    run_node r1 vtysh \
      -c 'configure terminal' \
      -c "no ip route ${prefix} eth1" \
      -c "no ip route ${prefix} blackhole" \
      >/dev/null 2>&1 || true
  done

  # Remove all Phase-2 unresolved-next-hop variants.
  for nh in \
    172.16.1.250 \
    172.16.1.251 \
    172.16.1.252 \
    172.16.1.253 \
    172.16.1.254
  do
    run_node r1 vtysh \
      -c 'configure terminal' \
      -c "no ip route 10.20.20.0/24 ${nh}" \
      >/dev/null 2>&1 || true
  done

  # Restore the canonical Phase-1 network state.
  reset_network >/dev/null 2>&1 || true

  set -e
}

verify_canonical_baseline() {
  local addresses
  local running

  addresses="$(run_node server-a ip -brief addr show dev eth1)"

  grep -q '10\.20\.20\.10/24' <<<"$addresses" || {
    echo "[FAIL] canonical server address missing after cleanup" >&2
    return 1
  }

  if grep -Eq '10\.20\.20\.(11|12|13|14)/24' <<<"$addresses"; then
    echo "[FAIL] Phase-2 server alias survived cleanup" >&2
    return 1
  fi

  run_node server-a sh -c \
    "ss -lnt | grep -q '10.20.20.10:443'" || {
      echo "[FAIL] canonical HTTP listener not restored" >&2
      return 1
    }

  run_node client-a curl -fsS \
    --connect-timeout 2 --max-time 4 \
    http://10.20.20.10:443/ >/dev/null || {
      echo "[FAIL] canonical HTTP connectivity not restored" >&2
      return 1
    }

  [[ "$(run_node sw1 ovs-vsctl get Port eth1 tag)" == "10" ]] || {
    echo "[FAIL] sw1 eth1 VLAN not restored" >&2
    return 1
  }

  [[ "$(run_node sw1 ovs-vsctl get Port eth2 trunks)" == "[10]" ]] || {
    echo "[FAIL] sw1 eth2 trunk VLAN not restored" >&2
    return 1
  }

  running="$(run_node r1 vtysh -c 'show running-config')"

  grep -q 'ip route 10.20.20.0/24 172.16.1.2' <<<"$running" || {
    echo "[FAIL] canonical r1 route not restored" >&2
    return 1
  }

  if grep -Eq \
    'ip route 10\.20\.20\.0/24 172\.16\.1\.25[0-4]' \
    <<<"$running"
  then
    echo "[FAIL] unresolved-next-hop route survived cleanup" >&2
    return 1
  fi

  if grep -Eq \
    'ip route 10\.20\.20\.(0/(25|26|27|28)|10/32) (eth1|blackhole)' \
    <<<"$running"
  then
    echo "[FAIL] Phase-2 specific route survived cleanup" >&2
    return 1
  fi
}

setup_target_overlay() {
  # .10 is the canonical baseline and needs no overlay.
  if [[ "$DST_IP" == "10.20.20.10" ]]; then
    return 0
  fi

  run_node server-a ip addr add "${DST_IP}/24" dev eth1

  # Replace the .10-only HTTP process with one evaluation-only wildcard
  # listener. Cleanup restores the canonical .10-only process.
  run_node server-a sh -c \
    "pkill -f '^python3 .*http.server 443 ' 2>/dev/null || true" \
    >/dev/null 2>&1 || true

  run_node_detached server-a sh -c \
    "exec python3 -u -m http.server 443 \
     --bind 0.0.0.0 \
     --directory /srv/kansoku \
     >/tmp/kansoku-phase2-http.log 2>&1"

  wait_for_command 10 1 \
    run_node server-a sh -c \
    "ss -lnt | grep -q '0.0.0.0:443'" || {
      echo "[FAIL] Phase-2 wildcard HTTP listener did not start" >&2
      return 1
    }

  # Evaluation-only healthy baseline policy for the alias.
  run_node fw1 nft insert rule inet filter forward \
    ip saddr 10.10.10.0/24 \
    ip daddr "$DST_IP" \
    tcp dport 443 \
    counter accept
}

assert_http_success() {
  local ip="$1"
  run_node client-a curl -fsS \
    --connect-timeout 2 --max-time 4 \
    "http://${ip}:443/" >/dev/null || {
      echo "[FAIL] expected healthy HTTP connectivity to ${ip}" >&2
      return 1
    }
}

assert_http_failure() {
  local ip="$1"
  if run_node client-a curl -fsS \
      --connect-timeout 2 --max-time 4 \
      "http://${ip}:443/" >/dev/null 2>&1
  then
    echo "[FAIL] expected HTTP failure to ${ip}" >&2
    return 1
  fi
}

capture_target_https() {
  local output="$1"
  local expected="$2"
  local dst="$3"

  local remote="/tmp/kansoku-phase2-${INSTANCE_ID}-${REPETITION}.pcap"
  local filter="vlan 10 and tcp dst port 443 and dst host ${dst}"

  rm -f "$output"

  run_node fw1 rm -f "$remote" /tmp/kansoku-phase2-tcpdump.log

  run_node fw1 sh -c \
    "timeout 6 '$KANSOKU_TCPDUMP_BIN' \
     -U -nn -s 96 -i eth1 \
     -w '$remote' '$filter' \
     >/tmp/kansoku-phase2-tcpdump.log 2>&1" &

  local capture_pid=$!

  sleep 1

  local curl_rc=0
  run_node client-a curl -fsS \
    --connect-timeout 2 --max-time 4 \
    "http://${dst}:443/" >/dev/null 2>&1 || curl_rc=$?

  local tcpdump_rc=0
  wait "$capture_pid" || tcpdump_rc=$?

  if [[ "$tcpdump_rc" -ne 0 && "$tcpdump_rc" -ne 124 ]]; then
    echo "[FAIL] tcpdump failed rc=${tcpdump_rc}" >&2
    run_node fw1 sh -c \
      'cat /tmp/kansoku-phase2-tcpdump.log 2>/dev/null || true' >&2
    return 1
  fi

  run_node fw1 test -s "$remote" || {
    echo "[FAIL] remote Phase-2 capture missing or empty" >&2
    return 1
  }

  "$DOCKER_BIN" cp \
    "$(container_name fw1):$remote" \
    "$output" >/dev/null

  [[ -s "$output" ]] || {
    echo "[FAIL] local Phase-2 capture is empty" >&2
    return 1
  }

  if [[ "$expected" == "success" && "$curl_rc" -ne 0 ]]; then
    echo "[FAIL] HTTP was expected to succeed during capture" >&2
    return 1
  fi

  if [[ "$expected" == "failure" && "$curl_rc" -eq 0 ]]; then
    echo "[FAIL] HTTP was expected to fail during capture" >&2
    return 1
  fi
}

inject_fault() {
  case "$PROTO" in
    normal)
      ;;

    firewall-deny)
      run_node fw1 nft insert rule inet filter forward \
        ip saddr 10.10.10.0/24 \
        ip daddr "$P_DENY_DST" \
        tcp dport 443 \
        counter drop
      ;;

    firewall-subnet-deny)
      run_node fw1 nft insert rule inet filter forward \
        ip saddr "$P_SOURCE_SUBNET" \
        tcp dport 443 \
        counter drop
      ;;

    firewall-port-range-deny)
      run_node fw1 nft insert rule inet filter forward \
        tcp dport "$P_PORT_RANGE" \
        counter drop
      ;;

    firewall-rule-order)
      run_node fw1 nft insert rule inet filter forward \
        ip saddr 10.10.10.0/24 \
        ip daddr "$P_SHADOW_PREFIX" \
        counter drop
      ;;

    route-missing)
      run_node r1 vtysh \
        -c 'configure terminal' \
        -c "no ip route ${P_REMOVED_PREFIX} 172.16.1.2" \
        >/dev/null
      ;;

    route-unreachable-next-hop)
      run_node r1 vtysh \
        -c 'configure terminal' \
        -c 'no ip route 10.20.20.0/24 172.16.1.2' \
        -c "ip route 10.20.20.0/24 ${P_NEXT_HOP}" \
        >/dev/null
      sleep 1
      ;;

    route-wrong-interface)
      run_node r1 vtysh \
        -c 'configure terminal' \
        -c "ip route ${P_ROUTE_PREFIX} ${P_WRONG_IF}" \
        >/dev/null
      sleep 1
      ;;

    route-blackhole-host)
      run_node r1 vtysh \
        -c 'configure terminal' \
        -c "ip route ${P_BLACKHOLE_PREFIX} blackhole" \
        >/dev/null
      sleep 1
      ;;

    vlan-mismatch)
      run_node sw1 ovs-vsctl set Port eth1 tag="$P_DRIFT_VLAN"
      run_node sw1 ovs-vsctl set Port eth2 trunks="$P_DRIFT_VLAN"
      sleep 1
      ;;

    vlan-access-only-drift)
      run_node sw1 ovs-vsctl set Port eth1 tag="$P_ACCESS_VLAN"
      sleep 1
      ;;

    vlan-trunk-only-drift)
      run_node sw1 ovs-vsctl set Port eth2 trunks="$P_TRUNK_VLAN"
      sleep 1
      ;;

    *)
      echo "[FAIL] unsupported prototype: $PROTO" >&2
      return 1
      ;;
  esac
}

echo "===== Phase 2 instance ====="
echo "instance   : $INSTANCE_ID"
echo "prototype  : $PROTO"
echo "family     : $FAMILY"
echo "target     : $SRC_IP -> $DST_IP TCP/$DST_PORT"
echo "repetition : $REPETITION"
echo "prereg SHA : $PREREG_SHA"
echo "exec SHA   : $EXECUTION_SHA"
echo "plan qid   : $PREREG_QUERY_ID"
echo "runtime qid: $RUNTIME_QUERY_ID"
echo "output     : $OUT"

# Always begin from an explicitly clean Phase-2 state.
phase2_cleanup
trap 'phase2_cleanup >/dev/null 2>&1 || true' EXIT

setup_target_overlay

echo "[1/6] healthy precondition"
assert_http_success "$DST_IP"

if [[ "$PROTO" == vlan-* ]]; then
  # VLAN experiments deliberately pair a pre-drift known-good flow with
  # post-drift configuration state.
  echo "[2/6] capture known-good pre-drift flow"
  capture_target_https "$PCAP" success "$DST_IP"

  echo "[3/6] inject fault"
  inject_fault

  echo "[4/6] verify fault effect"
  assert_http_failure "$DST_IP"
else
  echo "[2/6] inject fault"
  inject_fault

  echo "[3/6] capture fault-active flow"
  if [[ "$PROTO" == "normal" ]]; then
    capture_target_https "$PCAP" success "$DST_IP"
  else
    capture_target_https "$PCAP" failure "$DST_IP"
  fi

  echo "[4/6] fault-effect gate passed"
fi

echo "[5/6] collect normalized network state"
collect_live_state "$DB"

CAPTURE_JSON="$(
  summarize_capture \
    "$DB" \
    "$PCAP" \
    "$RUNTIME_QUERY_ID"
)"

CAPTURE_ID="$(
  capture_id_from_json <<<"$CAPTURE_JSON"
)"

printf '%s\n' "$CAPTURE_JSON" > "$OUT/capture-summary.json"

echo "[6/6] run three diagnosis methods"
"$KANSOKU_PYTHON" scripts/experiments/run_paper_ablation.py \
  --db "$DB" \
  --target-spec "$TARGET_SPEC" \
  --capture-id "$CAPTURE_ID" \
  --output-dir "$OUT" \
  > "$OUT/ablation.stdout.json"

"$KANSOKU_PYTHON" - \
  "$OUT/trial.json" \
  "$INSTANCE_ID" \
  "$PROTO" \
  "$FAMILY" \
  "$REPETITION" \
  "$CAPTURE_ID" \
  "$PREREG_SHA" \
  "$EXECUTION_SHA" \
  "$PREREG_QUERY_ID" \
  "$RUNTIME_QUERY_ID" <<'PY'
import datetime
import json
import sys

(
    output,
    iid,
    prototype,
    family,
    repetition,
    capture_id,
    prereg_sha,
    execution_sha,
    prereg_query_id,
    runtime_query_id,
) = sys.argv[1:]

payload = {
    "instance_id": iid,
    "prototype_id": prototype,
    "family": family,
    "repetition": int(repetition),
    "capture_id": capture_id,
    "preregistration_commit": prereg_sha,
    "execution_commit": execution_sha,
    "preregistered_query_id": prereg_query_id,
    "runtime_query_id": runtime_query_id,
    "completed_at": datetime.datetime.now(
        datetime.timezone.utc
    ).isoformat(),
    "ground_truth_consumed_by_runner": False,
}

with open(output, "w", encoding="utf-8") as f:
    json.dump(payload, f, indent=2, sort_keys=True)
    f.write("\n")
PY

# Explicitly clean before declaring the trial complete.
phase2_cleanup
verify_canonical_baseline
trap - EXIT

echo "[PASS] $INSTANCE_ID repetition $REPETITION"
echo "[PASS] canonical baseline restored"
echo "diagnostics: $OUT/diagnostics.json"
