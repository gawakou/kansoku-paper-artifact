#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "$0")" && pwd)/lib.sh"
"$LAB_DIR/scripts/preflight.sh"
"$LAB_DIR/scripts/lab-build.sh"

if [[ "$EUID" -eq 0 ]]; then
  containerlab deploy --topo "$TOPOLOGY" --reconfigure
else
  sudo -E containerlab deploy --topo "$TOPOLOGY" --reconfigure
fi

for node in client-a sw1 fw1 r1 r2 sw2 server-a; do
  wait_for_command 30 2 assert_container_running "$node" || {
    echo "[FAIL] node did not become ready: $node" >&2
    exit 1
  }
done

wait_for_command 30 2 run_node r1 vtysh -c 'show ip route json' || {
  echo "[FAIL] FRRouting r1 did not become ready" >&2
  exit 1
}
wait_for_command 30 2 run_node sw1 ovs-vsctl show || {
  echo "[FAIL] Open vSwitch sw1 did not become ready" >&2
  exit 1
}
wait_for_command 30 2 run_node fw1 nft -j list ruleset || {
  echo "[FAIL] nftables fw1 did not become ready" >&2
  exit 1
}
start_server_services
wait_for_server_services || exit 1
wait_for_command 30 2 run_node client-a ping -c 1 -W 1 10.20.20.10 || {
  echo "[FAIL] end-to-end connectivity did not become ready" >&2
  exit 1
}
wait_for_command 30 1 run_node client-a curl -fsS --connect-timeout 1 --max-time 2 http://10.20.20.10:443/ || {
  echo "[FAIL] end-to-end HTTP service did not become ready" >&2
  dump_server_diagnostics
  exit 1
}
wait_for_command 30 1 run_node client-a sh -c "iperf3 -c 10.20.20.10 -t 1 >/dev/null" || {
  echo "[FAIL] end-to-end iperf3 service did not become ready" >&2
  dump_server_diagnostics
  exit 1
}

echo "[PASS] KANSOKU containerlab and application services are ready"
"$LAB_DIR/scripts/lab-status.sh"
