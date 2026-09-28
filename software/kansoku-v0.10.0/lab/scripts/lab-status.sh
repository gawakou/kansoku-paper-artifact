#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "$0")" && pwd)/lib.sh"
printf '%-12s %-34s %-8s\n' NODE CONTAINER STATUS
for node in client-a sw1 fw1 r1 r2 sw2 server-a; do
  name="$(container_name "$node")"
  state="$("$DOCKER_BIN" inspect -f '{{.State.Status}}' "$name" 2>/dev/null || echo missing)"
  printf '%-12s %-34s %-8s\n' "$node" "$name" "$state"
done

if assert_container_running server-a >/dev/null 2>&1; then
  http_state="down"
  iperf_state="down"
  run_node server-a sh -c "ss -lnt | grep -Eq '[:.]443[[:space:]]'" >/dev/null 2>&1 && http_state="up"
  run_node server-a sh -c "ss -lnt | grep -Eq '[:.]5201[[:space:]]'" >/dev/null 2>&1 && iperf_state="up"
  printf 'APPLICATION SERVICES: http/443=%s iperf3/5201=%s\n' "$http_state" "$iperf_state"
fi
