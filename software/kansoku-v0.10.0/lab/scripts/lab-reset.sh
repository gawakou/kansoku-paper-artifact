#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "$0")" && pwd)/lib.sh"
for node in client-a sw1 fw1 r1 r2 sw2 server-a; do
  assert_container_running "$node"
done
reset_network
rm -rf "$ARTIFACT_DIR"
mkdir -p "$DB_DIR" "$PCAP_DIR" "$REPORT_DIR"
echo "[PASS] network faults and lab artifacts reset"
