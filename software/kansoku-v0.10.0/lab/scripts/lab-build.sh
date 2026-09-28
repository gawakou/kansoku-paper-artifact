#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "$0")" && pwd)/lib.sh"
"$DOCKER_BIN" build \
  --tag kansoku/lab-node:0.10.0 \
  "$LAB_DIR/images/kansoku-lab-node"
echo "[PASS] built kansoku/lab-node:0.10.0"
