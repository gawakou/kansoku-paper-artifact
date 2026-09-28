#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "$0")" && pwd)/lib.sh"
if [[ "$EUID" -eq 0 ]]; then
  containerlab destroy --topo "$TOPOLOGY" --cleanup || true
else
  sudo -E containerlab destroy --topo "$TOPOLOGY" --cleanup || true
fi
echo "[PASS] KANSOKU containerlab destroyed"
