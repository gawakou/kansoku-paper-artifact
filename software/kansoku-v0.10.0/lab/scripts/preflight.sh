#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "$0")" && pwd)/lib.sh"

[[ "$(uname -s)" == "Linux" ]] || {
  echo "[FAIL] containerlab deployment must run inside a Linux host or Linux VM" >&2
  exit 1
}
require_command "$DOCKER_BIN"
require_command containerlab
require_command "$KANSOKU_PYTHON"
"$DOCKER_BIN" info >/dev/null

case "$(uname -m)" in
  x86_64|amd64|aarch64|arm64) ;;
  *) echo "[WARN] untested architecture: $(uname -m)" ;;
esac

for module in openvswitch 8021q; do
  if ! grep -qw "$module" /proc/modules 2>/dev/null; then
    sudo modprobe "$module" 2>/dev/null || true
  fi
done

echo "[PASS] Linux host"
echo "[PASS] Docker access"
echo "[PASS] containerlab"
echo "[PASS] KANSOKU Python: $KANSOKU_PYTHON"
