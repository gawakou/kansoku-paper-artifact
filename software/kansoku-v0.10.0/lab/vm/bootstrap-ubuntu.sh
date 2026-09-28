#!/usr/bin/env bash
set -euo pipefail

if [[ ! -r /etc/os-release ]]; then
  echo "This installer requires Ubuntu Linux." >&2
  exit 1
fi
. /etc/os-release
if [[ "${ID:-}" != "ubuntu" ]]; then
  echo "This installer supports Ubuntu; detected: ${PRETTY_NAME:-unknown}." >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
SUDO=""
[[ "$EUID" -eq 0 ]] || SUDO="sudo"

$SUDO apt-get update
$SUDO apt-get install -y \
  ca-certificates curl git gnupg jq openvswitch-switch \
  python3 python3-pip python3-venv tcpdump

if ! command -v docker >/dev/null 2>&1; then
  $SUDO install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    | $SUDO gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg
  $SUDO chmod a+r /etc/apt/keyrings/docker.gpg
  ARCH="$(dpkg --print-architecture)"
  CODENAME="${UBUNTU_CODENAME:-$VERSION_CODENAME}"
  echo "deb [arch=$ARCH signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $CODENAME stable" \
    | $SUDO tee /etc/apt/sources.list.d/docker.list >/dev/null
  $SUDO apt-get update
  $SUDO apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi

if ! command -v containerlab >/dev/null 2>&1; then
  curl -sL https://containerlab.dev/setup | $SUDO -E bash -s "all"
fi

$SUDO systemctl enable --now docker
$SUDO modprobe openvswitch || true
$SUDO modprobe 8021q || true
printf 'openvswitch\n8021q\n' | $SUDO tee /etc/modules-load.d/kansoku-lab.conf >/dev/null

TARGET_USER="${SUDO_USER:-$USER}"
if ! id -nG "$TARGET_USER" | tr ' ' '\n' | grep -qx docker; then
  $SUDO usermod -aG docker "$TARGET_USER"
  NEED_RELOGIN=1
else
  NEED_RELOGIN=0
fi

python3 -m venv "$ROOT_DIR/.lab-venv"
"$ROOT_DIR/.lab-venv/bin/python" -m pip install --upgrade pip
"$ROOT_DIR/.lab-venv/bin/python" -m pip install -e "$ROOT_DIR[dev]"
KANSOKU_PYTHON="$ROOT_DIR/.lab-venv/bin/python" "$ROOT_DIR/lab/scripts/lab-selftest.sh"

cat <<REPORT
KANSOKU v0.10.0 virtual-lab prerequisites are installed.
Repository: $ROOT_DIR
Python:     $ROOT_DIR/.lab-venv/bin/python
Docker:     $(docker --version 2>/dev/null || sudo docker --version)
containerlab: $(containerlab version 2>/dev/null | head -1 || true)
REPORT

if [[ "$NEED_RELOGIN" -eq 1 ]]; then
  cat <<NOTICE

The user '$TARGET_USER' was added to the docker group.
Log out of the Ubuntu VM and log in again, or run:
  newgrp docker
Then verify:
  docker info
NOTICE
fi
