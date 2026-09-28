#!/usr/bin/env bash
set -euo pipefail

IFACE="${1:?interface required}"
ADDRESS="${2:?address required}"
GATEWAY="${3:?gateway required}"
ROLE="${4:-host}"

ip link set "$IFACE" up
ip addr flush dev "$IFACE"
ip addr add "$ADDRESS" dev "$IFACE"
ip route replace default via "$GATEWAY" dev "$IFACE"

# Application services are started by lab-up.sh with `docker exec -d` after
# all links and routes are ready. This avoids losing background processes when
# the containerlab bootstrap exec session exits.
if [[ "$ROLE" == "server" ]]; then
  mkdir -p /run/kansoku /var/log /srv/kansoku
  printf '%s\n' "$ADDRESS" > /run/kansoku/server-address
fi
