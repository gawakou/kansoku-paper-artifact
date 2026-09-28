#!/usr/bin/env bash
set -euo pipefail

sysctl -w net.ipv4.ip_forward=1 >/dev/null
ip link set eth1 up
ip link set eth2 up
ip link delete eth1.10 2>/dev/null || true
ip link add link eth1 name eth1.10 type vlan id 10
ip link set eth1.10 up
ip addr flush dev eth1.10
ip addr add 10.10.10.1/24 dev eth1.10
ip addr flush dev eth2
ip addr add 172.16.0.1/30 dev eth2
ip route replace 10.20.20.0/24 via 172.16.0.2 dev eth2
nft -f /etc/kansoku/ruleset.nft
