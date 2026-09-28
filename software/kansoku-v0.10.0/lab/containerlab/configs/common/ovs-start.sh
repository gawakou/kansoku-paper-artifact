#!/usr/bin/env bash
set -euo pipefail

BRIDGE="${1:-br0}"
shift || true

mkdir -p /var/run/openvswitch /var/log/openvswitch /etc/openvswitch
if [[ ! -s /etc/openvswitch/conf.db ]]; then
  ovsdb-tool create /etc/openvswitch/conf.db /usr/share/openvswitch/vswitch.ovsschema
fi
if [[ ! -S /var/run/openvswitch/db.sock ]]; then
  ovsdb-server /etc/openvswitch/conf.db \
    --remote=punix:/var/run/openvswitch/db.sock \
    --remote=db:Open_vSwitch,Open_vSwitch,manager_options \
    --pidfile=/var/run/openvswitch/ovsdb-server.pid \
    --detach --log-file=/var/log/openvswitch/ovsdb-server.log
fi
ovs-vsctl --no-wait init
if ! pgrep -x ovs-vswitchd >/dev/null 2>&1; then
  ovs-vswitchd unix:/var/run/openvswitch/db.sock \
    --pidfile=/var/run/openvswitch/ovs-vswitchd.pid \
    --detach --log-file=/var/log/openvswitch/ovs-vswitchd.log
fi
ovs-vsctl --may-exist add-br "$BRIDGE"
ip link set "$BRIDGE" up

for IFACE in "$@"; do
  ip link set "$IFACE" up
  ovs-vsctl --may-exist add-port "$BRIDGE" "$IFACE"
done
