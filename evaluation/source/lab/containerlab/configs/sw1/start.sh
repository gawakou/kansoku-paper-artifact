#!/usr/bin/env bash
set -euo pipefail
bash /opt/kansoku/ovs-start.sh br0 eth1 eth2
ovs-vsctl set Port eth1 tag=10
ovs-vsctl clear Port eth1 trunks
ovs-vsctl clear Port eth2 tag
ovs-vsctl set Port eth2 trunks=10
