#!/usr/bin/env bash
set -euo pipefail
bash /opt/kansoku/ovs-start.sh br0 eth1 eth2
ovs-vsctl set Port eth1 tag=20
ovs-vsctl set Port eth2 tag=20
