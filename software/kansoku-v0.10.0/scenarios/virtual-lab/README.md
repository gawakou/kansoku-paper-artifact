# KANSOKU v0.8 virtual-lab fixtures

These read-only JSON fixtures model an open-source reference network:

- `frr-r1.json`: FRRouting interfaces and routes;
- `ovs-sw1.json`: Open vSwitch access/trunk VLAN state and one configured peer;
- `nft-fw1.json`: nftables forward-chain rules with an HTTPS allow rule and default deny.

They are intentionally small and deterministic so the network-state import and flow-correlation path can be reproduced without physical equipment or privileged containers.
