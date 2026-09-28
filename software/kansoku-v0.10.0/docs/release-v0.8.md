# KANSOKU v0.8.0

KANSOKU v0.8.0 introduces the first vendor-neutral Network State Model.

## Highlights

- FRRouting interface and route import;
- Open vSwitch VLAN and link-state import;
- nftables policy import;
- device and configuration snapshot inventory;
- packet-flow correlation with routes, firewall rules, and VLANs;
- explainable, persisted flow assessments;
- rootless virtual-lab fixtures and smoke test;
- dashboard network inventory and assessment views.

## Safety boundary

All live collectors are read-only. v0.8 does not generate or apply device configuration. A flow verdict is diagnostic evidence, not authorization to modify a production router, switch, or firewall.
