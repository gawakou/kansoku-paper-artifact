# KANSOKU v0.9.0

## Added

- `ConfigurationRecommendation` vendor-neutral review model
- route, VLAN, and firewall recommendation generation
- FRRouting, Open vSwitch, and nftables command templates
- rollback templates, impact, risk, preconditions, and postconditions
- model-level what-if correlation before a recommendation is stored
- SQLite recommendation audit table
- `recommend generate/list/show/validate/export` CLI
- read-only dashboard recommendation view
- three containerlab recommendation checks after fault scenarios

## Safety boundary

v0.9.0 does not execute generated network configuration. Recommendations remain `DRAFT` review packets.
