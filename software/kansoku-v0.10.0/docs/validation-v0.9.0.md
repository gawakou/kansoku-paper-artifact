# KANSOKU v0.9.0 Validation Plan

KANSOKU v0.9.0 extends the validated v0.8.4 containerlab environment with configuration-recommendation checks.

## Baseline environment

- Ubuntu Server 24.04
- Docker Engine
- containerlab
- FRRouting routers: `r1`, `r2`
- Open vSwitch nodes: `sw1`, `sw2`
- nftables firewall: `fw1`
- client/server nodes: `client-a`, `server-a`

## Existing forwarding scenarios

- `normal` → `ALLOW`
- `firewall-deny` → `DENY`
- `route-missing` → `UNROUTABLE`
- `vlan-mismatch` → `UNKNOWN / UNKNOWN_VLAN`
- `packet-loss` → fault injection and recovery

## v0.9 recommendation checks

After the abnormal scenarios, the test suite generates review-only plans and requires a model-level `ALLOW` result:

- firewall denial → narrow nftables allow candidate and rollback template
- missing route → FRRouting static-route candidate and rollback template
- VLAN mismatch → Open vSwitch access/trunk repair candidate and rollback template

The generated commands are not executed by the recommendation engine.

## Commands

```bash
make lab-up
make lab-test
make lab-down
```

A successful v0.9 run ends with:

```text
[PASS] 5/5 virtual-lab scenarios and 3/3 recommendation what-if checks
```
