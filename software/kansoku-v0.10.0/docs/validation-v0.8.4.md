# KANSOKU v0.8.4 validation record

## Validation status

KANSOKU v0.8.4 completed the reproducible virtual-lab integration suite on an Ubuntu host. The test exercised live traffic, packet capture, FRRouting route collection, Open vSwitch VLAN collection, nftables policy collection, flow correlation, fault injection, and recovery.

## Environment

| Item | Validated value |
|---|---|
| Validation date | 2026-07-17 |
| Guest operating system | Ubuntu Server 24.04 LTS |
| Docker Engine | 27.5.1 |
| containerlab | 0.77.0 |
| FRRouting image | `frrouting/frr:v8.4.0` |
| KANSOKU lab-node image | `kansoku/lab-node:0.8.4` |
| Lab nodes | 7 containers |
| Management subnet | `172.31.81.0/24` |

## Automated validation

The Ubuntu validation run produced:

```text
81 passed
verified v0.8.4 topology and lab file set
verified v0.8.4 shell syntax
```

The integration run produced:

```text
[PASS] normal → ALLOW
[PASS] firewall-deny → DENY
[PASS] route-missing → UNROUTABLE
[PASS] vlan-mismatch → UNKNOWN / UNKNOWN_VLAN
[PASS] packet-loss injection and recovery
[PASS] 5/5 virtual-lab scenarios
```

## Scenario evidence

| Scenario | Live traffic result | Live state collected | Final result |
|---|---|---|---|
| Normal | ping, HTTP/443, and iperf3 succeed | FRR + OVS + nftables + pcap | `ALLOW` |
| Firewall deny | TCP/443 connection fails after rule insertion | nftables drop rule and matching flow evidence | `DENY` |
| Route missing | Service path fails after route removal | No eligible data-plane route after management-route exclusion | `UNROUTABLE` |
| VLAN mismatch | Service path fails after VLAN drift | Captured VLAN evidence conflicts with current OVS state | `UNKNOWN`, `UNKNOWN_VLAN` |
| Packet loss | Connectivity fails under `netem loss 100%` and recovers after reset | fault injection and restoration verified | pass |

## Defects found through live validation

The virtual-lab process exposed integration issues that fixture-only tests did not reveal:

1. application processes needed explicit post-deployment readiness checks;
2. native nftables JSON uses structured prefix/range expressions;
3. nftables fault-injection comments required correct command-line quoting;
4. container management routes had to be excluded from data-plane correlation;
5. VLAN assessment status is stored inside the persisted assessment JSON payload; and
6. release scripts needed explicit `.lab-venv` interpreter propagation.

These corrections are included in the validated v0.8.4 source.

## Reproduction

```bash
./lab/vm/bootstrap-ubuntu.sh
make lab-up
make lab-status
make lab-test
cat artifacts/lab/reports/summary.json
make lab-down
```

The report, pcap files, and SQLite databases under `artifacts/lab/` are intentionally excluded from Git because they are runtime evidence rather than source artifacts.

## Scope and limitations

The validation demonstrates the KANSOKU reference pipeline against FRRouting, Open vSwitch, and nftables. It does not claim complete equivalence with hardware ASIC forwarding, vendor-specific firewall semantics, dynamic routing convergence, complex NAT, policy-based routing, or production high-availability behavior. Those capabilities require additional adapters and separate physical-device validation.
