# KANSOKU v0.10.0 reproducible virtual lab

This lab validates the real KANSOKU packet, flow, route, VLAN, and firewall-state pipeline against running open-source network components rather than fixture JSON alone.

## Topology

[![KANSOKU virtual-lab topology](../docs/images/virtual-lab-topology.svg)](../docs/virtual-lab.md)

The data plane is a linear client-to-server path. A separate containerlab management network (`172.31.81.0/24`, `eth0`) reaches every node but is explicitly excluded from KANSOKU data-plane route correlation.

| Segment | Addressing / VLAN |
|---|---|
| client-a to sw1 | untagged access VLAN 10 |
| sw1 to fw1 | trunk VLAN 10 |
| fw1 to r1 | `172.16.0.0/30` |
| r1 to r2 | `172.16.1.0/30` |
| r2 to sw2/server-a | `10.20.20.0/24`, access VLAN 20 |

A complete architectural description, Mermaid source, and observation-point explanation are available in [`docs/virtual-lab.md`](../docs/virtual-lab.md).

The lab contains seven containers:

- `client-a`: ping, curl, and iperf3 client
- `sw1`: Open vSwitch access/trunk bridge for VLAN 10
- `fw1`: nftables stateful forwarding firewall and VLAN gateway
- `r1`, `r2`: FRRouting routers with static routes
- `sw2`: Open vSwitch access bridge for VLAN 20
- `server-a`: HTTP-on-443 and iperf3 server

KANSOKU runs on the Ubuntu VM and uses the new read-only `--container` collector mode to execute `vtysh`, `ovs-vsctl`, and `nft` inside the lab nodes. Packet capture is performed inside `fw1`, copied to the VM, summarized by KANSOKU, and correlated with live configuration state.

## Safety boundary

The integration suite changes only disposable lab containers. It does not modify the Ubuntu host's routing table, firewall policy, or production interfaces. The v0.10 executor requires a stored named approval, accepts only `environment=virtual-lab`, uses shell-free `docker exec`/`podman exec`, and rolls changes back by default. `lab-up.sh` requires `sudo` only for containerlab network-namespace and veth creation.

## Quick start

On Ubuntu Server 24.04:

```bash
./lab/vm/bootstrap-ubuntu.sh
```

After logging out and back in when Docker group membership changes:

```bash
make lab-up
make lab-test
make lab-down
```

The result is written to:

```text
artifacts/lab/reports/summary.json
```

## Individual commands

```bash
./lab/scripts/lab-selftest.sh   # no Docker required
./lab/scripts/preflight.sh
./lab/scripts/lab-build.sh
./lab/scripts/lab-up.sh
./lab/scripts/lab-status.sh
./lab/scripts/lab-test.sh
./lab/scripts/lab-reset.sh
./lab/scripts/lab-down.sh
```

Run an individual scenario:

```bash
./lab/scripts/scenarios/normal.sh
./lab/scripts/scenarios/firewall-deny.sh
./lab/scripts/scenarios/route-missing.sh
./lab/scripts/scenarios/vlan-mismatch.sh
./lab/scripts/scenarios/packet-loss.sh
```

## Scenario expectations

| Scenario | Injected condition | Connectivity | KANSOKU result |
|---|---|---|---|
| normal | Baseline configuration | ping/HTTP/iperf3 succeed | `ALLOW` |
| firewall-deny | Insert TCP/443 drop rule | HTTP fails | `DENY` |
| route-missing | Remove r1 route to server subnet | HTTP fails | `UNROUTABLE` |
| vlan-mismatch | Change sw1 access/trunk VLAN from 10 to 30 | HTTP fails | `UNKNOWN`, `UNKNOWN_VLAN` |
| packet-loss | `tc netem loss 100%` on r1 | ping fails, then recovers | Injection/recovery pass |

The VLAN scenario intentionally correlates a last-known-good VLAN-tagged flow against the current drifted switch state. This demonstrates configuration-state inconsistency even though the failed frame no longer reaches the firewall observation point.

## Live collector examples

```bash
python -m kansoku --db artifacts/lab/manual.db network collect frr-routes \
  --device-id r1 \
  --container clab-kansoku-v100-r1

python -m kansoku --db artifacts/lab/manual.db network collect ovs-ports \
  --device-id sw1 \
  --container clab-kansoku-v100-sw1

python -m kansoku --db artifacts/lab/manual.db network collect nft-ruleset \
  --device-id fw1 \
  --container clab-kansoku-v100-fw1
```

The scripts deliberately use `python -m kansoku` through `.lab-venv` so that an older globally installed `kansoku` launcher cannot shadow the active source tree.

## Reproducible evaluation output

In addition to the scenario JSON reports, v0.10.0 creates a separate experiment database and publication-oriented export:

```text
artifacts/lab/evaluation.db
artifacts/lab/evaluation/environment.json
artifacts/lab/evaluation/export/experiment.json
artifacts/lab/evaluation/export/trials.json
artifacts/lab/evaluation/export/trials.csv
artifacts/lab/evaluation/export/summary.json
```

The export contains eleven trials: five operational scenarios, three recommendation what-if checks, and three approved virtual-lab remediation cycles with rollback verification. The source reports remain available under `artifacts/lab/reports/` for audit and debugging.

## Cleanup

```bash
make lab-down
rm -rf artifacts/lab
```

Raw pcap files, databases, and reports under `artifacts/lab` are ignored by Git.
