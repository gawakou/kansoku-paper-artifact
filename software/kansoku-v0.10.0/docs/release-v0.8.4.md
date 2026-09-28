# KANSOKU v0.8.4

KANSOKU v0.8.4 is the validated virtual-lab release candidate. It prevents out-of-band container management routes from participating in data-plane flow correlation and includes the corrected nftables fault-injection command.

## Key fixes

- Explicit route filtering with `--exclude-interface` and `--exclude-prefix`
- Containerlab FRRouting collection excludes management interface `eth0`
- Route-missing scenario can correctly produce `UNROUTABLE` even when the container has a management default route
- Correct nftables comment quoting in the firewall-deny scenario
- Filter provenance retained in `NetworkSnapshot.metadata`

- Fixed the VLAN-mismatch integration assertion to read `vlan_status` from the persisted assessment JSON payload rather than a non-existent SQL column.
- Made release and nested smoke-test scripts resolve `.lab-venv`, `.venv`, or an explicit `KANSOKU_PYTHON` interpreter.
- Expanded automated coverage to 84 tests.
