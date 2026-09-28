# KANSOKU v0.9.1 Validation Plan

## Source-level checks

- Python compilation succeeds.
- All automated tests pass.
- JSON schemas parse.
- Existing pcap idempotency and checksum checks pass.
- v0.8 network-state and v0.9 recommendation smoke tests pass.
- v0.9.1 experiment definition, trial persistence, metrics, CSV export, environment manifest, and scenario-catalog checks pass.
- Virtual-lab topology and shell scripts pass static validation.

## Ubuntu/containerlab integration

Run:

```bash
make lab-up
make lab-status
make lab-test
make lab-down
```

Expected operational checks:

1. normal → `ALLOW`;
2. firewall-deny → `DENY`;
3. route-missing → `UNROUTABLE`;
4. vlan-mismatch → `UNKNOWN / UNKNOWN_VLAN`;
5. packet-loss injection and recovery;
6. firewall recommendation → `FIREWALL_POLICY / ALLOW`;
7. route recommendation → `ROUTE / ALLOW`;
8. VLAN recommendation → `VLAN / ALLOW`.

Expected evaluation checks:

- eight lab outputs imported as eight experiment trials;
- trial pass count equals eight;
- verdict accuracy equals 1.0 for evaluated records;
- recommendation-category accuracy equals 1.0;
- recovery accuracy equals 1.0;
- `experiment.json`, `trials.json`, `trials.csv`, and `summary.json` are exported.

Artifacts are written to:

```text
artifacts/lab/reports/
artifacts/lab/evaluation.db
artifacts/lab/evaluation/environment.json
artifacts/lab/evaluation/export/
```

The artifact directory is intentionally ignored by Git.
