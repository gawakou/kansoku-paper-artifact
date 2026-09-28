# Reproducible experiment workflow

KANSOKU v0.10.0 separates operational evidence from evaluation metadata. Runtime observations remain in the existing capture, flow, snapshot, assessment, and recommendation tables. Research design and trial outcomes are stored in `experiments` and `experiment_trials`.

## Experiment definition

An experiment records:

- a stable identifier and human-readable name;
- scenario identifiers;
- repetition count and base seed;
- comparison baselines;
- planned metrics;
- lifecycle status;
- tags and metadata.

```bash
kansoku --db evaluation.db experiment create \
  --name "cross-layer ablation" \
  --scenario normal \
  --scenario firewall-deny \
  --scenario route-missing \
  --repetitions 20 \
  --base-seed 20260718 \
  --baseline flow-only \
  --baseline configuration-only \
  --baseline full-correlation
```

## Trial record

A trial records ground truth and observed output without assuming that every scenario has all fields. Diagnosis trials can use verdict fields, recommendation trials can use category fields, and recovery trials can use Boolean recovery fields.

```bash
kansoku --db evaluation.db experiment record \
  --experiment-id experiment-xxxxxxxxxxxx \
  --scenario-id route-missing \
  --repetition 1 \
  --seed 20260719 \
  --status PASS \
  --expected-verdict UNROUTABLE \
  --observed-verdict UNROUTABLE \
  --expected-category ROUTE \
  --observed-category ROUTE \
  --timing diagnosis=21.3 \
  --timing recommendation=9.6 \
  --counter observation_bytes=24576 \
  --counter packet_count=5 \
  --artifact report=artifacts/lab/reports/route-missing.json
```

## Environment manifest

The manifest captures the KANSOKU version, Python implementation, operating system, machine architecture, hostname, CPU count, Git commit, dirty-tree indicator, Docker version, containerlab version, and user-supplied labels.

```bash
kansoku experiment manifest \
  --output artifacts/evaluation/environment.json \
  --label site=lab-a \
  --label topology=kansoku-v100
```

A manifest may be attached to manually recorded trials or imported lab trials.

## Virtual-lab import

`make lab-test` writes the existing raw scenario reports and then creates a separate evaluation database. Five scenario results, three recommendation what-if results, and three guarded remediation results are imported as eleven trials.

```bash
kansoku --db artifacts/lab/evaluation.db experiment import-lab \
  --experiment-id experiment-xxxxxxxxxxxx \
  --summary artifacts/lab/reports/summary.json \
  --environment-manifest artifacts/lab/evaluation/environment.json
```

## Aggregate output

```bash
kansoku --db evaluation.db experiment summarize \
  --experiment-id experiment-xxxxxxxxxxxx \
  --output artifacts/evaluation/summary.json

kansoku --db evaluation.db experiment export \
  --experiment-id experiment-xxxxxxxxxxxx \
  --output-dir artifacts/evaluation/export
```

The export directory contains:

```text
experiment.json
trials.json
trials.csv
summary.json
```

The summary reports exact-match verdict and recommendation accuracy. This is intentionally transparent and conservative; macro-F1 and confidence intervals should be computed from exported trial data when the scenario matrix becomes sufficiently large.

## Scenario catalog

The initial catalog is `scenarios/evaluation/catalog.json`. It contains 18 unique scenarios across healthy operation, L2, L3, firewall, link, compound-fault, and background-traffic categories. Five are implemented in v0.10.0. The remaining entries provide a stable implementation and paper-evaluation backlog.

Validate it with:

```bash
kansoku experiment validate-catalog \
  --file scenarios/evaluation/catalog.json
```

## Reproducibility boundary

The evaluation layer records what was run and what was observed. Model-level what-if results remain distinct from live remediation results. v0.10 separately records service recovery, readback, and rollback verification in the virtual lab; production-device impact and collateral traffic evaluation remain future work.
