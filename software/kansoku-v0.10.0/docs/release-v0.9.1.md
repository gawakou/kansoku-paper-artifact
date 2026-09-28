# KANSOKU v0.9.1

KANSOKU v0.9.1 adds the reproducible evaluation substrate needed to turn the v0.9 diagnosis and recommendation prototype into a measurable research system.

## Added

- Persistent `ExperimentDefinition` and `ExperimentTrial` records.
- Deterministic repetition and seed tracking.
- Expected and observed diagnosis verdicts, recommendation categories, and recovery outcomes.
- Timing, data-volume, packet, flow, and arbitrary numeric counters.
- Artifact references and environment manifests.
- Aggregate pass rate, verdict accuracy, recommendation accuracy, recovery accuracy, timing distributions, counter distributions, scenario-level summaries, and verdict-confusion counts.
- JSON and CSV exports suitable for statistical analysis and paper figures.
- Import of the containerlab `summary.json` into eight structured trials.
- An 18-scenario catalog separating five implemented cases from the planned evaluation backlog.
- `experiment create`, `list`, `show`, `status`, `record`, `trials`, `import-lab`, `summarize`, `export`, `manifest`, and `validate-catalog` CLI commands.

## Database migration

Opening an earlier KANSOKU database adds:

```text
experiments
experiment_trials
```

Existing observations, captures, network state, assessments, and recommendations are preserved.

## Safety boundary

v0.9.1 records and evaluates recommendations. It does not apply generated FRRouting, Open vSwitch, or nftables commands.
