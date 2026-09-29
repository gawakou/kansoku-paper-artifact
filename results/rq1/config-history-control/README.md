# CONFIG_HISTORY_ONLY Post-hoc Control

This directory contains the minimized public artifact for the
post-hoc configuration-history control used to interpret the five
VLAN-mismatch instances responsible for the RQ1 difference between
Proposed and current-state Configuration-only diagnosis.

## Scope

CONFIG_HISTORY_ONLY receives:

- the target communication specification;
- sanitized pre-fault normalized configuration;
- sanitized post-fault normalized configuration.

It does not receive packet or flow evidence, the ground-truth manifest,
or the injected VLAN parameter.

The control is intentionally limited to the five VLAN-mismatch
parameterized instances. It is not presented as a general
historical-configuration RCA algorithm.

## Version freezing

Protocol identifier:

    config-history-v1

Successful execution-harness revision:

    v1.1

Freeze tag in gawakou/kansoku:

    paper-config-history-control-v1.1-freeze

Freeze and execution commit:

    db600665e2012c99a5665cc35ca48c111cef2006

The v1.1 revision corrected the runtime query identifier so that the
scenario/fault-family label was not exposed to the leakage checker or
diagnoser. The diagnostic rule and evaluation criteria were not changed
after successful diagnostic outputs were observed.

An earlier frozen harness revision halted before producing diagnostic
results because its query identifier contained the scenario label and
was rejected by the leakage checker. No diagnostic results from that
revision are reported.

## Primary result

Five VLAN-mismatch parameterized instances were evaluated, with one
primary execution per instance.

    strict correctness:                 5/5
    affected-device correctness:        5/5
    affected-element-type correctness:  5/5

All five returned UNKNOWN / VLAN, localized sw1, and identified VLAN
as the affected element type.

## Integrity

Before ground-truth scoring, the complete local execution outputs were
frozen with SHA-256. The SHA-256 of that private execution SHA256SUMS
file was:

    124e58cf9892600a8b6e8c0a7040159099b0aca3c7f206202f90f334d1f2d78a

That private manifest also covers local SQLite execution databases,
which are intentionally excluded from this public artifact.

The SHA-256 of the original evaluation SHA256SUMS file, generated in
the execution workspace, was:

    545bdb2c4bc6f606ab38f774d208671170e48ba5e1143a0ff77f7ec05f59309a

The public evaluation directory contains byte-identical records.csv and
summary.json files together with a relocated, relative-path SHA256SUMS
manifest suitable for verification from this repository.

## Public-data minimization

The public artifact contains sanitized configuration views, minimized
configuration deltas, diagnostic results, trial metadata, and aggregate
evaluation outputs.

SQLite experiment databases, packet captures, raw command logs,
secret-bearing logs, and other environment-specific raw artifacts are
not published.
