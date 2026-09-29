# Source Provenance

## Evaluated software baseline

KANSOKU v0.10.0

Commit:

5defbf8996d956ed455c568ec28426ffb8c2c74f

This is the fixed software baseline evaluated in the paper.

## Paper-specific evaluation snapshot

Private development repository:

gawakou/kansoku

Branch:

paper/kansoku-concept

Artifact assembly snapshot:

8740edd8577bcb1e0af85c3c197254e7fa25ee5f

Paper-specific experiment runners, manifests, evaluation scripts,
and audit material are separated from the evaluated v0.10.0 software
snapshot.

## Post-hoc RQ1 configuration-history control

A targeted post-hoc control was added after the primary formal RQ1
outputs had been frozen. It is limited to the five VLAN-mismatch
parameterized instances responsible for the observed difference between
Proposed and current-state Configuration-only diagnosis.

Private development repository:

gawakou/kansoku

Freeze tag:

paper-config-history-control-v1.1-freeze

Freeze and successful execution commit:

db600665e2012c99a5665cc35ca48c111cef2006

Protocol identifier:

config-history-v1

Execution-harness revision:

v1.1

The control receives the target communication specification and
sanitized pre-fault and post-fault normalized configuration. It does
not receive packet/flow evidence, ground truth, or the injected VLAN
parameter.

The control obtained strict correctness of 5/5 for the evaluated
VLAN-mismatch instances. This post-hoc result is supplemental to, and
does not modify, the frozen primary RQ1 results.

## Exclusions

The public artifact excludes unrestricted packet captures, SQLite
experiment databases, secret-bearing logs, raw command logs, and other
environment-specific raw artifacts.
