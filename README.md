# KANSOKU Paper Artifact

Research artifact for:

**KANSOKU: A Flow-Centric Evidence Framework for Cross-Layer
Network Diagnosis and Guarded Remediation**

This repository contains the frozen software snapshot, experimental
definitions, evaluation scripts, minimized results, audit records, and
environment provenance associated with the paper.

This is not the active KANSOKU development repository.

## Software baseline

The software evaluated in the paper is KANSOKU v0.10.0:

5defbf8996d956ed455c568ec28426ffb8c2c74f

Paper-specific evaluation material was assembled from:

8740edd8577bcb1e0af85c3c197254e7fa25ee5f

## Repository contents

- `software/`: frozen KANSOKU v0.10.0 software baseline
- `evaluation/source/`: paper-specific scenarios, runners, evaluators, and lab definitions
- `results/rq1/`: formal RQ1 results and boundary audit
  - `results/rq1/config-history-control/`: version-frozen post-hoc configuration-history control for the five VLAN-mismatch instances
- `results/rq2/`: formal recommendation/ranking results
- `results/rq3/`: formal guarded-remediation results
- `results/audits/`: post-hoc integrity and reproducibility audits
- `provenance/`: source and environment provenance
- `checksums/`: SHA-256 checksums

## Artifact versions

- `paper-artifact-v1.0.0`: primary frozen paper artifact.
- `paper-artifact-v1.1.0`: extends v1.0.0 with the targeted post-hoc
  `CONFIG_HISTORY_ONLY` control and its minimized results. The original
  formal RQ1/RQ2/RQ3 results are unchanged.

## Excluded data

This public artifact intentionally excludes unrestricted packet captures,
SQLite experiment databases, secret-bearing logs, raw command logs, and
other environment-specific artifacts that are not required to inspect
the reported results.

## License

No open-source license has been assigned to this repository at this time.

This repository is publicly available to support research transparency,
inspection of the reported artifacts, and verification of the results.
Public availability does not grant permission to use, modify, redistribute,
or create derivative works from the software except as permitted by
applicable law and the GitHub Terms of Service.

Unless otherwise stated, all rights are reserved by the applicable
copyright holder(s).

Licensing terms may be updated in the future after coordination between
the author and the affiliated institution.
