# KANSOKU v0.10.0

KANSOKU v0.10.0 turns the review-only v0.9 recommendation pipeline into a guarded, measurable remediation prototype while retaining a strict laboratory boundary.

## Added

- Cross-layer `EvidenceGraph`, `EvidenceNode`, and `EvidenceEdge` records linking flows, assessments, devices, routes, firewall rules, VLANs, interfaces, and explicit evidence gaps.
- JSON and Graphviz DOT evidence export with an evidence-coverage metric.
- Alternative recommendation generation for firewall, route, VLAN, and observation-only candidates.
- Weighted candidate ranking using model repair probability, evidence coverage, rollback reversibility, blast-radius safety, security safety, and change simplicity.
- Named human review decisions with `REVIEWED`, `APPROVED`, and `REJECTED` status history.
- Approval invariants enforced below the CLI so manual-review candidates, failed what-if outcomes, and unresolved apply templates cannot cross the execution boundary.
- A containerlab-only executor for approved FRRouting, Open vSwitch, and nftables recommendations.
- Shell-free command execution, command-family allowlists, read-only configuration readback, fixed service verification, rollback by default, and persistent execution audit records.
- Experiment import for three guarded remediation trials in addition to the existing five network scenarios and three recommendation what-if trials.
- Dashboard views for ranking metadata, evidence graphs, and virtual-lab remediation executions.

## Database migration

Opening an earlier database adds:

```text
evidence_graphs
remediation_executions
```

Existing observations, captures, network state, assessments, recommendations, experiments, and trials are preserved.

## Safety boundary

The v0.10 executor accepts only `environment=virtual-lab` and a named containerlab topology. It has no SSH, NETCONF, RESTCONF, gNMI, or vendor API adapter. It never invokes a shell, requires a stored `APPROVED` recommendation with a successful model-level what-if result, and rolls back after verification unless `--keep-change` is explicitly supplied.
