# Safety model

KANSOKU v0.4 separates observation, state estimation, proposal generation, policy validation, human approval, execution, verification, and rollback.

## Default behavior

- Dry-run is the default.
- Only allowlisted low-risk observation-rate changes are auto-approved.
- Medium- and high-risk actions require an explicit `ApprovalRecord`.
- A human rejection causes Guard rejection.
- Reversible actions require rollback definitions.
- Postconditions are mandatory.
- Requested observation intervals cannot be shorter than the policy minimum.
- System-changing adapters are disabled by default.

## Dual authorization for system changes

A system adapter is executed only when:

1. the effective persisted `SafetyPolicy` has `allow_system_changes=true`; and
2. the controller command includes `--allow-system-changes`.

This prevents either a permissive policy or an accidental CLI invocation from being sufficient by itself.

## Verification and rollback

- Internal observation-plan actions are verified against the persisted interval.
- Other actions require a post-action state or adapter-specific verifier.
- Missing post-action evidence produces `INCONCLUSIVE`, not a false success.
- Failed verification triggers rollback when the policy permits it and a rollback is defined.
- Both primary and rollback action results are persisted.

## Auditability

The Hub stores:

- proposal;
- effective policy ID;
- Guard decision;
- human approval/rejection;
- action result;
- verification result;
- rollback result;
- final controller transaction.

The dashboard is read-only and binds to localhost by default.

## Remote ingest boundary in v0.6

A valid remote-agent token authorizes only heartbeat and observation ingest. It does not authorize Safety Policy changes, human approval records, action execution, observation-plan updates, or system-adapter access. Remote observations enter the same explainable State and guarded Controller pipeline as local observations.

## v0.7 capture privacy controls

Packet observation is treated as evidence acquisition, not as an unrestricted action. The default live-capture policy is a 96-byte snaplen, local raw-pcap retention, bounded flow export, and explicit BPF filtering. `--full-packet` is an operator opt-in because it can retain application payload. Remote ingest never accepts raw pcap bytes in v0.7. Retention and storage quotas reduce persistence risk but do not replace authorization, access control, or legal/ethical review.

## v0.8 read-only configuration boundary

FRR, OVS, and nftables collectors execute only documented show/list commands and mark their `CollectionRun` as read-only. Offline import is preferred for reproducible tests. Correlation results do not trigger control proposals automatically. Production collection still requires operator authorization because configuration and topology data can disclose sensitive infrastructure details.

## v0.9 recommendation-only boundary

Generated FRRouting, Open vSwitch, and nftables strings are review artifacts, not executable actions. The recommendation engine performs no subprocess call and does not invoke `ActEngine` or `SafeController`.

Each actionable recommendation must include rollback templates and explicit preconditions and postconditions. A model-level `PASSED` result only means the normalized route/policy/VLAN model predicts an `ALLOW` verdict after the proposed delta. It does not prove vendor syntax, control-plane convergence, performance safety, policy authorization, or absence of unintended reachability.

Any future application workflow must require a separate human-approved proposal and pass the existing dual authorization, Guard, verifier, and rollback controls.
