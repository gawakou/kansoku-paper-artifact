# Data model

## Observation

A normalized metric with target, source, timestamp, method, quality, and labels. Real command observations include a `run_id` label.

## CollectionRun

The complete provenance record for one ping or iperf3 invocation: command, return code, stdout, stderr, timing, source, target, and metadata.

## TargetProfile

Target-specific expected bandwidth or learned throughput baseline, relative throughput ratios, RTT/loss thresholds, and normal/intensive observation intervals.

## StateEstimate

Operational state, confidence, reason, control mode, evidence observation IDs, and extracted features.

## ActionProposal

A proposed control or observation action with risk, preconditions, postconditions, expected effect, and rollback.

## ObservationPlan

The active observation interval and mode persisted after an explicitly executed observation-rate action.

## SafetyPolicy

A target-scoped policy containing:

- allowed, blocked, auto-approved, approval-required, and rollback-required actions;
- blocked targets;
- minimum observation interval;
- system-change permission;
- rollback-on-verification-failure behavior.

A policy scoped to `*` is the default when no target-specific policy exists.

## GuardDecision

The validation result for one proposal under one effective policy. v0.4 stores both `policy_version` and `policy_id`.

## ApprovalRecord

An explicit human approval or rejection with actor, comment, proposal ID, and timestamp.

## ActionResult

Execution evidence including status, adapter class (`internal`, `simulation`, `system`, or `legacy`), command, stdout/stderr, return code, and whether the result is a rollback.

## VerificationResult

A postcondition result with `PASSED`, `FAILED`, `INCONCLUSIVE`, or `SKIPPED`, plus structured checks and a reason.

## ControlTransaction

The audit envelope for one controller attempt. It links proposal, Guard decision, approval, action result, verification, rollback result, final outcome, and message.

## ManagedTarget

Persistent target inventory configuration: enabled state, ping settings, iperf3 cadence and parameters, raw-evidence directory, and whether low-risk proposals may be sent to the safe controller automatically.

Evaluation thresholds remain in `TargetProfile`; action permissions remain in `SafetyPolicy`.

## SchedulerCycle

One persistent service attempt for one target. It stores owner, timing, status, collection-run IDs, observation count, state, proposal, controller transaction, and diagnostic message.

## SchedulerLease

A time-bounded SQLite lease that prevents two observation-service instances from processing the same database concurrently. Expired leases can be replaced; forced release is an operator recovery action.

## v0.6 remote entities

### RemoteAgentRegistration

Stores agent identity, capabilities, labels, enabled state, token fingerprint, PBKDF2 token-hash material, creation/update timestamps, and last-seen time. Public representations omit all token-hash material.

### AgentHeartbeat

Stores agent ID, hostname, KANSOKU version, online status, local spool depth, platform metadata, and timestamp.

### IngestBatch

Immutable edge-to-Hub delivery unit containing normalized `Observation` objects and zero or more raw `CollectionRun` objects. `batch_id` is the idempotency key.

### IngestReceipt

Hub acknowledgement containing accepted counts, affected targets, duplicate status, receipt ID, and receive time.

## v0.7 packet and flow entities

### CaptureSession

Provenance for one live or offline packet-capture artifact: target, source, interface, BPF filter, snaplen, privacy mode, path, SHA-256, file size, packet/captured/wire byte counts, flow count, link type, duration, retention, storage scope, timestamps, and parser counters. The Hub stores an indexed fingerprint and a deduplication key derived from target, source, and SHA-256; explicit force-reimport sessions retain distinct capture IDs. `storage_scope=edge` means the path names an edge-local artifact and is not a Hub-downloadable file.

### FlowRecord

A directional aggregate keyed by IP version, protocol, source/destination IP, source/destination port, and optional VLAN ID. It stores packet and byte totals, first/last timestamps, counted TCP flags, capture ID, target, source, and metadata. Directional records are retained separately so asymmetric behavior remains observable.

### IngestBatch v0.7 extension

In addition to observations and collection runs, a batch may contain capture-session metadata and bounded flow records. Older batches without these arrays remain readable through dataclass defaults. Raw pcap bytes are never serialized into the batch.

### IngestReceipt v0.7 extension

Adds `capture_count` and `flow_count` while retaining the v0.6 observation/run counts and idempotency behavior.

## v0.8 network-state entities

- `NetworkDevice`: logical inventory record for a router, L2/L3 switch, firewall, host, or generic node.
- `NetworkSnapshot`: immutable import provenance and entity counts for one collector run.
- `NetworkInterface`: normalized administrative/operational state, addressing, VRF, bridge, and VLAN mode.
- `VlanRecord`: device-local VLAN membership.
- `L2Link`: configured or discovered interface-to-interface adjacency.
- `RouteEntry`: normalized prefix, protocol, next hop, output interface, metric, distance, and selected/installed state.
- `PolicyRule`: normalized ordered ACL/firewall match/action rule.
- `FlowAssessment`: explainable relation between a `FlowRecord` and route, policy, and VLAN evidence.

## v0.9 configuration recommendation entity

### ConfigurationRecommendation

A reviewable plan derived from one `FlowAssessment` and its `FlowRecord`. It stores the target device and platform, category, intent, risk, confidence, rationale, current and desired state, command templates, rollback templates, impact, preconditions, postconditions, model-level what-if status, and immutable source identifiers.

Supported categories are:

- `FIREWALL_POLICY`
- `ROUTE`
- `VLAN`
- `MANUAL_REVIEW`

Actionable recommendations remain `DRAFT` by default. `simulation_status` records `PASSED`, `FAILED`, `INCONCLUSIVE`, or `NOT_RUN`; it does not represent execution against a live device.

## v0.9.1 experiment entities

### ExperimentDefinition

A persistent research-design record containing scenario identifiers, repetition count, base seed, comparison baselines, planned metrics, lifecycle status, tags, and metadata. It is separate from operational evidence so the same KANSOKU database can preserve both runtime observations and the evaluation plan that interprets them.

### ExperimentTrial

One scenario repetition with explicit ground truth and observed output. It may contain diagnosis verdicts, recommendation categories, recovery outcomes, timing measurements, arbitrary numeric counters, artifact references, an environment manifest, error text, and scenario-specific metadata.

The model permits partially populated trial types: diagnosis-only, recommendation-only, and recovery-only records are valid. Aggregate metrics evaluate only records containing both expected and observed values.

## v0.10 evidence and remediation entities

- `EvidenceGraph`: assessment-scoped graph containing typed evidence nodes and relations.
- `EvidenceNode`: flow, assessment, device, route, policy rule, VLAN, interface, or explicit evidence-gap node.
- `EvidenceEdge`: typed relation such as `ROUTED_BY`, `MATCHED_BY`, `TAGGED_WITH`, or `MISSING`.
- `RemediationExecution`: named approval, allowlisted apply results, readback, post-change verification, rollback results, rollback verification, and error/audit metadata.

The corresponding additive tables are `evidence_graphs` and `remediation_executions`.
