# Changelog

## v0.10.0

- Added persisted cross-layer evidence graphs for flows, assessments, routes, firewall rules, VLANs, interfaces, devices, and explicit evidence gaps.
- Added JSON and Graphviz DOT evidence export plus evidence-coverage scoring.
- Added alternative firewall, route, VLAN, and observation-only recommendation generation.
- Added weighted candidate ranking across repair probability, evidence coverage, reversibility, blast-radius safety, security safety, and change simplicity.
- Added named recommendation review history and explicit `REVIEWED`, `APPROVED`, and `REJECTED` decisions.
- Enforced approval eligibility in both the persistence boundary and CLI: manual-review, failed what-if, and unresolved apply templates cannot be approved.
- Added a containerlab-only remediation executor with command-family allowlists, shell-free execution, readback, service verification, rollback by default, and persistent audit records.
- Added `recommend candidates`, `evidence`, `review`, `apply-lab`, `executions`, and `execution-show` CLI commands.
- Added additive `evidence_graphs` and `remediation_executions` SQLite tables and JSON schemas.
- Extended the dashboard with ranking, evidence-graph, and virtual-lab remediation views.
- Extended the lab evaluation from 8 to 11 structured trials by adding three guarded remediation cycles.
- Expanded automated coverage from 100 to 106 tests.
- Preserved the strict safety boundary: no production-device transport is implemented.

## v0.9.1

- Added persistent experiment definitions and trial records with deterministic repetition and seed tracking.
- Added expected/observed verdicts, recommendation categories, recovery outcomes, timings, counters, artifact references, and environment metadata.
- Added aggregate pass rate, exact-match accuracy, recovery accuracy, per-scenario summaries, timing/counter distributions, and verdict-confusion counts.
- Added JSON and CSV research-data export.
- Added environment manifests with KANSOKU, Python, platform, Git, Docker, and containerlab provenance.
- Added import of the containerlab summary into five scenario trials and three recommendation what-if trials.
- Added an 18-scenario evaluation catalog with five implemented and thirteen planned scenarios.
- Added `experiment` CLI commands and additive `experiments` / `experiment_trials` SQLite tables.
- Extended `make lab-test` to produce a structured reproducibility bundle under `artifacts/lab/evaluation/`.
- Expanded automated coverage to 100 tests.
- Preserved the recommendation-only execution boundary.

## v0.9.0

- Added reviewable `ConfigurationRecommendation` records for firewall, route, VLAN, and manual-review outcomes.
- Added narrow nftables, FRRouting, and Open vSwitch command templates with rollback templates.
- Added current/desired state, impact, risk, preconditions, postconditions, and evidence-grounded rationale.
- Added model-level what-if correlation and `PASSED`, `FAILED`, or `INCONCLUSIVE` simulation status.
- Added additive SQLite persistence and a configuration-recommendation JSON schema.
- Added `recommend generate`, `list`, `show`, `validate`, and `export` CLI commands.
- Added JSON and Markdown review-packet export.
- Added read-only dashboard recommendation cards and tables.
- Extended the containerlab suite with firewall, route, and VLAN recommendation what-if checks.
- Preserved a strict execution boundary: v0.9.0 does not apply generated network configuration.
- Expanded automated coverage to 91 tests.

## v0.8.4

- Separated management-plane routes from data-plane correlation with explicit repeatable `--exclude-interface` and `--exclude-prefix` filters.
- Updated the containerlab collector to exclude the FRRouting management interface `eth0`, preventing its default route from masking route-missing faults.
- Fixed the packaged nftables fault-injection comment quoting.
- Recorded route-filter provenance and excluded-route counts in network snapshot metadata.
- Added regression tests for containerlab management default routes and packaged fault scenarios.

- Fixed the VLAN-mismatch integration assertion to read `vlan_status` from the persisted assessment JSON payload rather than a non-existent SQL column.
- Made release and nested smoke-test scripts resolve `.lab-venv`, `.venv`, or an explicit `KANSOKU_PYTHON` interpreter.
- Expanded automated coverage to 84 tests.

## v0.8.3

- Fixed live nftables JSON parsing for structured CIDR prefix and port-range operands.
- Added explicit diagnostics for failed live network-state collectors.
- Added regression tests based on native `nft -j list ruleset` operand shapes.

## 0.8.2

- Fixed virtual-lab HTTP/iperf3 service lifecycle after containerlab bootstrap.
- Added listener and end-to-end readiness checks to `make lab-up`.
- Added automatic server-service recovery during lab reset.
- Added detailed server diagnostics for readiness failures.

## 0.8.1

- Added a reproducible Ubuntu/containerlab lab with FRRouting, Open vSwitch, nftables, client, and server nodes.
- Added Ubuntu VM bootstrap, macOS VM guidance, cloud-init template, Makefile targets, and static lab self-tests.
- Added live container-scoped read-only network collectors through `network collect --container`.
- Added normal, firewall-deny, route-missing, VLAN-mismatch, packet-loss, and recovery integration scenarios.
- Added pcap acquisition inside the live firewall path and correlation against live route, VLAN, and firewall state.
- Added JSON integration reports under ignored `artifacts/lab/`.
- Corrected nftables chain ordering to use emitted evaluation order rather than numeric rule handles.
- Added conservative conntrack-state matching so established-only rules do not match initial SYN flows.
- Expanded automated coverage from 64 to 71 tests.

## 0.8.0

- Added vendor-neutral network device, interface, VLAN, L2 link, route, firewall-policy, snapshot, and flow-assessment models.
- Added additive SQLite persistence and migration for network-state entities.
- Added FRRouting JSON import for interfaces and IPv4/IPv6 route entries.
- Added Open vSwitch JSON import for access/trunk ports, VLAN membership, and configured peers.
- Added nftables JSON import for ordered match/action rules and counters.
- Added read-only live collectors for `vtysh`, `ovs-vsctl`, and `nft`.
- Added longest-prefix route lookup and explainable flow correlation across pcap flows, VLAN state, routes, and firewall rules.
- Added `network` CLI commands, dashboard inventory, flow-assessment views, schemas, and deterministic virtual-lab fixtures.
- Expanded automated coverage from 55 to 64 tests.


## 0.7.1

- Added idempotent offline pcap import keyed by target, source, and SHA-256.
- Added explicit `--force-reimport` for controlled duplicate analysis sessions.
- Added Hub-side duplicate suppression for identical captures delivered in different remote batches.
- Added additive capture fingerprint columns and migration for existing v0.7 databases.
- Replaced the synthetic sample with a valid TCP three-way handshake and a valid mDNS PTR query.
- Added correct IPv4, TCP, and UDP checksums plus release checks for duplicate suppression and packet validity.
- Expanded automated coverage from 50 to 55 tests.

## 0.7.0

- Added live tcpdump capture with BPF filters, duration/packet limits, interface selection, and explicit full-packet mode.
- Added a standard-library classic-pcap parser for Ethernet, VLAN, Linux cooked, raw IP, and common loopback link types.
- Added IPv4/IPv6 and TCP/UDP/ICMP metadata extraction plus directional 5-tuple flow aggregation.
- Added `CaptureSession` provenance with SHA-256, packet/byte counts, privacy mode, link type, local/edge storage scope, and retention metadata.
- Added persistent `FlowRecord` storage and capture/flow dashboard views.
- Added local pcap retention and quota enforcement while retaining pruned metadata.
- Extended remote ingest and durable spool batches with capture metadata and bounded flow records; raw pcap is never uploaded.
- Added `capture` and `edge pcap/capture` CLI commands.
- Added deterministic rootless sample-pcap generation and macOS smoke coverage.
- Added additive v0.6-to-v0.7 database migration and expanded automated coverage from 43 to 50 tests.

## 0.6.0

- Added authenticated remote-agent registration and token rotation.
- Added HTTP heartbeat and idempotent observation-batch ingest.
- Added durable edge spool with FIFO retry and offline retention.
- Added automatic state evaluation after remote ingest.
- Added remote-agent, heartbeat, and ingest-batch SQLite tables.
- Added remote-agent status to the read-only dashboard.
- Added remote-agent, heartbeat, ingest-batch, and receipt JSON schemas.
- Expanded automated coverage to 43 tests.

## 0.5.0

- Added persistent `ManagedTarget` inventory with per-target ping and iperf3 settings.
- Added `service once`, `service run`, `service status`, `service cycles`, and lease recovery CLI commands.
- Added due-time scheduling based on the active observation plan, target profile, or 30-second fallback.
- Added iperf3 cadence control per target.
- Added SQLite scheduler leases to prevent duplicate service instances.
- Added persistent `SchedulerCycle` audit records linking collection runs, states, proposals, and controller transactions.
- Added conservative automatic processing of low-risk proposals through the v0.4 safe controller.
- Added multi-target fleet and scheduler status to the dashboard and JSON API.
- Added v0.4-to-v0.5 additive database migration.
- Expanded tests from 24 to 33 and extended the macOS smoke test to cover the persistent service.

## 0.4.0

- Added target-scoped `SafetyPolicy` persistence with allowlists, blocked actions, approval requirements, minimum observation intervals, system-change permission, and rollback policy.
- Added explicit human `ApprovalRecord` persistence and CLI commands.
- Added the `SafeController` lifecycle: Guard -> Approval -> Act -> Verify -> Rollback.
- Added internal, simulation, and system adapter classification.
- Added dual authorization for system-changing adapters: policy permission plus explicit CLI flag.
- Added postcondition `VerificationResult` persistence.
- Added automatic rollback on failed verification for reversible actions.
- Added persistent `ControlTransaction` audit records and controller status CLI.
- Routed low-risk watch actions through the safe controller lifecycle.
- Added dashboard safety-policy and controller cards plus a complete safe-action lifecycle table.
- Clamped network metric chart minima to zero.
- Added additive v0.3 database migration for policies, approvals, verifications, and controller transactions.
- Expanded tests from 15 to 24.

## 0.3.0

- Added SQLite-backed target profiles and observation plans.
- Added relative throughput evaluation against expected bandwidth or a learned median baseline.
- Preserved v0.2 absolute thresholds when no profile is configured.
- Added automatic state estimation after ping, iperf3, simulation, and CSV replay.
- Added state-transition-aware observation-rate proposals and recovery proposals.
- Added explicit application of low-risk observation-rate plans.
- Added `agent watch`, `profile`, and `plan` CLI commands.
- Added dashboard profile/plan cards, state evidence, browser-local time, native SVG time-series charts, proposals, and clickable raw runs.
- Added automatic v0.2 database migration through additive tables.
- Expanded tests from 7 to 15, including profile evaluation, baseline learning, workflow transitions, observation-plan execution, dashboard data, CLI auto-evaluation, and database migration.
- Added macOS integration and pre-release verification scripts.

## 0.2.0

- Added platform-aware macOS/Linux ping collection.
- Added iperf3 TCP/UDP JSON collection and normalization.
- Added CollectionRun provenance records with raw stdout/stderr.
- Added raw JSON artifact export.
- Added local read-only Web dashboard and JSON API.
- Added collection-run inspection CLI.
- Added GitHub Actions and expanded tests.
- Prevented command permission/configuration errors from being misclassified as target outages.

## 0.1.0

- Initial modular closed-loop prototype with Agent, Hub, State, Guard, Act, Replay, and text View.
