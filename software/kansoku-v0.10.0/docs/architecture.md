# KANSOKU architecture

```text
Persistent Target Inventory
          |
          v
Observation Service Scheduler -- SQLite Lease
          |
          +--> due target --> Ping / iperf3 / Simulation
                              |
                              v
Hub (Observation + CollectionRun + SchedulerCycle)
                              |
                              v
TargetProfile + State Engine
                              |
                              v
StateEstimate + ActionProposal
                              |
                              v
Effective SafetyPolicy
                              |
                              v
Guard -> Human Approval -> Act -> Verify
                              |       |
                              |       +---- failure ----> Rollback
                              v
                       ObservationPlan
                              |
                              +---- changes next service due time
```

## Core modules

- `inventory.py`: persistent managed-target configuration.
- `scheduler.py`: scheduler-cycle, lease, and due-status records.
- `service.py`: due calculation, target collection, lease handling, automatic evaluation, and conservative low-risk controller integration.
- `agent.py`: simulation, ping, and iperf3 collectors.
- `capture.py`: tcpdump execution, classic-pcap parsing, privacy-aware capture provenance, flow aggregation, and retention/quota enforcement.
- `hub.py`: additive SQLite persistence compatible with earlier databases.
- `experiment.py`: experiment/trial models, environment provenance, lab-summary import, aggregate metrics, and CSV/JSON export.
- `profiles.py`: target expectations, learned throughput baselines, and observation plans.
- `state.py`: explainable absolute or profile-relative state estimation.
- `safety.py`, `guard.py`, `controller.py`, `verifier.py`: safe action lifecycle.
- `dashboard.py`: local read-only target and fleet dashboard.
- `view.py`: textual observation, scheduler, and action-lifecycle timeline.

## Scheduling boundary

The service computes a due time from the persisted observation plan, then the target profile, then a 30-second fallback. A disabled target is never scheduled. A SQLite lease prevents concurrent service instances from processing the same database.

The service can auto-process only low-risk proposals and always calls the safe controller with system changes disabled. Persistent service execution therefore does not bypass the v0.4 safety model.

## v0.6 distributed observation plane

```text
┌──────────────────────── Edge node ────────────────────────┐
│ PingAgent / Iperf3Agent / Simulation                      │
│          ↓                                                │
│ IngestBatch → durable SpoolQueue → RemoteHubClient        │
└───────────────────────────┬────────────────────────────────┘
                            │ Bearer token + agent ID
                            ▼
┌──────────────────────── KANSOKU Hub ───────────────────────┐
│ RemoteAgent registry → Ingest API → idempotency check      │
│                         ↓                                  │
│ CollectionRun + Observation + IngestReceipt                │
│                         ↓                                  │
│ State → Proposal → Guard → Approval → Act → Verify         │
└────────────────────────────────────────────────────────────┘
```

The remote observation plane is intentionally one-way. Edge agents can submit observations and health data, but cannot modify profiles, policies, approvals, plans, or controller permissions through the ingest API.

## v0.7 packet and flow observation plane

```text
Network interface / mirror port / virtual link
                |
                v
      tcpdump + BPF filter
                |
      classic pcap stored locally
                |
                v
  Header parser + flow aggregator
       |                    |
       v                    v
CaptureSession         FlowRecord[]
       \                    /
        \                  /
         Observation metrics
                |
                v
      local Hub or IngestBatch
```

The default live capture uses a 96-byte snaplen and records `privacy_mode=headers-only`. Full-packet capture is opt-in. Raw pcap is not part of the remote `IngestBatch`; only provenance, normalized capture observations, and a bounded set of flow records are transmitted.

The parser is intentionally independent of libpcap bindings so offline summarization and CI are rootless and dependency-free. Live capture still uses the platform `tcpdump` command and may require elevated capture privileges.

The v0.7 remote observation plane remains one-way. Edge pcap paths are recorded with `storage_scope=edge` as provenance and are not accessible as Hub-local files.

## v0.8 network-state and correlation plane

The v0.8 plane adds vendor-neutral configuration evidence beside packet/flow evidence. Platform adapters normalize FRRouting, Open vSwitch, and nftables JSON into SQLite snapshots. The correlation engine selects an installed route by longest prefix, matches basic ordered firewall rules, verifies captured VLAN presence, and persists a `FlowAssessment`. Read-only collectors are separated from v0.4 guarded action adapters; no device configuration is changed in v0.8.

## v0.9 recommendation plane

```text
FlowAssessment + FlowRecord + latest normalized state
                    |
                    v
          RecommendationEngine
                    |
        +-----------+-----------+
        |           |           |
        v           v           v
   nftables       FRR route    OVS VLAN
   candidate      candidate    candidate
        \           |           /
         \          |          /
          v         v         v
      ConfigurationRecommendation
      - rationale and evidence
      - current / desired state
      - narrow command templates
      - rollback templates
      - impact and risk
      - preconditions / postconditions
      - model-level what-if verdict
```

The v0.9 plane is review-only. It does not call `subprocess`, a system adapter, or the v0.4 action engine. A later controlled-application layer must separately convert an approved recommendation into an action proposal and pass the existing Guard, approval, execution, verification, and rollback lifecycle.


## v0.9.1 reproducible evaluation plane

```text
Scenario catalog + experiment definition
                    |
                    v
          deterministic trial matrix
                    |
        +-----------+-----------+
        |                       |
        v                       v
 raw lab reports       manually recorded trials
        \                       /
         \                     /
          v                   v
             ExperimentTrial[]
                    |
                    v
      summary metrics + confusion counts
                    |
                    v
 experiment.json / trials.json / trials.csv / summary.json
```

The evaluation plane does not alter diagnosis or recommendation decisions. It records the planned scenario, repetition, seed, ground truth, observed output, timing, counters, artifacts, and environment provenance. This separation supports baseline and ablation experiments without weakening the existing execution boundary.

## v0.10 evidence and guarded remediation plane

The v0.10 plane adds two explicit boundaries after `FlowAssessment`:

```text
FlowAssessment
  → EvidenceGraph
  → alternative ConfigurationRecommendation records
  → weighted ranking
  → named human review
  → containerlab-only apply
  → readback and service verification
  → rollback by default
  → RemediationExecution audit record
```

The executor has no production transport and does not use a shell. Its only write path is an explicitly named disposable lab container.
