# KANSOKU Concept

KANSOKU is an observation-driven framework for safe infrastructure operations. It continuously observes infrastructure state, estimates operational conditions, proposes actions, validates them through target-scoped safety policies, requests human approval when required, executes approved actions, verifies postconditions, and rolls back failed changes.

Core loop:

```text
Observe
  -> Estimate State
  -> Propose Action
  -> Guard
  -> Human Approval when required
  -> Act
  -> Verify
  -> Rollback on failure
  -> Re-observe
```

The first target domain is network degradation and safe recovery. Future plugin domains include Starlink, Wi-Fi QoE, MQTT, server racks, data centers, and disaster networks.
