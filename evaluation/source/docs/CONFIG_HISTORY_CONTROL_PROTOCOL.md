# CONFIG_HISTORY_ONLY post-hoc control protocol (v1)

## Question

The original RQ1 VLAN-mismatch gain used a retained pre-fault tagged-flow observation as a temporal reference and post-fault OVS state. This control asks a narrower question: **can an equivalent pre-fault normalized configuration snapshot provide the same temporal signal without packet/flow evidence?**

## Scope

Only the five frozen `vlan-mismatch-v01` ... `vlan-mismatch-v05` parameterized instances are included. This is a post-hoc control, not a fourth primary baseline for the original 60-instance RQ1 experiment.

## Inputs available to the diagnoser

- target communication specification;
- sanitized pre-fault normalized FRR/OVS/nftables state;
- sanitized post-fault normalized FRR/OVS/nftables state.

The diagnoser receives **no packet/flow evidence, no ground-truth manifest, and no injected VLAN value**. The shell runner reads the frozen `drift_vlan` parameter solely to apply the fault in the laboratory; it is not passed to the diagnosis program.

## Decision rule

1. Run the existing `CONFIG_ONLY` diagnosis on post-fault state.
2. If that current-state diagnosis already identifies a represented non-`ALLOW` cause, preserve that diagnosis.
3. Otherwise compare semantic signatures of the pre/post normalized state while ignoring identifiers, timestamps, raw metadata, nftables counters, and policy comments.
4. If route state, firewall policy state, and non-VLAN interface state are unchanged, while VLAN membership and/or interface VLAN configuration changed on the configured VLAN device, report `UNKNOWN/VLAN` on that device.
5. Otherwise report `UNKNOWN/UNKNOWN` and abstain.

This rule intentionally does not infer an expected VLAN from ground truth. It detects a temporal normalized-configuration delta. In the present single-fault laboratory it is a targeted control, not a general configuration-history RCA algorithm.

## Primary unit and metrics

The primary unit is the five distinct parameterized VLAN-mismatch instances at repetition 1. Repetitions 2--5, if executed, are stability checks only and are not additional independent accuracy samples.

Primary metrics are joint verdict/fault-domain strict correctness, affected-device correctness, and affected-element-type correctness.

## Interpretation fixed before execution

- **5/5 strict correct:** the equivalent normalized configuration history recovers the temporal VLAN-drift signal in all five evaluated instances. The manuscript should attribute the original 5-instance gain to the availability of a pre-fault temporal reference, with flow evidence as one way to supply that reference, rather than claim uniqueness of flow evidence.
- **<5/5 strict correct:** the implemented configuration-history control does not fully recover the temporal signal. Any residual difference must be limited to these evaluated instances and to this control design.

## Freeze procedure

Commit the protocol, runner, diagnoser, evaluator, and source plan before execution, then create the annotated tag:

```bash
git tag -a paper-config-history-control-v1-freeze -m "Freeze CONFIG_HISTORY_ONLY post-hoc control v1"
```

The runner refuses execution if these files differ from the freeze tag. This is **version freezing**, not an externally verifiable preregistration claim.
