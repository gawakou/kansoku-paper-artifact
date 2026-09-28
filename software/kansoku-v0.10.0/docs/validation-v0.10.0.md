# KANSOKU v0.10.0 Validation Plan

## Source-level checks

The packaged release candidate has passed the following non-Docker checks:

- Python compilation succeeds.
- 106 automated tests pass.
- JSON schemas parse successfully.
- The v0.8 flow/configuration smoke test, v0.9 recommendation smoke test, v0.9.1 experiment smoke test, and v0.10 evidence/ranking/remediation smoke test pass.
- The containerlab topology and all shell scripts pass static validation.

## Ubuntu integration acceptance criteria

The release candidate is accepted only after the Ubuntu Docker/containerlab test completes:

- 5/5 live network scenarios;
- 3/3 model-level recommendation checks;
- 3/3 named-approval remediation cycles;
- successful post-change service verification;
- successful rollback verification;
- import/export of 11 structured experiment trials.

## Execution boundary

No production-device transport is included. All write execution is restricted to containers whose names are derived from the explicitly supplied containerlab lab name.

## Ubuntu Docker/containerlab Integration Validation

- Validation date: 2026-07-19
- Platform: Ubuntu Linux
- Runtime: Docker and containerlab
- KANSOKU version: 0.10.0
- Python automated tests: 107/107 passed
- Network diagnosis scenarios: 5/5 passed
- Configuration recommendation checks: 3/3 passed
- Guarded remediation checks: 3/3 passed
- Structured experiment trials: 11/11 passed
- Pre-release checks: passed
- Virtual-lab static self-test: passed

### Validated Network Scenarios

| Scenario | Expected result | Result |
|---|---|---|
| Normal communication | `ALLOW` | Passed |
| Firewall deny | `DENY` | Passed |
| Missing route | `UNROUTABLE` | Passed |
| VLAN mismatch | `UNKNOWN / UNKNOWN_VLAN` | Passed |
| Packet loss | Fault injection and recovery | Passed |

### Configuration Recommendation Validation

| Scenario | Recommendation | Simulated result | Result |
|---|---|---|---|
| Firewall deny | `FIREWALL_POLICY` | `ALLOW` | Passed |
| Missing route | `ROUTE` | `ALLOW` | Passed |
| VLAN mismatch | `VLAN` | `ALLOW` | Passed |

### Guarded Remediation Validation

The following sequence was validated for the firewall, route, and VLAN
scenarios:

1. Inject a network fault.
2. Collect packet-flow and configuration evidence.
3. Diagnose the cross-layer fault.
4. Generate a configuration recommendation.
5. Validate the recommendation using the model-based what-if function.
6. Record explicit operator approval.
7. Apply the configuration change only inside the named containerlab node.
8. Verify recovery of the target communication.
9. Roll back the configuration change.
10. Verify restoration of the injected fault state.

All three guarded remediation scenarios completed the apply, verification,
rollback, and rollback-verification sequence successfully.

### Integration Issue Identified and Corrected

During the firewall remediation test, an nftables rule comment containing
spaces lost its literal quotation marks when the command was converted from
a reviewable command string into a shell-free `docker exec` argument list.

The generated recommendation was correct, but nftables received the comment
as unquoted tokens and rejected the rule with a syntax error.

The execution boundary was corrected so that nftables string literals retain
their quotation marks when passed as process arguments. A regression test was
added to verify this behavior.

The corrected implementation passed:

- 7/7 remediation-specific tests
- 107/107 automated Python tests
- Actual nftables rule application
- Service recovery verification
- Runtime nftables handle acquisition
- Rule deletion during rollback
- Fault-restoration verification

### Safety Boundary

Version 0.10.0 restricts remediation execution to explicitly named
containerlab containers.

The following are not supported by this release:

- Production network devices
- Arbitrary remote hosts
- SSH-based configuration
- NETCONF
- RESTCONF
- gNMI
- Arbitrary shell command execution

A failed command is recorded as a failed remediation execution, and subsequent
verification or rollback stages are not executed unless the required prior
stage succeeds.

### Reproduction Commands

```bash
.lab-venv/bin/python -m pytest -q
./scripts/pre_release_check.sh
./lab/scripts/lab-selftest.sh

make lab-up
make lab-status
make lab-test
make lab-down
