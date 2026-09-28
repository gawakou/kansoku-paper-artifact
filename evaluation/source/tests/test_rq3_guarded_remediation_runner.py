from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

from kansoku.recommendation import (
    ConfigurationRecommendation,
)


ROOT = Path(__file__).resolve().parents[1]

MODULE = (
    ROOT
    / "scripts"
    / "experiments"
    / "run_rq3_guarded_remediation.py"
)

spec = importlib.util.spec_from_file_location(
    "run_rq3_guarded_remediation",
    MODULE,
)

assert spec is not None
assert spec.loader is not None

runner = importlib.util.module_from_spec(
    spec
)
spec.loader.exec_module(runner)


def test_frozen_rq3_plan_loads():
    plan = runner.load_frozen_plan(
        ROOT
        / "scenarios"
        / "paper"
        / "rq3_guarded_remediation_plan.json"
    )

    assert plan["execution_count"] == 15

    assert set(
        plan["families"]
    ) == {
        "FIREWALL",
        "ROUTE",
        "VLAN",
    }


def test_parser_has_no_ground_truth_argument():
    parser = runner.build_parser()

    help_text = parser.format_help()

    assert "--ground-truth" not in help_text
    assert "--instance" in help_text
    assert "--plan" in help_text


def test_candidate_variant_default():
    rec = ConfigurationRecommendation(
        assessment_id="assessment-x",
        flow_id="flow-x",
        capture_id="capture-x",
        target="rq3-target",
        device_id="r1",
        category="ROUTE",
        intent="RESTORE_ROUTE",
        platform="frr",
        risk_level="medium",
        confidence=0.9,
        summary="test",
        rationale="test",
        current_state={},
        desired_state={},
        commands=["vtysh -c 'show ip route'"],
        rollback_commands=[
            "vtysh -c 'show ip route'"
        ],
        preconditions=[],
        postconditions=[],
        impact={},
        simulation_status="PASSED",
        simulated_verdict="ALLOW",
    )

    assert (
        runner.candidate_variant(rec)
        == "primary"
    )


def test_instrumented_executor_records_both_stages():
    state = {
        "fixed": False,
    }

    def fake_runner(argv, timeout):
        joined = " ".join(argv)

        if (
            "no ip route "
            "10.20.20.10/32"
            in joined
        ):
            state["fixed"] = False
            return subprocess.CompletedProcess(
                argv,
                0,
                "",
                "",
            )

        if (
            "ip route "
            "10.20.20.10/32"
            in joined
        ):
            state["fixed"] = True
            return subprocess.CompletedProcess(
                argv,
                0,
                "",
                "",
            )

        if "show ip route json" in joined:
            return subprocess.CompletedProcess(
                argv,
                0,
                '{"routes": {}}',
                "",
            )

        if (
            "curl -fsS"
            in joined
            and ":443/"
            in joined
        ):
            rc = (
                0
                if state["fixed"]
                else 7
            )

            return subprocess.CompletedProcess(
                argv,
                rc,
                "ok" if rc == 0 else "",
                "" if rc == 0 else "failed",
            )

        return subprocess.CompletedProcess(
            argv,
            0,
            "",
            "",
        )

    def auxiliary(stage):
        return {
            "stage": stage,

            "independent_control": {
                "observed_success": True,
            },

            "security_service_listening": {
                "observed_success": True,
            },

            "security_invariant": {
                "observed_success": False,
            },

            "same_path_control": None,
            "stage_duration_ms": 1.0,
        }

    rec = ConfigurationRecommendation(
        assessment_id="assessment-route",
        flow_id="flow-route",
        capture_id="capture-route",
        target="rq3-target",
        device_id="r1",
        category="ROUTE",
        intent="ADD_ROUTE",
        platform="frr",
        risk_level="medium",
        confidence=0.95,
        summary="Add host route",
        rationale="Test fixture",
        current_state={},
        desired_state={},
        commands=[
            (
                "vtysh "
                "-c 'configure terminal' "
                "-c 'ip route "
                "10.20.20.10/32 "
                "172.16.1.2'"
            )
        ],
        rollback_commands=[
            (
                "vtysh "
                "-c 'configure terminal' "
                "-c 'no ip route "
                "10.20.20.10/32 "
                "172.16.1.2'"
            )
        ],
        preconditions=[],
        postconditions=[],
        impact={
            "scope":
                "single host"
        },
        simulation_status="PASSED",
        simulated_verdict="ALLOW",
        status="APPROVED",
    )

    executor = (
        runner
        .InstrumentedVirtualLabExecutor(
            auxiliary_probe=auxiliary,
            runner=fake_runner,
        )
    )

    execution = executor.execute(
        rec,
        approved_by="rq3-operator",
        environment="virtual-lab",
        rollback_after_verify=True,
    )

    assert execution.status == "ROLLED_BACK"

    assert (
        execution.verification[
            "observed_success"
        ]
        is True
    )

    assert (
        execution.rollback_verification[
            "observed_success"
        ]
        is False
    )

    assert set(
        executor.stage_observations
    ) == {
        "post_change",
        "post_rollback",
    }

    assert (
        executor.stage_observations[
            "post_change"
        ]["auxiliary"][
            "independent_control"
        ]["observed_success"]
        is True
    )

    assert (
        executor.stage_observations[
            "post_change"
        ]["auxiliary"][
            "security_invariant"
        ]["observed_success"]
        is False
    )

    assert state["fixed"] is False
