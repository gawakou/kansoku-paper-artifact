from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from kansoku.diagnostic_eval import (
    ConfigStateView,
    FlowEvidenceView,
    ObservedFlowEvidence,
    TargetFlowSpec,
    view_checksums,
)
from kansoku.network_state import (
    PolicyRule,
    RouteEntry,
)


ROOT = Path(__file__).resolve().parents[1]

MODULE_PATH = (
    ROOT
    / "scripts"
    / "experiments"
    / "run_rq2_recommendation.py"
)

spec = importlib.util.spec_from_file_location(
    "run_rq2_recommendation",
    MODULE_PATH,
)

assert spec is not None
assert spec.loader is not None

runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def write_json(path: Path, payload) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    path.write_text(
        json.dumps(
            payload,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def build_firewall_fixture(tmp_path: Path):
    repo = tmp_path / "repo"
    source_root = (
        repo
        / "artifacts"
        / "phase2"
    )

    source = (
        source_root
        / "firewall-source-v01"
        / "rep-01"
    )

    query_id = "q-test-opaque"

    target = TargetFlowSpec(
        query_id=query_id,
        ip_version=4,
        protocol="TCP",
        src_ip="10.10.10.10",
        dst_ip="10.20.20.10",
        src_port=None,
        dst_port=443,
    )

    flow_view = FlowEvidenceView(
        query_id=query_id,
        flows=(
            ObservedFlowEvidence(
                evidence_id="flowev-test",
                ip_version=4,
                protocol="TCP",
                src_ip="10.10.10.10",
                dst_ip="10.20.20.10",
                src_port=40000,
                dst_port=443,
                packets=1,
                captured_bytes=54,
                wire_bytes=54,
                first_seen=(
                    "2026-09-16T00:00:00+00:00"
                ),
                last_seen=(
                    "2026-09-16T00:00:00+00:00"
                ),
                vlan_id=None,
                tcp_flags={
                    "syn": 1,
                    "ack": 0,
                },
            ),
        ),
    )

    route = RouteEntry(
        device_id="r1",
        prefix="10.20.20.0/24",
        protocol="static",
        next_hop="172.16.1.2",
        interface="eth2",
        route_id="route-test",
    )

    deny = PolicyRule(
        device_id="fw1",
        policy_type="firewall",
        table="filter",
        chain="forward",
        action="DENY",
        priority=1,
        protocol="TCP",
        src_network="10.10.10.0/24",
        dst_network="10.20.20.10/32",
        dst_port="443",
        rule_id="rule-test-deny",
    )

    config = ConfigStateView(
        query_id=query_id,
        ingress_device_id="fw1",
        route_device_id="r1",
        policy_device_id="fw1",
        vlan_device_id="sw1",
        vrf="default",
        in_interface="",
        routes=(route,),
        policies=(deny,),
        vlans=(),
        interfaces=(),
    )

    checksums = view_checksums(
        target,
        flow_view,
        config,
    )

    write_json(
        source / "views" / "target.json",
        target.to_dict(),
    )

    write_json(
        source / "views" / "flow.json",
        flow_view.to_dict(),
    )

    write_json(
        source / "views" / "config.json",
        config.to_dict(),
    )

    write_json(
        source / "views" / "checksums.json",
        checksums,
    )

    write_json(
        source / "diagnostics.json",
        {
            "view_checksums": checksums,
            "results": {
                "PROPOSED": {
                    "verdict": "DENY",
                    "fault_domain": "FIREWALL",
                },
            },
        },
    )

    write_json(
        source / "trial.json",
        {
            "runtime_query_id": query_id,
            "execution_commit":
                "phase2-runner-test",
            "preregistration_commit":
                "phase2-prereg-test",
            "ground_truth_consumed_by_runner":
                False,
        },
    )

    plan = {
        "schema_version": 1,
        "instance_count": 1,
        "instances": {
            "rq2-test-v01": {
                "family": "FIREWALL",
                "source_instance":
                    "firewall-source-v01",
                "source_repetition": 1,
                "source_root":
                    "artifacts/phase2",
                "recommendation_inputs": {
                    "policy_device_id": "fw1",
                },
            },
        },
    }

    plan_path = repo / "plan.json"

    write_json(
        plan_path,
        plan,
    )

    return repo, plan_path, source


def test_parser_has_no_ground_truth_argument():
    parser = runner.build_parser()

    help_text = parser.format_help()

    assert "--ground-truth" not in help_text
    assert "--instance" in help_text
    assert "--plan" in help_text


def test_candidate_variant_normalization():
    class Dummy:
        metadata = {}

    assert (
        runner.candidate_variant(Dummy())
        == "primary"
    )

    class Alt:
        metadata = {
            "candidate_variant":
                "observation-only"
        }

    assert (
        runner.candidate_variant(Alt())
        == "observation-only"
    )


def test_firewall_runner_end_to_end(
    tmp_path: Path,
):
    repo, plan_path, _ = (
        build_firewall_fixture(tmp_path)
    )

    out = repo / "output"

    result = runner.execute_instance(
        plan_path=plan_path,
        instance_id="rq2-test-v01",
        output_dir=out,
        repo_root=repo,
        runner_commit="rq2-runner-test",
        prereg_commit="rq2-prereg-test",
    )

    assert result["top1"]["rank"] == 1
    assert (
        result["top1"]["category"]
        == "FIREWALL_POLICY"
    )
    assert (
        result["top1"]["variant"]
        == "primary"
    )
    assert (
        result["top1"]["simulation_status"]
        == "PASSED"
    )
    assert (
        result["top1"]["simulated_verdict"]
        == "ALLOW"
    )

    trial = json.loads(
        (out / "trial.json").read_text()
    )

    assert (
        trial[
            "ground_truth_consumed_by_runner"
        ]
        is False
    )

    assert (
        trial["runner_commit"]
        == "rq2-runner-test"
    )

    assert (
        trial["rq2_preregistration_commit"]
        == "rq2-prereg-test"
    )

    assert (
        out / "evidence-graph.json"
    ).exists()

    assert (
        out / "candidates.json"
    ).exists()

    assert (
        out / "ranked-candidates.json"
    ).exists()

    assert (
        out / "result.json"
    ).exists()


def test_runner_rejects_changed_frozen_view(
    tmp_path: Path,
):
    repo, plan_path, source = (
        build_firewall_fixture(tmp_path)
    )

    flow_path = (
        source / "views" / "flow.json"
    )

    data = json.loads(
        flow_path.read_text()
    )

    data["flows"][0]["wire_bytes"] += 1

    write_json(
        flow_path,
        data,
    )

    with pytest.raises(
        ValueError,
        match="checksum mismatch",
    ):
        runner.execute_instance(
            plan_path=plan_path,
            instance_id="rq2-test-v01",
            output_dir=repo / "output",
            repo_root=repo,
            runner_commit="runner-test",
            prereg_commit="prereg-test",
        )


def test_runner_rejects_source_ground_truth_use(
    tmp_path: Path,
):
    repo, plan_path, source = (
        build_firewall_fixture(tmp_path)
    )

    trial_path = source / "trial.json"

    trial = json.loads(
        trial_path.read_text()
    )

    trial[
        "ground_truth_consumed_by_runner"
    ] = True

    write_json(
        trial_path,
        trial,
    )

    with pytest.raises(
        ValueError,
        match="consumed ground truth",
    ):
        runner.execute_instance(
            plan_path=plan_path,
            instance_id="rq2-test-v01",
            output_dir=repo / "output",
            repo_root=repo,
            runner_commit="runner-test",
            prereg_commit="prereg-test",
        )
