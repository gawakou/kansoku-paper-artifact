#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

from kansoku.diagnostic_eval import (
    ConfigStateView,
    EvidenceLeakageChecker,
    FlowEvidenceView,
    ObservedFlowEvidence,
    TargetFlowSpec,
    view_checksums,
)
from kansoku.evidence import build_evidence_graph
from kansoku.network_state import (
    NetworkInterface,
    PolicyRule,
    RouteEntry,
    VlanRecord,
    correlate_flow,
)
from kansoku.recommendation import RecommendationEngine
from kansoku.remediation import RecommendationRanker


DEFAULT_PLAN = Path(
    "scenarios/paper/rq2_recommendation_instances.json"
)

PREREG_TAG = "paper-rq2-recommendation-prereg-v1"


def load_json(path: Path) -> Any:
    return json.loads(
        path.read_text(encoding="utf-8")
    )


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    path.write_text(
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()

    with path.open("rb") as f:
        for chunk in iter(
            lambda: f.read(1024 * 1024),
            b"",
        ):
            h.update(chunk)

    return h.hexdigest()


def git(*args: str) -> str:
    return subprocess.check_output(
        ["git", *args],
        text=True,
    ).strip()


def load_flow_view(path: Path) -> FlowEvidenceView:
    data = load_json(path)

    return FlowEvidenceView(
        query_id=data["query_id"],
        flows=tuple(
            ObservedFlowEvidence(**row)
            for row in data["flows"]
        ),
    )


def load_config_view(path: Path) -> ConfigStateView:
    data = load_json(path)

    return ConfigStateView(
        query_id=data["query_id"],
        ingress_device_id=data[
            "ingress_device_id"
        ],
        route_device_id=data[
            "route_device_id"
        ],
        policy_device_id=data[
            "policy_device_id"
        ],
        vlan_device_id=data[
            "vlan_device_id"
        ],
        vrf=data["vrf"],
        in_interface=data["in_interface"],
        routes=tuple(
            RouteEntry.from_dict(row)
            for row in data["routes"]
        ),
        policies=tuple(
            PolicyRule.from_dict(row)
            for row in data["policies"]
        ),
        vlans=tuple(
            VlanRecord.from_dict(row)
            for row in data["vlans"]
        ),
        interfaces=tuple(
            NetworkInterface.from_dict(row)
            for row in data["interfaces"]
        ),
    )


def matches_target(
    target: TargetFlowSpec,
    ev: ObservedFlowEvidence,
) -> bool:
    if ev.ip_version != target.ip_version:
        return False

    if (
        ev.protocol.upper()
        != target.protocol.upper()
    ):
        return False

    if (
        ev.src_ip != target.src_ip
        or ev.dst_ip != target.dst_ip
    ):
        return False

    if (
        target.src_port is not None
        and ev.src_port != target.src_port
    ):
        return False

    if (
        target.dst_port is not None
        and ev.dst_port != target.dst_port
    ):
        return False

    return True


def assessment_fault_domain(
    assessment,
) -> str:
    if assessment.verdict == "DENY":
        return "FIREWALL"

    if assessment.verdict == "UNROUTABLE":
        return "ROUTE"

    if assessment.vlan_status == "UNKNOWN_VLAN":
        return "VLAN"

    if assessment.verdict == "ALLOW":
        return "NONE"

    return "UNKNOWN"


def candidate_variant(rec) -> str:
    return str(
        rec.metadata.get("candidate_variant")
        or "primary"
    )


def reconstruct_assessment(
    *,
    target: TargetFlowSpec,
    flow_view: FlowEvidenceView,
    config: ConfigStateView,
):
    matched = sorted(
        (
            ev
            for ev in flow_view.flows
            if matches_target(target, ev)
        ),
        key=lambda item: item.evidence_id,
    )

    if not matched:
        raise ValueError(
            "no target-flow evidence found"
        )

    reconstructed = []

    for ev in matched:
        flow = ev.to_flow(
            query_id=target.query_id
        )

        assessment = correlate_flow(
            flow,
            ingress_device_id=(
                config.ingress_device_id
            ),
            routes=config.routes,
            rules=config.policies,
            vlans=config.vlans,
            vrf=config.vrf,
            in_interface=config.in_interface,
        )

        assessment.evidence = {
            **assessment.evidence,
            "route_device":
                config.route_device_id,
            "policy_device":
                config.policy_device_id,
            "vlan_device":
                config.vlan_device_id,
            "vrf":
                config.vrf,
            "in_interface":
                config.in_interface,
        }

        reconstructed.append(
            (flow, assessment)
        )

    semantic_keys = {
        (
            assessment.verdict,
            assessment.route_status,
            assessment.policy_status,
            assessment.vlan_status,
        )
        for _, assessment in reconstructed
    }

    if len(semantic_keys) != 1:
        raise ValueError(
            "matching target evidence produced "
            "inconsistent semantic assessments: "
            f"{sorted(semantic_keys)}"
        )

    # Deterministic representative:
    # matched list is ordered by evidence_id.
    flow, assessment = reconstructed[0]

    return (
        flow,
        assessment,
        len(matched),
    )


def execute_instance(
    *,
    plan_path: Path,
    instance_id: str,
    output_dir: Path,
    repo_root: Path,
    runner_commit: str,
    prereg_commit: str,
) -> dict[str, Any]:
    plan = load_json(plan_path)

    if plan.get("schema_version") != 1:
        raise ValueError(
            "unsupported RQ2 plan schema_version"
        )

    instances = plan.get("instances")

    if (
        not isinstance(instances, dict)
        or instance_id not in instances
    ):
        raise ValueError(
            f"unknown RQ2 instance: {instance_id}"
        )

    if output_dir.exists():
        raise FileExistsError(
            f"output directory already exists: "
            f"{output_dir}"
        )

    row = instances[instance_id]

    if int(row["source_repetition"]) != 1:
        raise ValueError(
            "RQ2 source repetition must be rep-01"
        )

    source = (
        repo_root
        / row["source_root"]
        / row["source_instance"]
        / "rep-01"
    )

    required = {
        "target":
            source / "views" / "target.json",
        "flow":
            source / "views" / "flow.json",
        "config":
            source / "views" / "config.json",
        "checksums":
            source / "views" / "checksums.json",
        "diagnostics":
            source / "diagnostics.json",
        "trial":
            source / "trial.json",
    }

    for name, path in required.items():
        if not path.exists():
            raise FileNotFoundError(
                f"missing source {name}: {path}"
            )

    target = TargetFlowSpec.from_dict(
        load_json(required["target"])
    )

    flow_view = load_flow_view(
        required["flow"]
    )

    config = load_config_view(
        required["config"]
    )

    EvidenceLeakageChecker().validate_views(
        flow_view,
        config,
    )

    frozen_checksums = load_json(
        required["checksums"]
    )

    recalculated = view_checksums(
        target,
        flow_view,
        config,
    )

    if recalculated != frozen_checksums:
        raise ValueError(
            "frozen Phase-2 view checksum mismatch"
        )

    diagnostics = load_json(
        required["diagnostics"]
    )

    if (
        diagnostics.get("view_checksums")
        != frozen_checksums
    ):
        raise ValueError(
            "diagnostics/view checksum mismatch"
        )

    proposed = diagnostics.get(
        "results", {}
    ).get("PROPOSED")

    if not isinstance(proposed, dict):
        raise ValueError(
            "frozen PROPOSED diagnosis is missing"
        )

    source_trial = load_json(
        required["trial"]
    )

    if (
        source_trial.get(
            "ground_truth_consumed_by_runner"
        )
        is not False
    ):
        raise ValueError(
            "source Phase-2 trial consumed "
            "ground truth"
        )

    if (
        source_trial.get("runtime_query_id")
        and source_trial["runtime_query_id"]
        != target.query_id
    ):
        raise ValueError(
            "source runtime query ID mismatch"
        )

    (
        flow,
        assessment,
        matched_flow_count,
    ) = reconstruct_assessment(
        target=target,
        flow_view=flow_view,
        config=config,
    )

    reconstructed_domain = (
        assessment_fault_domain(
            assessment
        )
    )

    if (
        assessment.verdict
        != proposed.get("verdict")
    ):
        raise ValueError(
            "reconstructed verdict differs from "
            "frozen PROPOSED diagnosis"
        )

    if (
        reconstructed_domain
        != proposed.get("fault_domain")
    ):
        raise ValueError(
            "reconstructed fault domain differs "
            "from frozen PROPOSED diagnosis"
        )

    graph = build_evidence_graph(
        assessment,
        flow,
        routes=config.routes,
        policies=config.policies,
        vlans=config.vlans,
        interfaces=config.interfaces,
    )

    candidates = (
        RecommendationEngine()
        .generate_candidates(
            assessment,
            flow,
            routes=config.routes,
            policies=config.policies,
            vlans=config.vlans,
            interfaces=config.interfaces,
            **row["recommendation_inputs"],
        )
    )

    if not candidates:
        raise ValueError(
            "no recommendation candidates generated"
        )

    ranked = RecommendationRanker().rank(
        candidates,
        evidence_graph=graph,
    )

    if not ranked:
        raise ValueError(
            "ranking produced no candidates"
        )

    candidate_payload = []

    for item in candidates:
        candidate_payload.append({
            "variant":
                candidate_variant(item),
            "recommendation":
                item.to_dict(),
        })

    ranked_payload = []

    for item in ranked:
        ranked_payload.append({
            "rank": item.rank,
            "score": item.score,
            "components": item.components,
            "explanation": item.explanation,
            "variant": candidate_variant(
                item.recommendation
            ),
            "recommendation":
                item.recommendation.to_dict(),
        })

    graph_payload = graph.to_dict()

    # Scenario identity is allowed only in the
    # outer trial provenance, never inside
    # generated diagnostic/recommendation content.
    generated_blob = json.dumps(
        {
            "graph": graph_payload,
            "candidates": candidate_payload,
            "ranked": ranked_payload,
        },
        sort_keys=True,
        ensure_ascii=False,
    ).lower()

    forbidden_identity_tokens = {
        instance_id.lower(),
        str(row["source_instance"]).lower(),
    }

    for token in forbidden_identity_tokens:
        if token in generated_blob:
            raise ValueError(
                "scenario identity leaked into "
                f"generated RQ2 content: {token}"
            )

    top = ranked[0]
    top_rec = top.recommendation

    node_types = sorted({
        item.node_type
        for item in graph.nodes
    })

    node_ids = sorted(
        item.node_id
        for item in graph.nodes
    )

    relations = sorted({
        item.relation
        for item in graph.edges
    })

    result = {
        "schema_version": 1,
        "source_query_id": target.query_id,
        "matched_flow_count":
            matched_flow_count,
        "reconstructed_diagnosis": {
            "verdict":
                assessment.verdict,
            "fault_domain":
                reconstructed_domain,
            "route_status":
                assessment.route_status,
            "policy_status":
                assessment.policy_status,
            "vlan_status":
                assessment.vlan_status,
        },
        "frozen_proposed_diagnosis": {
            "verdict":
                proposed["verdict"],
            "fault_domain":
                proposed["fault_domain"],
        },
        "evidence_graph_summary": {
            "evidence_coverage":
                graph.evidence_coverage,
            "node_types":
                node_types,
            "node_ids":
                node_ids,
            "relations":
                relations,
        },
        "candidate_count":
            len(ranked),
        "top1": {
            "rank":
                top.rank,
            "score":
                top.score,
            "category":
                top_rec.category,
            "device_id":
                top_rec.device_id,
            "variant":
                candidate_variant(top_rec),
            "risk_level":
                top_rec.risk_level,
            "simulation_status":
                top_rec.simulation_status,
            "simulated_verdict":
                top_rec.simulated_verdict,
            "ranking_components":
                top.components,
        },
    }

    source_file_sha256 = {
        name: sha256_file(path)
        for name, path in required.items()
    }

    trial = {
        "schema_version": 1,
        "phase":
            "RQ2 recommendation evaluation",
        "rq2_instance_id":
            instance_id,
        "family":
            row["family"],
        "source_instance":
            row["source_instance"],
        "source_repetition":
            row["source_repetition"],
        "source_query_id":
            target.query_id,
        "source_phase2_execution_commit":
            source_trial.get(
                "execution_commit", ""
            ),
        "source_phase2_preregistration_commit":
            source_trial.get(
                "preregistration_commit", ""
            ),
        "rq2_preregistration_commit":
            prereg_commit,
        "runner_commit":
            runner_commit,
        "ground_truth_consumed_by_runner":
            False,
        "source_view_checksums":
            frozen_checksums,
        "source_file_sha256":
            source_file_sha256,
        "created_at_utc":
            datetime.datetime.now(
                datetime.timezone.utc
            ).isoformat(),
    }

    output_dir.mkdir(
        parents=True,
        exist_ok=False,
    )

    write_json(
        output_dir / "trial.json",
        trial,
    )

    write_json(
        output_dir / "evidence-graph.json",
        graph_payload,
    )

    write_json(
        output_dir / "candidates.json",
        {
            "schema_version": 1,
            "candidates": candidate_payload,
        },
    )

    write_json(
        output_dir / "ranked-candidates.json",
        {
            "schema_version": 1,
            "ranked": ranked_payload,
        },
    )

    write_json(
        output_dir / "result.json",
        result,
    )

    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run one frozen-evidence RQ2 "
            "recommendation evaluation instance."
        )
    )

    parser.add_argument(
        "--instance",
        required=True,
    )

    parser.add_argument(
        "--plan",
        default=str(DEFAULT_PLAN),
    )

    parser.add_argument(
        "--output-dir",
        required=True,
    )

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    repo_root = Path.cwd()

    prereg_commit = git(
        "rev-list",
        "-n",
        "1",
        PREREG_TAG,
    )

    runner_commit = git(
        "rev-parse",
        "HEAD",
    )

    result = execute_instance(
        plan_path=Path(args.plan),
        instance_id=args.instance,
        output_dir=Path(args.output_dir),
        repo_root=repo_root,
        runner_commit=runner_commit,
        prereg_commit=prereg_commit,
    )

    print(
        json.dumps(
            result,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
    )

    print(
        "PASS: RQ2 recommendation instance completed"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
