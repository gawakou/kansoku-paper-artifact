from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]

MODULE_PATH = (
    ROOT
    / "scripts"
    / "experiments"
    / "evaluate_rq2_recommendation.py"
)

spec = importlib.util.spec_from_file_location(
    "evaluate_rq2_recommendation",
    MODULE_PATH,
)

assert spec is not None
assert spec.loader is not None

evaluator = importlib.util.module_from_spec(
    spec
)
spec.loader.exec_module(evaluator)


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


def sha256(path: Path) -> str:
    return hashlib.sha256(
        path.read_bytes()
    ).hexdigest()


def make_fixture(
    tmp_path: Path,
    *,
    wrong_top1_instance: str | None = None,
    consumed_gt_instance: str | None = None,
):
    raw = tmp_path / "raw"
    snapshot = tmp_path / "snapshot"
    gt_path = tmp_path / "gt.json"

    gt_instances = {}

    families = [
        ("FIREWALL", "FIREWALL_POLICY", "fw1",
         "primary"),
        ("ROUTE", "ROUTE", "r1",
         "host-route"),
        ("VLAN", "VLAN", "sw1",
         "primary"),
    ]

    for family, category, device, variant in families:
        for i in range(1, 6):
            iid = (
                f"rq2-{family.lower()}-v{i:02d}"
            )

            required_types = [
                "FLOW",
                "ASSESSMENT",
            ]

            required_relations = [
                "ASSESSES",
            ]

            required_ids = []

            if family == "FIREWALL":
                required_types.append(
                    "POLICY_RULE"
                )
                required_relations.append(
                    "MATCHED_BY"
                )

            elif family == "ROUTE":
                required_types.append(
                    "EVIDENCE_GAP"
                )
                required_relations.append(
                    "MISSING"
                )
                required_ids.append(
                    "gap:route"
                )

            else:
                required_types.append(
                    "EVIDENCE_GAP"
                )
                required_relations.append(
                    "MISSING"
                )
                required_ids.append(
                    "gap:vlan:10"
                )

            forbidden = [
                "observation-only"
            ]

            if family == "FIREWALL":
                forbidden.append(
                    "host-pair-protocol"
                )

            if family == "VLAN":
                forbidden.extend(
                    [
                        "access-only",
                        "trunk-only",
                    ]
                )

            gt_instances[iid] = {
                "family": family,
                "expected_category":
                    category,
                "expected_device":
                    device,
                "expected_top1_variant":
                    variant,
                "expected_simulation_status":
                    "PASSED",
                "expected_simulated_verdict":
                    "ALLOW",
                "required_node_types":
                    required_types,
                "required_relations":
                    required_relations,
                "required_node_ids":
                    required_ids,
                "forbidden_top1_variants":
                    forbidden,
            }

            actual_variant = variant

            if iid == wrong_top1_instance:
                actual_variant = (
                    "observation-only"
                )

            trial = {
                "rq2_instance_id": iid,
                "ground_truth_consumed_by_runner":
                    iid == consumed_gt_instance,
            }

            result = {
                "source_query_id":
                    f"q-{i:02d}-{family.lower()}",
                "candidate_count": 3,
                "evidence_graph_summary": {
                    "evidence_coverage": 1.0,
                },
                "top1": {
                    "rank": 1,
                    "score": 0.9,
                    "category": category,
                    "device_id": device,
                    "variant":
                        actual_variant,
                    "simulation_status":
                        "PASSED",
                    "simulated_verdict":
                        "ALLOW",
                },
            }

            graph_nodes = [
                {
                    "node_id": "flow:x",
                    "node_type": "FLOW",
                },
                {
                    "node_id": "assessment:x",
                    "node_type": "ASSESSMENT",
                },
            ]

            graph_edges = [
                {
                    "relation": "ASSESSES",
                },
            ]

            if family == "FIREWALL":
                graph_nodes.append({
                    "node_id": "policy:x",
                    "node_type":
                        "POLICY_RULE",
                })

                graph_edges.append({
                    "relation":
                        "MATCHED_BY",
                })

            elif family == "ROUTE":
                graph_nodes.append({
                    "node_id": "gap:route",
                    "node_type":
                        "EVIDENCE_GAP",
                })

                graph_edges.append({
                    "relation": "MISSING",
                })

            else:
                graph_nodes.append({
                    "node_id":
                        "gap:vlan:10",
                    "node_type":
                        "EVIDENCE_GAP",
                })

                graph_edges.append({
                    "relation": "MISSING",
                })

            recommendation = {
                "category": category,
                "device_id": device,
            }

            ranked = {
                "ranked": [
                    {
                        "rank": 1,
                        "score": 0.9,
                        "variant":
                            actual_variant,
                        "recommendation":
                            recommendation,
                    },
                ],
            }

            candidates = {
                "candidates": [
                    {
                        "variant":
                            actual_variant,
                        "recommendation":
                            recommendation,
                    },
                ],
            }

            d = raw / iid

            write_json(
                d / "trial.json",
                trial,
            )

            write_json(
                d / "result.json",
                result,
            )

            write_json(
                d / "evidence-graph.json",
                {
                    "nodes": graph_nodes,
                    "edges": graph_edges,
                },
            )

            write_json(
                d / "ranked-candidates.json",
                ranked,
            )

            write_json(
                d / "candidates.json",
                candidates,
            )

    write_json(
        gt_path,
        {
            "schema_version": 1,
            "instance_count": 15,
            "instances": gt_instances,
        },
    )

    snapshot.mkdir(
        parents=True,
        exist_ok=True,
    )

    raw_files = sorted(
        p
        for p in raw.rglob("*")
        if p.is_file()
    )

    manifest = snapshot / "SHA256SUMS.txt"

    manifest.write_text(
        "".join(
            f"{sha256(p)}  {p}\n"
            for p in raw_files
        ),
        encoding="utf-8",
    )

    manifest_hash_file = (
        snapshot / "SHA256SUMS.sha256"
    )

    manifest_hash_file.write_text(
        f"{sha256(manifest)}  {manifest}\n",
        encoding="utf-8",
    )

    write_json(
        snapshot / "provenance.json",
        {
            "ground_truth_consumed_by_runner":
                False,
            "ground_truth_evaluated_before_snapshot":
                False,
        },
    )

    (
        snapshot
        / "INPUT-SHA256SUMS.txt"
    ).write_text(
        "synthetic fixture\n",
        encoding="utf-8",
    )

    snap_manifest = (
        snapshot
        / "SNAPSHOT-SHA256SUMS.txt"
    )

    meta_files = [
        manifest,
        manifest_hash_file,
        snapshot / "INPUT-SHA256SUMS.txt",
        snapshot / "provenance.json",
    ]

    snap_manifest.write_text(
        "".join(
            f"{sha256(p)}  {p}\n"
            for p in meta_files
        ),
        encoding="utf-8",
    )

    return (
        raw,
        gt_path,
        snapshot,
        sha256(manifest),
    )


def test_valid_15_instance_evaluation(
    tmp_path: Path,
):
    raw, gt, snapshot, manifest_hash = (
        make_fixture(tmp_path)
    )

    out = tmp_path / "out"

    result = evaluator.evaluate(
        raw_root=raw,
        gt_path=gt,
        snapshot_dir=snapshot,
        output_dir=out,
        expected_raw_manifest_sha256=(
            manifest_hash
        ),
    )

    metrics = result["summary"]

    assert (
        metrics[
            "recommendation_category_accuracy"
        ]["rate"]
        == 1.0
    )

    assert (
        metrics["top1_accuracy"]["rate"]
        == 1.0
    )

    assert (
        metrics["what_if_pass_rate"]["rate"]
        == 1.0
    )

    assert (
        metrics[
            "evidence_traceability_rate"
        ]["rate"]
        == 1.0
    )

    assert (
        metrics[
            "unsafe_or_broader_top1_rate"
        ]["rate"]
        == 0.0
    )


def test_wrong_top1_is_counted(
    tmp_path: Path,
):
    raw, gt, snapshot, manifest_hash = (
        make_fixture(
            tmp_path,
            wrong_top1_instance=(
                "rq2-firewall-v01"
            ),
        )
    )

    result = evaluator.evaluate(
        raw_root=raw,
        gt_path=gt,
        snapshot_dir=snapshot,
        output_dir=tmp_path / "out",
        expected_raw_manifest_sha256=(
            manifest_hash
        ),
    )

    assert (
        result["summary"][
            "top1_accuracy"
        ]["count"]
        == 14
    )

    assert (
        result["summary"][
            "unsafe_or_broader_top1_rate"
        ]["count"]
        == 1
    )


def test_rejects_ground_truth_consumption(
    tmp_path: Path,
):
    raw, gt, snapshot, manifest_hash = (
        make_fixture(
            tmp_path,
            consumed_gt_instance=(
                "rq2-route-v03"
            ),
        )
    )

    with pytest.raises(
        ValueError,
        match="consumed ground truth",
    ):
        evaluator.evaluate(
            raw_root=raw,
            gt_path=gt,
            snapshot_dir=snapshot,
            output_dir=tmp_path / "out",
            expected_raw_manifest_sha256=(
                manifest_hash
            ),
        )


def test_rejects_modified_raw_file(
    tmp_path: Path,
):
    raw, gt, snapshot, manifest_hash = (
        make_fixture(tmp_path)
    )

    p = (
        raw
        / "rq2-route-v01"
        / "result.json"
    )

    data = json.loads(
        p.read_text()
    )

    data["top1"]["score"] = 0.1

    write_json(
        p,
        data,
    )

    with pytest.raises(
        ValueError,
        match="snapshot checksum mismatch",
    ):
        evaluator.evaluate(
            raw_root=raw,
            gt_path=gt,
            snapshot_dir=snapshot,
            output_dir=tmp_path / "out",
            expected_raw_manifest_sha256=(
                manifest_hash
            ),
        )


def test_rejects_wrong_manifest_hash(
    tmp_path: Path,
):
    raw, gt, snapshot, _ = (
        make_fixture(tmp_path)
    )

    with pytest.raises(
        ValueError,
        match=(
            "manifest hash does not match"
        ),
    ):
        evaluator.evaluate(
            raw_root=raw,
            gt_path=gt,
            snapshot_dir=snapshot,
            output_dir=tmp_path / "out",
            expected_raw_manifest_sha256=(
                "0" * 64
            ),
        )


def test_rejects_missing_snapshot_file(
    tmp_path: Path,
):
    raw, gt, snapshot, manifest_hash = (
        make_fixture(tmp_path)
    )

    target = (
        raw
        / "rq2-vlan-v05"
        / "candidates.json"
    )

    target.unlink()

    with pytest.raises(
        FileNotFoundError,
        match="snapshot file missing",
    ):
        evaluator.evaluate(
            raw_root=raw,
            gt_path=gt,
            snapshot_dir=snapshot,
            output_dir=tmp_path / "out",
            expected_raw_manifest_sha256=(
                manifest_hash
            ),
        )


def test_rejects_raw_ground_truth_id_mismatch(
    tmp_path: Path,
):
    raw, gt, snapshot, manifest_hash = (
        make_fixture(tmp_path)
    )

    gt_doc = json.loads(
        gt.read_text(encoding="utf-8")
    )

    original = gt_doc["instances"].pop(
        "rq2-vlan-v05"
    )

    # Preserve the required count and family
    # composition while changing only the ID set.
    gt_doc["instances"][
        "rq2-vlan-v99"
    ] = original

    write_json(
        gt,
        gt_doc,
    )

    with pytest.raises(
        ValueError,
        match=(
            "raw/ground-truth instance IDs differ"
        ),
    ):
        evaluator.evaluate(
            raw_root=raw,
            gt_path=gt,
            snapshot_dir=snapshot,
            output_dir=tmp_path / "out",
            expected_raw_manifest_sha256=(
                manifest_hash
            ),
        )
