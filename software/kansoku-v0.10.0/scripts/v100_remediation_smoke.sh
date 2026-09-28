#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

if [[ -n "${KANSOKU_PYTHON:-}" ]]; then
  PYTHON_BIN="$KANSOKU_PYTHON"
elif [[ -x "$ROOT_DIR/.lab-venv/bin/python" ]]; then
  PYTHON_BIN="$ROOT_DIR/.lab-venv/bin/python"
elif [[ -x "$ROOT_DIR/.venv/bin/python" ]]; then
  PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="$(command -v python3)"
else
  PYTHON_BIN="$(command -v python)"
fi

"$PYTHON_BIN" - <<'PY'
import subprocess
from tempfile import TemporaryDirectory
from pathlib import Path

from kansoku.capture import FlowRecord
from kansoku.evidence import build_evidence_graph
from kansoku.hub import Hub
from kansoku.network_state import FlowAssessment, PolicyRule
from kansoku.recommendation import RecommendationEngine
from kansoku.remediation import RecommendationRanker, VirtualLabExecutor

flow = FlowRecord(
    capture_id="capture-smoke", target="virtual-lab-path", source="smoke",
    ip_version=4, protocol="TCP", src_ip="10.10.10.10", dst_ip="10.20.20.10",
    src_port=40000, dst_port=443, packets=1, captured_bytes=54, wire_bytes=54,
    first_seen="2026-07-18T00:00:00+00:00", last_seen="2026-07-18T00:00:00+00:00",
    tcp_flags={"syn": 1}, flow_id="flow-smoke",
)
rule = PolicyRule(
    device_id="fw1", policy_type="firewall", table="filter", chain="forward",
    action="ALLOW", priority=10, protocol="TCP", src_network="10.10.10.0/24",
    dst_network="10.20.20.10/32", dst_port="443", rule_id="allow-smoke",
)
assessment = FlowAssessment(
    flow_id=flow.flow_id, capture_id=flow.capture_id, target=flow.target,
    ingress_device_id="fw1", route_status="NO_ROUTE", policy_status="ALLOW",
    verdict="UNROUTABLE", matched_rule_id=rule.rule_id,
    evidence={"route_device": "r1", "policy_device": "fw1", "vlan_device": "sw1"},
)
graph = build_evidence_graph(assessment, flow, policies=[rule])
candidates = RecommendationEngine().generate_candidates(
    assessment, flow, policies=[rule], route_device_id="r1",
    destination_prefix="10.20.20.0/24", next_hop="172.16.1.2", out_interface="eth2",
)
ranked = RecommendationRanker().rank(candidates, evidence_graph=graph)
assert ranked[0].recommendation.metadata.get("candidate_variant") == "host-route"
rec = ranked[0].recommendation
rec.status = "APPROVED"
state = {"fixed": False}
def runner(argv, timeout):
    joined = " ".join(argv)
    if "curl -fsS" in joined:
        return subprocess.CompletedProcess(argv, 0 if state["fixed"] else 7, "", "")
    if "show ip route json" in joined:
        return subprocess.CompletedProcess(argv, 0, '{"routes": {}}', "")
    if " no ip route " in f" {joined} ":
        state["fixed"] = False
    elif " ip route " in f" {joined} ":
        state["fixed"] = True
    return subprocess.CompletedProcess(argv, 0, "", "")
execution = VirtualLabExecutor(runner=runner).execute(
    rec, approved_by="pre-release", environment="virtual-lab",
)
assert execution.status == "ROLLED_BACK", execution.to_dict()
with TemporaryDirectory() as tmp:
    hub = Hub(Path(tmp) / "hub.db")
    hub.add_evidence_graphs([graph])
    hub.add_configuration_recommendations([rec])
    hub.add_remediation_executions([execution])
    assert hub.get_evidence_graph(graph.graph_id)
    assert hub.get_remediation_execution(execution.execution_id)
print("verified v0.10 evidence graph, candidate ranking, approval boundary, and lab rollback")
PY
