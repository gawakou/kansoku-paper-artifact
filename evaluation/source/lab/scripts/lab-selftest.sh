#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "$0")" && pwd)/lib.sh"

"$KANSOKU_PYTHON" - "$ROOT_DIR" "$TOPOLOGY" <<'PY'
import json
from pathlib import Path
import sys
root = Path(sys.argv[1])
topology_path = Path(sys.argv[2])
data = json.loads(topology_path.read_text())
assert data["name"] == "kansoku-v100"
nodes = data["topology"]["nodes"]
assert set(nodes) == {"client-a", "sw1", "fw1", "r1", "r2", "sw2", "server-a"}
assert nodes["sw1"]["image"] == "kansoku/lab-node:0.10.0"
assert nodes["r1"]["image"].startswith("frrouting/frr:")
links = data["topology"]["links"]
assert len(links) == 6
endpoints = [tuple(link["endpoints"]) for link in links]
assert len(endpoints) == len(set(endpoints))
required = [
    "lab/images/kansoku-lab-node/Dockerfile",
    "lab/containerlab/configs/fw1/ruleset.nft",
    "lab/scripts/scenarios/normal.sh",
    "lab/scripts/scenarios/firewall-deny.sh",
    "lab/scripts/scenarios/route-missing.sh",
    "lab/scripts/scenarios/vlan-mismatch.sh",
    "lab/scripts/scenarios/packet-loss.sh",
    "lab/vm/bootstrap-ubuntu.sh",
    "kansoku/experiment.py",
    "scenarios/evaluation/catalog.json",
    "schemas/experiment-definition.schema.json",
    "schemas/experiment-trial.schema.json",
    "scripts/v091_experiment_smoke.sh",
    "scripts/v100_remediation_smoke.sh",
    "kansoku/evidence.py",
    "kansoku/remediation.py",
    "schemas/evidence-graph.schema.json",
    "schemas/remediation-execution.schema.json",
]
missing = [item for item in required if not (root / item).is_file()]
assert not missing, missing
print("verified v0.10.0 topology and lab file set")
PY

while IFS= read -r script; do
  bash -n "$script"
done < <(find "$LAB_DIR" -type f -name '*.sh' -print | sort)

echo "verified v0.10.0 shell syntax"
