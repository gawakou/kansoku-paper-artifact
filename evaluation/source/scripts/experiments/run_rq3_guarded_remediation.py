#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, Sequence

from kansoku.evidence import build_evidence_graph
from kansoku.hub import Hub
from kansoku.recommendation import (
    RecommendationEngine,
    approval_issues,
)
from kansoku.remediation import (
    RecommendationRanker,
    VirtualLabExecutor,
)


PREREG_TAG = "paper-rq3-guarded-remediation-prereg-v1"

DEFAULT_PLAN = Path(
    "scenarios/paper/"
    "rq3_guarded_remediation_plan.json"
)

EXPECTED_PLAN_SHA256 = (
    "294e8dbf258dbbafb6ab323169aedf563a69b084"
    "ad46bb54dcd5c249a3062f00"
)


def load_json(path: Path) -> Any:
    return json.loads(
        path.read_text(encoding="utf-8")
    )


def write_json(
    path: Path,
    value: Any,
) -> None:
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


def git(
    repo_root: Path,
    *args: str,
) -> str:
    return subprocess.check_output(
        ["git", *args],
        cwd=repo_root,
        text=True,
    ).strip()


def load_frozen_plan(
    path: Path,
) -> dict[str, Any]:
    actual = sha256_file(path)

    if actual != EXPECTED_PLAN_SHA256:
        raise ValueError(
            "RQ3 plan SHA256 mismatch: "
            f"expected={EXPECTED_PLAN_SHA256} "
            f"actual={actual}"
        )

    doc = load_json(path)

    if doc.get("schema_version") != 1:
        raise ValueError(
            "unsupported RQ3 plan schema"
        )

    if doc.get("execution_count") != 15:
        raise ValueError(
            "RQ3 plan must contain 15 executions"
        )

    constraints = doc.get(
        "runner_constraints",
        {},
    )

    if (
        constraints.get(
            "ground_truth_file_must_not_be_read"
        )
        is not True
    ):
        raise ValueError(
            "RQ3 plan does not forbid "
            "ground-truth consumption"
        )

    return doc


def candidate_variant(rec) -> str:
    return str(
        rec.metadata.get("candidate_variant")
        or "primary"
    )


def command_result(
    *,
    argv: Sequence[str],
    cwd: Path,
    timeout: float = 60.0,
    check: bool = True,
    log: list[dict[str, Any]] | None = None,
) -> subprocess.CompletedProcess[str]:
    started = time.monotonic()

    completed = subprocess.run(
        list(argv),
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )

    duration_ms = (
        time.monotonic() - started
    ) * 1000.0

    if log is not None:
        log.append({
            "argv": list(argv),
            "returncode":
                int(completed.returncode),
            "stdout":
                (completed.stdout or "")[:20000],
            "stderr":
                (completed.stderr or "")[:10000],
            "duration_ms":
                duration_ms,
        })

    if check and completed.returncode != 0:
        raise RuntimeError(
            "command failed: "
            + shlex.join(list(argv))
            + "\n"
            + (completed.stderr or "")
        )

    return completed


def lab_shell(
    *,
    repo_root: Path,
    script: str,
    log: list[dict[str, Any]],
    timeout: float = 90.0,
) -> subprocess.CompletedProcess[str]:
    lib = (
        repo_root
        / "lab"
        / "scripts"
        / "lib.sh"
    )

    command = (
        f"source {shlex.quote(str(lib))}; "
        f"{script}"
    )

    return command_result(
        argv=["bash", "-lc", command],
        cwd=repo_root,
        timeout=timeout,
        check=True,
        log=log,
    )


def container_name(
    lab_name: str,
    node: str,
) -> str:
    return f"clab-{lab_name}-{node}"


def docker_command(
    *,
    repo_root: Path,
    lab_name: str,
    node: str,
    args: Sequence[str],
    log: list[dict[str, Any]] | None = None,
    check: bool = True,
    timeout: float = 30.0,
    detached: bool = False,
) -> subprocess.CompletedProcess[str]:
    argv = ["docker", "exec"]

    if detached:
        argv.append("-d")

    argv.extend([
        container_name(
            lab_name,
            node,
        ),
        *args,
    ])

    return command_result(
        argv=argv,
        cwd=repo_root,
        timeout=timeout,
        check=check,
        log=log,
    )


def probe_command(
    *,
    repo_root: Path,
    lab_name: str,
    node: str,
    args: Sequence[str],
) -> dict[str, Any]:
    started = time.monotonic()

    try:
        completed = docker_command(
            repo_root=repo_root,
            lab_name=lab_name,
            node=node,
            args=args,
            check=False,
            timeout=10.0,
        )

        return {
            "argv": [
                "docker",
                "exec",
                container_name(
                    lab_name,
                    node,
                ),
                *args,
            ],
            "returncode":
                int(completed.returncode),
            "stdout":
                (completed.stdout or "")[:4000],
            "stderr":
                (completed.stderr or "")[:4000],
            "observed_success":
                completed.returncode == 0,
            "duration_ms":
                (
                    time.monotonic()
                    - started
                )
                * 1000.0,
        }

    except Exception as exc:
        return {
            "argv": [
                "docker",
                "exec",
                container_name(
                    lab_name,
                    node,
                ),
                *args,
            ],
            "returncode": 255,
            "stdout": "",
            "stderr": str(exc),
            "observed_success": False,
            "duration_ms":
                (
                    time.monotonic()
                    - started
                )
                * 1000.0,
        }


def start_security_service(
    *,
    repo_root: Path,
    plan: dict[str, Any],
    log: list[dict[str, Any]],
) -> None:
    lab = plan["lab"]
    lab_name = lab["name"]
    sec = lab["security_invariant"]

    server = sec["server"]
    ip = sec["destination_ip"]
    port = int(sec["destination_port"])

    docker_command(
        repo_root=repo_root,
        lab_name=lab_name,
        node=server,
        args=[
            "sh",
            "-c",
            (
                "pkill -f "
                f"'^python3 .*http.server {port} ' "
                "2>/dev/null || true"
            ),
        ],
        log=log,
        check=True,
    )

    docker_command(
        repo_root=repo_root,
        lab_name=lab_name,
        node=server,
        args=[
            "sh",
            "-c",
            (
                "exec python3 -u "
                f"-m http.server {port} "
                f"--bind {ip} "
                "--directory /srv/kansoku "
                f">/var/log/"
                f"kansoku-http-{port}.log "
                "2>&1"
            ),
        ],
        log=log,
        check=True,
        detached=True,
    )

    for _ in range(20):
        probe = probe_command(
            repo_root=repo_root,
            lab_name=lab_name,
            node=server,
            args=[
                "sh",
                "-c",
                (
                    "ss -lnt | grep -Eq "
                    f"'[:.]{port}[[:space:]]'"
                ),
            ],
        )

        if probe["observed_success"]:
            return

        time.sleep(1)

    raise RuntimeError(
        "security-invariant service "
        f"TCP/{port} did not start"
    )


def stop_security_service(
    *,
    repo_root: Path,
    plan: dict[str, Any],
) -> None:
    try:
        lab = plan["lab"]
        sec = lab["security_invariant"]

        docker_command(
            repo_root=repo_root,
            lab_name=lab["name"],
            node=sec["server"],
            args=[
                "sh",
                "-c",
                (
                    "pkill -f "
                    "'^python3 .*http.server "
                    f"{sec['destination_port']} ' "
                    "2>/dev/null || true"
                ),
            ],
            check=False,
        )
    except Exception:
        pass


def reset_network(
    *,
    repo_root: Path,
    log: list[dict[str, Any]],
) -> None:
    lab_shell(
        repo_root=repo_root,
        script="reset_network",
        log=log,
        timeout=90.0,
    )


def probe_state(
    *,
    repo_root: Path,
    plan: dict[str, Any],
    family: str,
    include_target: bool = True,
) -> dict[str, Any]:
    started = time.monotonic()

    lab = plan["lab"]
    lab_name = lab["name"]

    target = lab["target"]
    sec = lab["security_invariant"]
    ctl = lab["independent_control"]

    payload: dict[str, Any] = {}

    if include_target:
        payload["target"] = probe_command(
            repo_root=repo_root,
            lab_name=lab_name,
            node=target["client"],
            args=[
                "curl",
                "-fsS",
                "--connect-timeout",
                "2",
                "--max-time",
                "4",
                target["url"],
            ],
        )

    payload[
        "independent_control"
    ] = probe_command(
        repo_root=repo_root,
        lab_name=lab_name,
        node=ctl["source"],
        args=[
            "ping",
            "-c",
            "1",
            "-W",
            "1",
            ctl["destination_ip"],
        ],
    )

    payload[
        "security_service_listening"
    ] = probe_command(
        repo_root=repo_root,
        lab_name=lab_name,
        node=sec["server"],
        args=[
            "sh",
            "-c",
            (
                "ss -lnt | grep -Eq "
                f"'[:.]{sec['destination_port']}"
                "[[:space:]]'"
            ),
        ],
    )

    sec_url = (
        "http://"
        f"{sec['destination_ip']}:"
        f"{sec['destination_port']}/"
    )

    payload[
        "security_invariant"
    ] = probe_command(
        repo_root=repo_root,
        lab_name=lab_name,
        node=sec["client"],
        args=[
            "curl",
            "-fsS",
            "--connect-timeout",
            "2",
            "--max-time",
            "4",
            sec_url,
        ],
    )

    if (
        plan["families"][family][
            "same_path_control_required"
        ]
    ):
        same = lab[
            "firewall_same_path_control"
        ]

        payload[
            "same_path_control"
        ] = probe_command(
            repo_root=repo_root,
            lab_name=lab_name,
            node=same["client"],
            args=[
                "sh",
                "-c",
                (
                    "iperf3 -c "
                    f"{same['destination_ip']} "
                    "-t 1 >/dev/null"
                ),
            ],
        )
    else:
        payload[
            "same_path_control"
        ] = None

    payload["stage_duration_ms"] = (
        time.monotonic() - started
    ) * 1000.0

    return payload


def require_baseline(
    state: dict[str, Any],
    *,
    require_same_path: bool,
) -> None:
    if not state[
        "target"
    ]["observed_success"]:
        raise RuntimeError(
            "baseline target TCP/443 "
            "is not reachable"
        )

    if not state[
        "independent_control"
    ]["observed_success"]:
        raise RuntimeError(
            "baseline independent control failed"
        )

    if not state[
        "security_service_listening"
    ]["observed_success"]:
        raise RuntimeError(
            "security service TCP/8443 "
            "is not listening"
        )

    if state[
        "security_invariant"
    ]["observed_success"]:
        raise RuntimeError(
            "baseline security invariant violated: "
            "TCP/8443 is reachable"
        )

    if (
        require_same_path
        and not state[
            "same_path_control"
        ]["observed_success"]
    ):
        raise RuntimeError(
            "baseline TCP/5201 "
            "same-path control failed"
        )


def inject_fault(
    *,
    repo_root: Path,
    plan: dict[str, Any],
    family: str,
    log: list[dict[str, Any]],
) -> None:
    lab_name = plan["lab"]["name"]

    spec = plan["families"][
        family
    ]["fault_injection"]

    fault_type = spec["type"]

    if fault_type == "NFT_INSERT_DENY":
        docker_command(
            repo_root=repo_root,
            lab_name=lab_name,
            node=spec["device"],
            args=[
                "nft",
                "insert",
                "rule",
                spec["table_family"],
                spec["table"],
                spec["chain"],
                "ip",
                "saddr",
                spec["src_network"],
                "ip",
                "daddr",
                spec["dst_network"],
                "tcp",
                "dport",
                str(spec["dst_port"]),
                "counter",
                "drop",
                "comment",
                '"kansoku rq3 injected deny"',
            ],
            log=log,
        )

    elif fault_type == "REMOVE_STATIC_ROUTE":
        docker_command(
            repo_root=repo_root,
            lab_name=lab_name,
            node=spec["device"],
            args=[
                "vtysh",
                "-c",
                "configure terminal",
                "-c",
                (
                    "no ip route "
                    f"{spec['prefix']} "
                    f"{spec['next_hop']}"
                ),
            ],
            log=log,
        )

        time.sleep(1)

    elif (
        fault_type
        == "VLAN_ACCESS_TRUNK_DRIFT"
    ):
        docker_command(
            repo_root=repo_root,
            lab_name=lab_name,
            node=spec["device"],
            args=[
                "ovs-vsctl",
                "set",
                "Port",
                spec["access_interface"],
                f"tag={spec['access_vlan']}",
            ],
            log=log,
        )

        docker_command(
            repo_root=repo_root,
            lab_name=lab_name,
            node=spec["device"],
            args=[
                "ovs-vsctl",
                "set",
                "Port",
                spec["trunk_interface"],
                (
                    "trunks="
                    f"{spec['trunk_vlan']}"
                ),
            ],
            log=log,
        )

        time.sleep(1)

    else:
        raise ValueError(
            "unsupported RQ3 fault type: "
            f"{fault_type}"
        )


def capture_target_flow(
    *,
    repo_root: Path,
    pcap: Path,
    should_succeed: bool,
    log: list[dict[str, Any]],
) -> None:
    state = (
        "yes"
        if should_succeed
        else "no"
    )

    lab_shell(
        repo_root=repo_root,
        script=(
            "capture_https_on_fw "
            f"{shlex.quote(str(pcap))} "
            f"{state}"
        ),
        log=log,
        timeout=20.0,
    )

    if (
        not pcap.exists()
        or pcap.stat().st_size <= 0
    ):
        raise RuntimeError(
            "target-flow PCAP is missing or empty"
        )


def run_kansoku_json(
    *,
    repo_root: Path,
    db: Path,
    args: Sequence[str],
    log: list[dict[str, Any]],
    timeout: float = 60.0,
) -> dict[str, Any]:
    completed = command_result(
        argv=[
            sys.executable,
            "-m",
            "kansoku",
            "--db",
            str(db),
            *args,
        ],
        cwd=repo_root,
        timeout=timeout,
        check=True,
        log=log,
    )

    try:
        return json.loads(
            completed.stdout
        )
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            "KANSOKU CLI did not return JSON: "
            + completed.stdout[:2000]
        ) from exc


def collect_live_state(
    *,
    repo_root: Path,
    plan: dict[str, Any],
    db: Path,
    log: list[dict[str, Any]],
) -> None:
    lab_name = plan["lab"]["name"]

    common = [
        sys.executable,
        "-m",
        "kansoku",
        "--db",
        str(db),
    ]

    commands = [
        [*common, "init"],

        [
            *common,
            "network",
            "collect",
            "frr-routes",
            "--device-id",
            "r1",
            "--container",
            container_name(
                lab_name,
                "r1",
            ),
            "--exclude-interface",
            "eth0",
        ],

        [
            *common,
            "network",
            "collect",
            "ovs-ports",
            "--device-id",
            "sw1",
            "--container",
            container_name(
                lab_name,
                "sw1",
            ),
        ],

        [
            *common,
            "network",
            "collect",
            "nft-ruleset",
            "--device-id",
            "fw1",
            "--container",
            container_name(
                lab_name,
                "fw1",
            ),
        ],
    ]

    for argv in commands:
        command_result(
            argv=argv,
            cwd=repo_root,
            timeout=60.0,
            check=True,
            log=log,
        )


def summarize_and_correlate(
    *,
    repo_root: Path,
    db: Path,
    pcap: Path,
    log: list[dict[str, Any]],
) -> tuple[
    str,
    dict[str, Any],
    dict[str, Any],
]:
    capture = run_kansoku_json(
        repo_root=repo_root,
        db=db,
        args=[
            "capture",
            "summarize",
            "--pcap",
            str(pcap),
            "--target",
            "rq3-target",
            "--source",
            "containerlab",
        ],
        log=log,
    )

    capture_id = capture[
        "capture"
    ]["capture_id"]

    correlation = run_kansoku_json(
        repo_root=repo_root,
        db=db,
        args=[
            "network",
            "correlate",
            "--capture-id",
            capture_id,
            "--ingress-device",
            "fw1",
            "--route-device",
            "r1",
            "--policy-device",
            "fw1",
            "--vlan-device",
            "sw1",
        ],
        log=log,
    )

    return (
        capture_id,
        capture,
        correlation,
    )


def select_flow_and_assessment(
    hub: Hub,
    capture_id: str,
):
    flows = [
        flow
        for flow in hub.list_flow_records(
            capture_id=capture_id,
            limit=100,
        )
        if (
            flow.protocol.upper() == "TCP"
            and flow.src_ip
            == "10.10.10.10"
            and flow.dst_ip
            == "10.20.20.10"
            and flow.dst_port == 443
        )
    ]

    if not flows:
        raise RuntimeError(
            "target TCP/443 flow was not "
            "found in captured evidence"
        )

    flow = max(
        flows,
        key=lambda item: (
            item.wire_bytes,
            item.packets,
        ),
    )

    assessments = [
        item
        for item
        in hub.list_flow_assessments(
            capture_id=capture_id,
            limit=100,
        )
        if item.flow_id == flow.flow_id
    ]

    if not assessments:
        raise RuntimeError(
            "target-flow assessment not found"
        )

    return flow, assessments[0]


def source_network_state(
    hub: Hub,
) -> tuple[
    list[Any],
    list[Any],
    list[Any],
    list[Any],
]:
    routes = hub.list_network_routes(
        device_id="r1",
        limit=5000,
    )

    policies = hub.list_network_policies(
        device_id="fw1",
        limit=5000,
    )

    vlans = hub.list_network_vlans(
        device_id="sw1",
        limit=1000,
    )

    interfaces = (
        hub.list_network_interfaces(
            device_id="sw1",
            limit=1000,
        )
    )

    return (
        routes,
        policies,
        vlans,
        interfaces,
    )


AuxiliaryProbe = Callable[
    [str],
    dict[str, Any],
]


class InstrumentedVirtualLabExecutor(
    VirtualLabExecutor
):
    def __init__(
        self,
        *,
        auxiliary_probe: AuxiliaryProbe,
        **kwargs,
    ):
        super().__init__(**kwargs)

        self.auxiliary_probe = (
            auxiliary_probe
        )

        self.stage_observations: dict[
            str,
            dict[str, Any],
        ] = {}

    def _verify_service(
        self,
        *,
        client_node: str,
        verify_url: str,
        expect_success: bool,
    ) -> dict[str, Any]:
        started = time.monotonic()

        target = super()._verify_service(
            client_node=client_node,
            verify_url=verify_url,
            expect_success=expect_success,
        )

        stage = (
            "post_change"
            if expect_success
            else "post_rollback"
        )

        auxiliary = self.auxiliary_probe(
            stage
        )

        self.stage_observations[
            stage
        ] = {
            "target": target,
            "auxiliary": auxiliary,
            "stage_duration_ms":
                (
                    time.monotonic()
                    - started
                )
                * 1000.0,
        }

        return target


def observed_aux_state(
    payload: dict[str, Any] | None,
) -> dict[str, Any]:
    if not payload:
        return {
            "independent_control_reachable":
                None,
            "security_service_listening":
                None,
            "security_invariant_reachable":
                None,
            "same_path_control_reachable":
                None,
        }

    aux = payload["auxiliary"]

    same = aux.get(
        "same_path_control"
    )

    return {
        "independent_control_reachable":
            aux[
                "independent_control"
            ]["observed_success"],

        "security_service_listening":
            aux[
                "security_service_listening"
            ]["observed_success"],

        "security_invariant_reachable":
            aux[
                "security_invariant"
            ]["observed_success"],

        "same_path_control_reachable":
            (
                same["observed_success"]
                if same is not None
                else None
            ),
    }


def observed_full_state(
    payload: dict[str, Any],
) -> dict[str, Any]:
    same = payload.get(
        "same_path_control"
    )

    return {
        "target_reachable":
            payload[
                "target"
            ]["observed_success"],

        "independent_control_reachable":
            payload[
                "independent_control"
            ]["observed_success"],

        "security_service_listening":
            payload[
                "security_service_listening"
            ]["observed_success"],

        "security_invariant_reachable":
            payload[
                "security_invariant"
            ]["observed_success"],

        "same_path_control_reachable":
            (
                same["observed_success"]
                if same is not None
                else None
            ),
    }


def execute_instance(
    *,
    repo_root: Path,
    plan_path: Path,
    instance_id: str,
    output_dir: Path,
) -> dict[str, Any]:
    plan = load_frozen_plan(
        plan_path
    )

    if instance_id not in plan[
        "executions"
    ]:
        raise ValueError(
            f"unknown RQ3 instance: "
            f"{instance_id}"
        )

    if output_dir.exists():
        raise FileExistsError(
            "output directory already exists: "
            f"{output_dir}"
        )

    row = plan["executions"][
        instance_id
    ]

    family = row["family"]

    family_spec = plan[
        "families"
    ][family]

    output_dir.mkdir(
        parents=True,
        exist_ok=False,
    )

    db = output_dir / "state.db"
    pcap = output_dir / "target.pcap"

    command_log: list[
        dict[str, Any]
    ] = []

    prereg_commit = git(
        repo_root,
        "rev-list",
        "-n",
        "1",
        PREREG_TAG,
    )

    runner_commit = git(
        repo_root,
        "rev-parse",
        "HEAD",
    )

    write_json(
        output_dir / "trial.json",
        {
            "schema_version": 1,
            "phase":
                "RQ3 guarded remediation",
            "instance_id":
                instance_id,
            "family":
                family,
            "repetition":
                row["repetition"],
            "preregistration_tag":
                PREREG_TAG,
            "preregistration_commit":
                prereg_commit,
            "runner_commit":
                runner_commit,
            "plan_sha256":
                sha256_file(plan_path),
            "ground_truth_consumed_by_runner":
                False,
            "environment":
                plan[
                    "runner_constraints"
                ]["environment"],
        },
    )

    cleanup_error = ""

    try:
        reset_network(
            repo_root=repo_root,
            log=command_log,
        )

        start_security_service(
            repo_root=repo_root,
            plan=plan,
            log=command_log,
        )

        baseline_raw = probe_state(
            repo_root=repo_root,
            plan=plan,
            family=family,
            include_target=True,
        )

        require_baseline(
            baseline_raw,
            require_same_path=(
                family_spec[
                    "same_path_control_required"
                ]
            ),
        )

        if (
            family_spec["capture_timing"]
            == "before_fault_injection"
        ):
            capture_target_flow(
                repo_root=repo_root,
                pcap=pcap,
                should_succeed=True,
                log=command_log,
            )

        inject_fault(
            repo_root=repo_root,
            plan=plan,
            family=family,
            log=command_log,
        )

        fault_raw = probe_state(
            repo_root=repo_root,
            plan=plan,
            family=family,
            include_target=True,
        )

        if fault_raw[
            "target"
        ]["observed_success"]:
            raise RuntimeError(
                "fault injection did not "
                "interrupt target TCP/443"
            )

        if not fault_raw[
            "security_service_listening"
        ]["observed_success"]:
            raise RuntimeError(
                "security service TCP/8443 "
                "is not listening in fault state"
            )

        if (
            family_spec["capture_timing"]
            == "after_fault_injection"
        ):
            capture_target_flow(
                repo_root=repo_root,
                pcap=pcap,
                should_succeed=False,
                log=command_log,
            )

        collect_live_state(
            repo_root=repo_root,
            plan=plan,
            db=db,
            log=command_log,
        )

        (
            capture_id,
            capture_cli,
            correlation_cli,
        ) = summarize_and_correlate(
            repo_root=repo_root,
            db=db,
            pcap=pcap,
            log=command_log,
        )

        hub = Hub(db)

        (
            flow,
            assessment,
        ) = select_flow_and_assessment(
            hub,
            capture_id,
        )

        (
            routes,
            policies,
            vlans,
            interfaces,
        ) = source_network_state(hub)

        graph = build_evidence_graph(
            assessment,
            flow,
            routes=routes,
            policies=policies,
            vlans=vlans,
            interfaces=interfaces,
        )

        hub.add_evidence_graphs(
            [graph]
        )

        candidates = (
            RecommendationEngine()
            .generate_candidates(
                assessment,
                flow,
                routes=routes,
                policies=policies,
                vlans=vlans,
                interfaces=interfaces,
                **family_spec[
                    "recommendation_inputs"
                ],
            )
        )

        ranked = (
            RecommendationRanker()
            .rank(
                candidates,
                evidence_graph=graph,
            )
        )

        if not ranked:
            raise RuntimeError(
                "recommendation ranking "
                "returned no candidates"
            )

        top = ranked[0]
        top1 = top.recommendation

        eligibility = approval_issues(
            top1
        )

        hub.add_configuration_recommendations(
            candidates
        )

        write_json(
            output_dir
            / "capture.json",
            capture_cli,
        )

        write_json(
            output_dir
            / "correlation.json",
            correlation_cli,
        )

        write_json(
            output_dir
            / "flow.json",
            flow.to_dict(),
        )

        write_json(
            output_dir
            / "assessment.json",
            assessment.to_dict(),
        )

        write_json(
            output_dir
            / "network-state.json",
            {
                "routes": [
                    x.to_dict()
                    for x in routes
                ],
                "policies": [
                    x.to_dict()
                    for x in policies
                ],
                "vlans": [
                    x.to_dict()
                    for x in vlans
                ],
                "interfaces": [
                    x.to_dict()
                    for x in interfaces
                ],
            },
        )

        write_json(
            output_dir
            / "evidence-graph.json",
            graph.to_dict(),
        )

        write_json(
            output_dir
            / "candidates.json",
            {
                "schema_version": 1,
                "candidates": [
                    x.to_dict()
                    for x in candidates
                ],
            },
        )

        write_json(
            output_dir
            / "ranked-candidates.json",
            {
                "schema_version": 1,
                "ranked": [
                    x.to_dict()
                    for x in ranked
                ],
            },
        )

        if eligibility:
            raise RuntimeError(
                "rank-1 recommendation "
                "did not cross approval gate: "
                + "; ".join(eligibility)
            )

        approval_actor = plan[
            "runner_constraints"
        ]["approval_actor"]

        approved = (
            hub
            .set_configuration_recommendation_status(
                top1.recommendation_id,
                "APPROVED",
                reviewed_by=approval_actor,
                note=(
                    "RQ3 virtual-lab "
                    "guarded-remediation trial"
                ),
            )
        )

        approval_event = (
            approved.metadata[
                "review_history"
            ][-1]
        )

        write_json(
            output_dir
            / "approval.json",
            {
                "recommendation_id":
                    approved.recommendation_id,
                "status":
                    approved.status,
                "simulation_status":
                    approved.simulation_status,
                "simulated_verdict":
                    approved.simulated_verdict,
                "event":
                    approval_event,
            },
        )

        def auxiliary_probe(
            stage: str,
        ) -> dict[str, Any]:
            payload = probe_state(
                repo_root=repo_root,
                plan=plan,
                family=family,
                include_target=False,
            )

            payload["stage"] = stage
            return payload

        executor = (
            InstrumentedVirtualLabExecutor(
                auxiliary_probe=
                    auxiliary_probe,
                runtime="docker",
                lab_name=
                    plan["lab"]["name"],
                timeout=15.0,
            )
        )

        guarded_started = (
            time.monotonic()
        )

        execution = executor.execute(
            approved,
            approved_by=
                approval_actor,
            environment=
                plan[
                    "runner_constraints"
                ]["environment"],
            client_node=
                plan[
                    "lab"
                ][
                    "target"
                ][
                    "client"
                ],
            verify_url=
                plan[
                    "lab"
                ][
                    "target"
                ][
                    "url"
                ],
            rollback_after_verify=
                plan[
                    "runner_constraints"
                ][
                    "rollback_after_verify"
                ],
        )

        guarded_duration_ms = (
            time.monotonic()
            - guarded_started
        ) * 1000.0

        hub.add_remediation_executions(
            [execution]
        )

        post_change = (
            executor.stage_observations
            .get("post_change")
        )

        post_rollback = (
            executor.stage_observations
            .get("post_rollback")
        )

        write_json(
            output_dir
            / "remediation-execution.json",
            execution.to_dict(),
        )

        write_json(
            output_dir
            / "executor-stage-observations.json",
            executor.stage_observations,
        )

        # Canonical reset is deliberately
        # outside the guarded execution.
        reset_network(
            repo_root=repo_root,
            log=command_log,
        )

        final_raw = probe_state(
            repo_root=repo_root,
            plan=plan,
            family=family,
            include_target=True,
        )

        post_change_state = (
            observed_aux_state(
                post_change
            )
        )

        post_change_state[
            "target_reachable"
        ] = (
            post_change[
                "target"
            ]["observed_success"]
            if post_change
            else None
        )

        post_rollback_state = (
            observed_aux_state(
                post_rollback
            )
        )

        post_rollback_state[
            "target_reachable"
        ] = (
            post_rollback[
                "target"
            ]["observed_success"]
            if post_rollback
            else None
        )

        baseline = observed_full_state(
            baseline_raw
        )

        fault_state = observed_full_state(
            fault_raw
        )

        final_state = observed_full_state(
            final_raw
        )

        apply_success = (
            bool(
                execution.apply_results
            )
            and all(
                x.returncode == 0
                for x
                in execution.apply_results
            )
        )

        rollback_success = (
            bool(
                execution.rollback_results
            )
            and all(
                x.returncode == 0
                for x
                in execution.rollback_results
            )
        )

        what_if_actual_agreement = (
            approved.simulation_status
            == "PASSED"
            and approved.simulated_verdict
            == "ALLOW"
            and post_change_state[
                "target_reachable"
            ]
            is True
        )

        timing = {
            "apply_duration_ms":
                sum(
                    x.duration_ms
                    for x
                    in execution.apply_results
                ),

            "post_change_verification_duration_ms":
                (
                    post_change[
                        "stage_duration_ms"
                    ]
                    if post_change
                    else None
                ),

            "rollback_duration_ms":
                sum(
                    x.duration_ms
                    for x
                    in execution.rollback_results
                ),

            "post_rollback_verification_duration_ms":
                (
                    post_rollback[
                        "stage_duration_ms"
                    ]
                    if post_rollback
                    else None
                ),

            "total_guarded_remediation_duration_ms":
                guarded_duration_ms,
        }

        result = {
            "schema_version": 1,

            "instance_id":
                instance_id,
            "family":
                family,
            "repetition":
                row["repetition"],

            "capture_timing":
                family_spec[
                    "capture_timing"
                ],

            "assessment": {
                "assessment_id":
                    assessment.assessment_id,
                "verdict":
                    assessment.verdict,
                "route_status":
                    assessment.route_status,
                "policy_status":
                    assessment.policy_status,
                "vlan_status":
                    assessment.vlan_status,
            },

            "top1": {
                "recommendation_id":
                    approved.recommendation_id,
                "category":
                    approved.category,
                "device_id":
                    approved.device_id,
                "variant":
                    candidate_variant(
                        approved
                    ),
                "rank":
                    top.rank,
                "score":
                    top.score,
                "risk_level":
                    approved.risk_level,
                "simulation_status":
                    approved.simulation_status,
                "simulated_verdict":
                    approved.simulated_verdict,
                "approval_issues":
                    eligibility,
                "approved":
                    approved.status
                    == "APPROVED",
            },

            "execution": {
                "execution_id":
                    execution.execution_id,
                "status":
                    execution.status,
                "error":
                    execution.error,
                "apply_success":
                    apply_success,
                "rollback_success":
                    rollback_success,
            },

            "observed_states": {
                "baseline":
                    baseline,
                "fault":
                    fault_state,
                "post_change":
                    post_change_state,
                "post_rollback":
                    post_rollback_state,
                "final_baseline":
                    final_state,
            },

            "what_if_actual_agreement":
                what_if_actual_agreement,

            "timing":
                timing,

            "ground_truth_consumed_by_runner":
                False,
        }

        write_json(
            output_dir / "result.json",
            result,
        )

        write_json(
            output_dir / "command-log.json",
            {
                "schema_version": 1,
                "commands":
                    command_log,
            },
        )

        return result

    except Exception as exc:
        write_json(
            output_dir / "error.json",
            {
                "instance_id":
                    instance_id,
                "family":
                    family,
                "error":
                    str(exc),
                "ground_truth_consumed_by_runner":
                    False,
            },
        )

        write_json(
            output_dir / "command-log.json",
            {
                "schema_version": 1,
                "commands":
                    command_log,
            },
        )

        raise

    finally:
        try:
            reset_network(
                repo_root=repo_root,
                log=command_log,
            )
        except Exception as exc:
            cleanup_error = str(exc)

        stop_security_service(
            repo_root=repo_root,
            plan=plan,
        )

        if cleanup_error:
            write_json(
                output_dir
                / "cleanup-error.json",
                {
                    "error":
                        cleanup_error
                },
            )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run one preregistered KANSOKU "
            "RQ3 guarded-remediation trial."
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
    args = build_parser().parse_args()

    repo_root = Path(
        git(
            Path.cwd(),
            "rev-parse",
            "--show-toplevel",
        )
    )

    result = execute_instance(
        repo_root=repo_root,
        plan_path=(
            repo_root / args.plan
        ),
        instance_id=args.instance,
        output_dir=Path(
            args.output_dir
        ).resolve(),
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
        "PASS: RQ3 guarded-remediation "
        "instance completed"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
