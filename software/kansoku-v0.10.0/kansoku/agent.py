from __future__ import annotations

import json
import platform
import random
import re
import shutil
import socket
import subprocess
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

from .models import CollectionResult, CollectionRun, Domain, Observation, utc_now


@dataclass
class AgentConfig:
    source: str = socket.gethostname()


class AgentCommandError(RuntimeError):
    pass


class SimulatedNetworkAgent:
    """Generate observations for local demos and tests."""

    def __init__(self, config: Optional[AgentConfig] = None):
        self.config = config or AgentConfig()

    def observe(self, target: str, profile: str = "normal", count: int = 5) -> List[Observation]:
        observations: List[Observation] = []
        for _ in range(count):
            if profile == "normal":
                rtt = random.uniform(8, 25)
                loss = random.choice([0.0, 0.0, 0.0, 0.2])
                throughput = random.uniform(850, 950)
            elif profile == "warning":
                rtt = random.uniform(40, 80)
                loss = random.uniform(0.5, 2.5)
                throughput = random.uniform(500, 750)
            elif profile == "degraded":
                rtt = random.uniform(120, 260)
                loss = random.uniform(4.0, 12.0)
                throughput = random.uniform(80, 350)
            elif profile == "critical":
                rtt = random.uniform(300, 900)
                loss = random.uniform(15.0, 60.0)
                throughput = random.uniform(0, 80)
            else:
                raise ValueError(f"unknown simulation profile: {profile}")

            observations.extend(
                [
                    Observation(target=target, source=self.config.source, domain=Domain.NETWORK.value,
                                metric="rtt_ms", value=round(rtt, 3), unit="ms", method="simulation",
                                labels={"profile": profile}),
                    Observation(target=target, source=self.config.source, domain=Domain.NETWORK.value,
                                metric="packet_loss_pct", value=round(loss, 3), unit="%", method="simulation",
                                labels={"profile": profile}),
                    Observation(target=target, source=self.config.source, domain=Domain.NETWORK.value,
                                metric="throughput_mbps", value=round(throughput, 3), unit="Mbps",
                                method="simulation", labels={"profile": profile}),
                ]
            )
        return observations


class PingAgent:
    """Collect RTT and loss using platform-aware ping commands.

    Linux uses `-W <seconds>`. macOS uses `-W <milliseconds>`.
    Parsing accepts both `rtt` and `round-trip` summary formats.
    """

    PACKET_LOSS_RE = re.compile(r"(?P<loss>[0-9.]+)%\s+packet loss", re.IGNORECASE)
    RTT_RE = re.compile(
        r"(?:round-trip|rtt)[^=]*=\s*[0-9.]+/(?P<avg>[0-9.]+)/[0-9.]+(?:/[0-9.]+)?\s*ms",
        re.IGNORECASE,
    )

    def __init__(self, config: Optional[AgentConfig] = None, system_name: Optional[str] = None):
        self.config = config or AgentConfig()
        self.system_name = system_name or platform.system()

    def build_command(self, target: str, count: int = 4, timeout: float = 5.0) -> List[str]:
        if not shutil.which("ping"):
            raise AgentCommandError("ping command was not found in PATH")
        wait_value = str(max(1, int(timeout * 1000))) if self.system_name == "Darwin" else str(max(1, int(timeout)))
        return ["ping", "-c", str(count), "-W", wait_value, target]

    def collect(self, target: str, count: int = 4, timeout: float = 5.0) -> CollectionResult:
        cmd = self.build_command(target, count=count, timeout=timeout)
        started = utc_now()
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        finished = utc_now()
        output = proc.stdout + "\n" + proc.stderr
        observations = self.parse_output(target, output, proc.returncode)
        run = CollectionRun(
            agent="ping",
            target=target,
            source=self.config.source,
            command=cmd,
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            started_at=started,
            finished_at=finished,
            metadata={"platform": self.system_name, "count": count, "timeout_sec": timeout},
        )
        for obs in observations:
            obs.labels["run_id"] = run.run_id
        return CollectionResult(observations=observations, run=run)

    def observe(self, target: str, count: int = 4, timeout: float = 5.0) -> List[Observation]:
        return self.collect(target, count=count, timeout=timeout).observations

    def parse_output(self, target: str, output: str, returncode: int = 0) -> List[Observation]:
        loss = self._extract_loss(output)
        avg_rtt = self._extract_avg_rtt(output)
        observations: List[Observation] = []
        common = dict(target=target, source=self.config.source, domain=Domain.NETWORK.value, method="ping")

        if loss is not None:
            observations.append(Observation(metric="packet_loss_pct", value=loss, unit="%",
                                            quality={"confidence": 0.98, "missing": False}, **common))
            observations.append(Observation(metric="reachability", value=0.0 if loss >= 100.0 else 1.0,
                                            unit="bool", quality={"confidence": 0.98, "missing": False}, **common))
        if avg_rtt is not None:
            observations.append(Observation(metric="rtt_ms", value=avg_rtt, unit="ms",
                                            quality={"confidence": 0.98, "missing": False}, **common))
        elif returncode != 0 and loss is None and self._looks_like_network_failure(output):
            observations.append(Observation(metric="reachability", value=0.0, unit="bool",
                                            quality={"confidence": 0.8, "missing": False}, **common))
        return observations

    @staticmethod
    def _looks_like_network_failure(output: str) -> bool:
        text = output.lower()
        network_markers = (
            "destination host unreachable",
            "no route to host",
            "request timeout",
            "100% packet loss",
        )
        execution_error_markers = (
            "operation not permitted",
            "permission denied",
            "invalid option",
            "usage:",
            "command not found",
        )
        if any(marker in text for marker in execution_error_markers):
            return False
        return any(marker in text for marker in network_markers)

    @classmethod
    def _extract_loss(cls, output: str) -> Optional[float]:
        match = cls.PACKET_LOSS_RE.search(output)
        return float(match.group("loss")) if match else None

    @classmethod
    def _extract_avg_rtt(cls, output: str) -> Optional[float]:
        match = cls.RTT_RE.search(output)
        return float(match.group("avg")) if match else None


class Iperf3Agent:
    """Collect TCP/UDP performance metrics from iperf3 JSON output."""

    def __init__(self, config: Optional[AgentConfig] = None):
        self.config = config or AgentConfig()

    def build_command(
        self,
        target: str,
        port: int = 5201,
        duration: int = 10,
        reverse: bool = False,
        udp: bool = False,
        bitrate: Optional[str] = None,
        parallel: int = 1,
        connect_timeout_ms: int = 5000,
    ) -> List[str]:
        if not shutil.which("iperf3"):
            raise AgentCommandError("iperf3 command was not found in PATH; on macOS run: brew install iperf3")
        cmd = [
            "iperf3", "-c", target, "-p", str(port), "-t", str(duration),
            "-P", str(parallel), "--connect-timeout", str(connect_timeout_ms), "-J",
        ]
        if reverse:
            cmd.append("-R")
        if udp:
            cmd.append("-u")
            if bitrate:
                cmd.extend(["-b", bitrate])
        return cmd

    def collect(
        self,
        target: str,
        port: int = 5201,
        duration: int = 10,
        reverse: bool = False,
        udp: bool = False,
        bitrate: Optional[str] = None,
        parallel: int = 1,
        connect_timeout_ms: int = 5000,
    ) -> CollectionResult:
        cmd = self.build_command(
            target, port=port, duration=duration, reverse=reverse, udp=udp,
            bitrate=bitrate, parallel=parallel, connect_timeout_ms=connect_timeout_ms,
        )
        started = utc_now()
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        finished = utc_now()
        observations: List[Observation] = []
        parse_error: Optional[str] = None
        try:
            payload = json.loads(proc.stdout) if proc.stdout.strip() else {}
            observations = self.parse_json(target, payload, reverse=reverse, udp=udp, port=port)
            if payload.get("error"):
                parse_error = str(payload["error"])
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            parse_error = f"invalid iperf3 JSON: {exc}"

        run = CollectionRun(
            agent="iperf3",
            target=target,
            source=self.config.source,
            command=cmd,
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            started_at=started,
            finished_at=finished,
            metadata={
                "protocol": "udp" if udp else "tcp",
                "direction": "reverse" if reverse else "forward",
                "port": port,
                "duration_sec": duration,
                "parallel": parallel,
                "parse_error": parse_error,
            },
        )
        for obs in observations:
            obs.labels["run_id"] = run.run_id
        return CollectionResult(observations=observations, run=run)

    def observe(self, target: str, **kwargs: Any) -> List[Observation]:
        return self.collect(target, **kwargs).observations

    def parse_json(
        self,
        target: str,
        payload: Dict[str, Any],
        reverse: bool = False,
        udp: bool = False,
        port: int = 5201,
    ) -> List[Observation]:
        end = payload.get("end") or {}
        observations: List[Observation] = []
        labels = {
            "protocol": "udp" if udp else "tcp",
            "direction": "reverse" if reverse else "forward",
            "port": str(port),
        }
        common = dict(
            target=target,
            source=self.config.source,
            domain=Domain.NETWORK.value,
            method="iperf3",
            labels=labels,
            quality={"confidence": 0.99, "missing": False},
        )

        if udp:
            summary = end.get("sum") or end.get("sum_received") or end.get("sum_sent") or {}
            self._append_metric(observations, common, "throughput_mbps", summary.get("bits_per_second"), "Mbps", 1e6)
            self._append_metric(observations, common, "jitter_ms", summary.get("jitter_ms"), "ms")
            self._append_metric(observations, common, "packet_loss_pct", summary.get("lost_percent"), "%")
            self._append_metric(observations, common, "lost_packets", summary.get("lost_packets"), "packets")
        else:
            received = end.get("sum_received") or end.get("sum") or {}
            sent = end.get("sum_sent") or end.get("sum") or {}
            self._append_metric(observations, common, "throughput_mbps", received.get("bits_per_second"), "Mbps", 1e6)
            self._append_metric(observations, common, "sender_throughput_mbps", sent.get("bits_per_second"), "Mbps", 1e6)
            self._append_metric(observations, common, "retransmits", sent.get("retransmits"), "segments")

        cpu = end.get("cpu_utilization_percent") or {}
        self._append_metric(observations, common, "local_cpu_total_pct", cpu.get("host_total"), "%")
        self._append_metric(observations, common, "remote_cpu_total_pct", cpu.get("remote_total"), "%")
        return observations

    @staticmethod
    def _append_metric(
        observations: List[Observation],
        common: Dict[str, Any],
        metric: str,
        raw_value: Any,
        unit: str,
        divisor: float = 1.0,
    ) -> None:
        if raw_value is None:
            return
        value = float(raw_value) / divisor
        observations.append(Observation(metric=metric, value=round(value, 6), unit=unit, **common))
