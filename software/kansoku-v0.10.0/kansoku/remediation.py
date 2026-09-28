from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
import math
import re
import shlex
import subprocess
import time
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence

from .evidence import EvidenceGraph
from .models import new_id, utc_now
from .recommendation import ConfigurationRecommendation, require_approval_eligible


EXECUTION_STATUSES = {
    "PLANNED", "APPLYING", "VERIFIED", "ROLLED_BACK", "FAILED", "REFUSED",
}


@dataclass
class RankingWeights:
    repair_probability: float = 0.30
    evidence_coverage: float = 0.25
    reversibility: float = 0.15
    blast_radius_safety: float = 0.15
    security_safety: float = 0.10
    change_simplicity: float = 0.05

    def validate(self) -> None:
        values = asdict(self)
        if any(float(value) < 0 for value in values.values()):
            raise ValueError("ranking weights must be non-negative")
        if not math.isclose(sum(values.values()), 1.0, abs_tol=1e-9):
            raise ValueError("ranking weights must sum to 1.0")

    def to_dict(self) -> Dict[str, float]:
        self.validate()
        return {key: float(value) for key, value in asdict(self).items()}


@dataclass
class RankedRecommendation:
    recommendation_id: str
    assessment_id: str
    category: str
    rank: int
    score: float
    components: Dict[str, float]
    explanation: List[str]
    recommendation: ConfigurationRecommendation

    def validate(self) -> None:
        if self.rank < 1:
            raise ValueError("rank must be at least 1")
        if not 0.0 <= float(self.score) <= 1.0:
            raise ValueError("ranking score must be between 0 and 1")
        for name, value in self.components.items():
            if not 0.0 <= float(value) <= 1.0:
                raise ValueError(f"ranking component out of range: {name}")

    def to_dict(self) -> Dict[str, Any]:
        self.validate()
        return {
            "recommendation_id": self.recommendation_id,
            "assessment_id": self.assessment_id,
            "category": self.category,
            "rank": self.rank,
            "score": self.score,
            "components": self.components,
            "explanation": self.explanation,
            "recommendation": self.recommendation.to_dict(),
        }


class RecommendationRanker:
    def __init__(self, weights: Optional[RankingWeights] = None):
        self.weights = weights or RankingWeights()
        self.weights.validate()

    @staticmethod
    def _has_placeholders(commands: Sequence[str]) -> bool:
        return any("<" in command and ">" in command for command in commands)

    @staticmethod
    def _repair_probability(item: ConfigurationRecommendation) -> float:
        simulation = {
            "PASSED": 1.0,
            "INCONCLUSIVE": 0.45,
            "FAILED": 0.05,
            "NOT_RUN": 0.20,
        }[item.simulation_status]
        return max(0.0, min(1.0, float(item.confidence) * simulation))

    @classmethod
    def _reversibility(cls, item: ConfigurationRecommendation) -> float:
        if item.category == "MANUAL_REVIEW":
            return 1.0
        if not item.rollback_commands:
            return 0.0
        return 0.55 if cls._has_placeholders(item.rollback_commands) else 1.0

    @staticmethod
    def _blast_radius_safety(item: ConfigurationRecommendation) -> float:
        scope = str(item.impact.get("scope") or "").lower()
        if item.category == "MANUAL_REVIEW":
            return 1.0
        if "single observed" in scope or "single host" in scope:
            return 0.98
        if "explicitly named ports" in scope:
            return 0.84
        if item.category == "ROUTE":
            prefix = str(item.impact.get("scope") or "")
            try:
                length = int(prefix.rsplit("/", 1)[1])
                if ":" in prefix:
                    return max(0.25, min(0.98, length / 128))
                return max(0.25, min(0.98, length / 32))
            except (IndexError, ValueError):
                return 0.55
        if "vlan" in scope:
            return 0.70
        return 0.50

    @staticmethod
    def _security_safety(item: ConfigurationRecommendation) -> float:
        base = {"low": 0.95, "medium": 0.68, "high": 0.25}[item.risk_level]
        if item.category == "FIREWALL_POLICY" and item.intent == "ALLOW_OBSERVED_FLOW":
            base -= 0.10
        return max(0.0, min(1.0, base))

    @classmethod
    def _change_simplicity(cls, item: ConfigurationRecommendation) -> float:
        if item.category == "MANUAL_REVIEW":
            return 0.65
        count = len(item.commands)
        value = 1.0 if count <= 1 else max(0.25, 1.0 - 0.18 * (count - 1))
        if cls._has_placeholders(item.commands):
            value *= 0.35
        return value

    def rank(
        self,
        recommendations: Sequence[ConfigurationRecommendation],
        *,
        evidence_graph: Optional[EvidenceGraph] = None,
    ) -> List[RankedRecommendation]:
        if not recommendations:
            return []
        assessment_ids = {item.assessment_id for item in recommendations}
        if len(assessment_ids) != 1:
            raise ValueError("recommendations from different assessments cannot be ranked together")
        coverage = evidence_graph.evidence_coverage if evidence_graph else 0.5
        weight_map = self.weights.to_dict()
        rows: List[tuple[float, ConfigurationRecommendation, Dict[str, float], List[str]]] = []
        for item in recommendations:
            item.validate()
            components = {
                "repair_probability": self._repair_probability(item),
                "evidence_coverage": coverage,
                "reversibility": self._reversibility(item),
                "blast_radius_safety": self._blast_radius_safety(item),
                "security_safety": self._security_safety(item),
                "change_simplicity": self._change_simplicity(item),
            }
            score = sum(components[name] * weight_map[name] for name in weight_map)
            explanation = [
                f"model repair probability={components['repair_probability']:.3f}",
                f"evidence coverage={components['evidence_coverage']:.3f}",
                f"rollback reversibility={components['reversibility']:.3f}",
                f"blast-radius safety={components['blast_radius_safety']:.3f}",
                f"security safety={components['security_safety']:.3f}",
                f"change simplicity={components['change_simplicity']:.3f}",
            ]
            if self._has_placeholders(item.commands + item.rollback_commands):
                explanation.append("unresolved command placeholders reduce actionability")
            rows.append((score, item, components, explanation))
        rows.sort(key=lambda row: (-row[0], row[1].category, row[1].recommendation_id))
        ranked: List[RankedRecommendation] = []
        for index, (score, item, components, explanation) in enumerate(rows, 1):
            rounded = round(score, 6)
            item.metadata = {
                **item.metadata,
                "ranking": {
                    "rank": index,
                    "score": rounded,
                    "components": components,
                    "weights": weight_map,
                },
            }
            ranked.append(RankedRecommendation(
                recommendation_id=item.recommendation_id,
                assessment_id=item.assessment_id,
                category=item.category,
                rank=index,
                score=rounded,
                components=components,
                explanation=explanation,
                recommendation=item,
            ))
        return ranked


@dataclass
class CommandExecution:
    command: str
    argv: List[str]
    returncode: int
    stdout: str
    stderr: str
    started_at: str
    finished_at: str
    duration_ms: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "CommandExecution":
        return cls(**dict(data))


@dataclass
class RemediationExecution:
    recommendation_id: str
    assessment_id: str
    environment: str
    lab_name: str
    device_id: str
    category: str
    approved_by: str
    status: str = "PLANNED"
    apply_results: List[CommandExecution] = field(default_factory=list)
    verification: Dict[str, Any] = field(default_factory=dict)
    readback: Dict[str, Any] = field(default_factory=dict)
    rollback_results: List[CommandExecution] = field(default_factory=list)
    rollback_verification: Dict[str, Any] = field(default_factory=dict)
    error: str = ""
    execution_id: str = field(default_factory=lambda: new_id("remediation"))
    started_at: str = field(default_factory=utc_now)
    finished_at: str = field(default_factory=utc_now)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        if self.environment != "virtual-lab":
            raise ValueError("remediation execution is restricted to environment=virtual-lab")
        if self.status not in EXECUTION_STATUSES:
            raise ValueError(f"unsupported remediation execution status: {self.status}")
        if not self.recommendation_id or not self.assessment_id or not self.approved_by.strip():
            raise ValueError("recommendation_id, assessment_id, and approved_by are required")

    def to_dict(self) -> Dict[str, Any]:
        self.validate()
        return {
            "recommendation_id": self.recommendation_id,
            "assessment_id": self.assessment_id,
            "environment": self.environment,
            "lab_name": self.lab_name,
            "device_id": self.device_id,
            "category": self.category,
            "approved_by": self.approved_by,
            "status": self.status,
            "apply_results": [item.to_dict() for item in self.apply_results],
            "verification": self.verification,
            "readback": self.readback,
            "rollback_results": [item.to_dict() for item in self.rollback_results],
            "rollback_verification": self.rollback_verification,
            "error": self.error,
            "execution_id": self.execution_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "RemediationExecution":
        payload = dict(data)
        payload["apply_results"] = [CommandExecution.from_dict(item) for item in payload.get("apply_results", [])]
        payload["rollback_results"] = [CommandExecution.from_dict(item) for item in payload.get("rollback_results", [])]
        for key in ("verification", "readback", "rollback_verification", "metadata"):
            payload.setdefault(key, {})
        item = cls(**payload)
        item.validate()
        return item


Runner = Callable[[Sequence[str], float], subprocess.CompletedProcess[str]]


class VirtualLabExecutor:
    """Execute a previously approved recommendation only inside a named containerlab lab.

    The executor has no production-device transport. It accepts only an allowlisted
    command family, never invokes a shell, verifies a fixed HTTP service from the lab
    client, performs readback, and rolls the change back by default.
    """

    ALLOWED_PROGRAMS = {
        "FIREWALL_POLICY": "nft",
        "ROUTE": "vtysh",
        "VLAN": "ovs-vsctl",
    }

    def __init__(
        self,
        *,
        runtime: str = "docker",
        lab_name: str = "kansoku-v100",
        timeout: float = 15.0,
        runner: Optional[Runner] = None,
    ):
        if runtime not in {"docker", "podman"}:
            raise ValueError("runtime must be docker or podman")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", lab_name):
            raise ValueError("lab_name contains unsupported characters")
        self.runtime = runtime
        self.lab_name = lab_name
        self.timeout = timeout
        self.runner = runner or self._default_runner

    @staticmethod
    def _default_runner(argv: Sequence[str], timeout: float) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            list(argv), capture_output=True, text=True, timeout=timeout, check=False,
        )

    def _container(self, node: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", node):
            raise ValueError("node contains unsupported characters")
        return f"clab-{self.lab_name}-{node}"

    @staticmethod
    def _command_tokens(command: str) -> List[str]:
        tokens = shlex.split(command)
        if not tokens:
            raise ValueError("empty command is not allowed")

        # The executor deliberately bypasses a shell. nft parses its own
        # command language after argv has been reconstructed, so nft string
        # literals such as comments must retain literal quote characters.
        if tokens[0] == "nft":
            for index, token in enumerate(tokens[:-1]):
                if token == "comment":
                    value = tokens[index + 1]
                    if not (
                        len(value) >= 2
                        and value.startswith('"')
                        and value.endswith('"')
                    ):
                        tokens[index + 1] = json.dumps(value)

        return tokens

    def _execute(self, node: str, command: str) -> CommandExecution:
        tokens = self._command_tokens(command)
        argv = [self.runtime, "exec", self._container(node), *tokens]
        started_clock = time.monotonic()
        started_at = utc_now()
        completed = self.runner(argv, self.timeout)
        duration_ms = (time.monotonic() - started_clock) * 1000.0
        return CommandExecution(
            command=command,
            argv=list(argv),
            returncode=int(completed.returncode),
            stdout=completed.stdout or "",
            stderr=completed.stderr or "",
            started_at=started_at,
            finished_at=utc_now(),
            duration_ms=duration_ms,
        )

    def _validate_recommendation(self, item: ConfigurationRecommendation) -> None:
        item.validate()
        if item.status != "APPROVED":
            raise ValueError("recommendation must have status APPROVED before lab execution")
        require_approval_eligible(item)
        if item.category not in self.ALLOWED_PROGRAMS:
            raise ValueError(f"category is not executable in the virtual lab: {item.category}")
        if any("<" in command and ">" in command for command in item.commands):
            raise ValueError("apply command contains unresolved placeholders")
        expected_program = self.ALLOWED_PROGRAMS[item.category]
        for command in item.commands:
            tokens = self._command_tokens(command)
            if not tokens or tokens[0] != expected_program:
                raise ValueError(f"command is outside the {expected_program} allowlist")

    def _run_argv(self, argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
        return self.runner(list(argv), self.timeout)

    def _verify_service(self, *, client_node: str, verify_url: str, expect_success: bool) -> Dict[str, Any]:
        argv = [
            self.runtime, "exec", self._container(client_node),
            "curl", "-fsS", "--connect-timeout", "2", "--max-time", "5", verify_url,
        ]
        started = time.monotonic()
        completed = self._run_argv(argv)
        observed_success = completed.returncode == 0
        return {
            "argv": list(argv),
            "returncode": int(completed.returncode),
            "stdout": completed.stdout or "",
            "stderr": completed.stderr or "",
            "duration_ms": (time.monotonic() - started) * 1000.0,
            "expected_success": expect_success,
            "observed_success": observed_success,
            "passed": observed_success == expect_success,
        }

    def _readback(self, item: ConfigurationRecommendation) -> Dict[str, Any]:
        if item.category == "FIREWALL_POLICY":
            inner = ["nft", "-j", "list", "ruleset"]
        elif item.category == "ROUTE":
            inner = ["vtysh", "-c", "show ip route json"]
        else:
            inner = ["ovs-vsctl", "--format=json", "--columns=name,tag,trunks,interfaces", "list", "Port"]
        argv = [self.runtime, "exec", self._container(item.device_id), *inner]
        completed = self._run_argv(argv)
        return {
            "argv": argv,
            "returncode": int(completed.returncode),
            "stdout": (completed.stdout or "")[:20000],
            "stderr": (completed.stderr or "")[:4000],
            "read_only": True,
        }

    def _resolve_firewall_handle(self, item: ConfigurationRecommendation) -> Optional[str]:
        table = str(item.current_state.get("matched_rule", {}).get("table") or "filter")
        chain = str(item.current_state.get("matched_rule", {}).get("chain") or "forward")
        argv = [
            self.runtime, "exec", self._container(item.device_id),
            "nft", "-a", "list", "chain", "inet", table, chain,
        ]
        completed = self._run_argv(argv)
        if completed.returncode != 0:
            return None
        needle = f"kansoku {item.assessment_id}"
        for line in (completed.stdout or "").splitlines():
            if needle in line:
                match = re.search(r"#\s*handle\s+(\d+)", line)
                if match:
                    return match.group(1)
        return None

    def execute(
        self,
        recommendation: ConfigurationRecommendation,
        *,
        approved_by: str,
        environment: str = "virtual-lab",
        client_node: str = "client-a",
        verify_url: str = "http://10.20.20.10:443/",
        rollback_after_verify: bool = True,
    ) -> RemediationExecution:
        execution = RemediationExecution(
            recommendation_id=recommendation.recommendation_id,
            assessment_id=recommendation.assessment_id,
            environment=environment,
            lab_name=self.lab_name,
            device_id=recommendation.device_id,
            category=recommendation.category,
            approved_by=approved_by,
            status="PLANNED",
            metadata={
                "runtime": self.runtime,
                "verify_url": verify_url,
                "execution_boundary": "containerlab virtual lab only",
                "rollback_after_verify": rollback_after_verify,
            },
        )
        try:
            if environment != "virtual-lab":
                raise ValueError("only environment=virtual-lab is supported")
            if not approved_by.strip():
                raise ValueError("approved_by is required")
            self._validate_recommendation(recommendation)
            execution.status = "APPLYING"
            for command in recommendation.commands:
                result = self._execute(recommendation.device_id, command)
                execution.apply_results.append(result)
                if result.returncode != 0:
                    raise RuntimeError(f"apply command failed: {command}: {result.stderr.strip()}")

            rollback_commands = list(recommendation.rollback_commands)
            if recommendation.category == "FIREWALL_POLICY" and any("<new-rule-handle>" in item for item in rollback_commands):
                handle = self._resolve_firewall_handle(recommendation)
                if not handle:
                    raise RuntimeError("could not resolve the inserted nftables rule handle")
                rollback_commands = [item.replace("<new-rule-handle>", handle) for item in rollback_commands]
                execution.metadata["runtime_nft_handle"] = handle

            execution.readback = self._readback(recommendation)
            execution.verification = self._verify_service(
                client_node=client_node, verify_url=verify_url, expect_success=True,
            )
            if not execution.verification["passed"]:
                raise RuntimeError("post-change service verification failed")
            execution.status = "VERIFIED"

            if rollback_after_verify:
                for command in reversed(rollback_commands):
                    result = self._execute(recommendation.device_id, command)
                    execution.rollback_results.append(result)
                    if result.returncode != 0:
                        raise RuntimeError(f"rollback command failed: {command}: {result.stderr.strip()}")
                execution.rollback_verification = self._verify_service(
                    client_node=client_node, verify_url=verify_url, expect_success=False,
                )
                if not execution.rollback_verification["passed"]:
                    raise RuntimeError("rollback did not restore the injected fault")
                execution.status = "ROLLED_BACK"
        except Exception as exc:  # retain a complete execution audit record
            execution.error = str(exc)
            if execution.status == "PLANNED" and not execution.apply_results:
                execution.status = "REFUSED"
            elif execution.status not in {"ROLLED_BACK"}:
                execution.status = "FAILED"
            # Best-effort rollback after a partially applied change. Never use shell.
            if execution.apply_results and not execution.rollback_results:
                for command in reversed(recommendation.rollback_commands):
                    if "<new-rule-handle>" in command:
                        handle = self._resolve_firewall_handle(recommendation)
                        if not handle:
                            continue
                        command = command.replace("<new-rule-handle>", handle)
                    if "<" in command and ">" in command:
                        continue
                    try:
                        execution.rollback_results.append(self._execute(recommendation.device_id, command))
                    except Exception:
                        pass
        execution.finished_at = utc_now()
        execution.validate()
        return execution
