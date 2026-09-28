from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib import error, request

from .models import CollectionRun, Observation, new_id, utc_now
from .capture import CaptureSession, FlowRecord

PBKDF2_ITERATIONS = 200_000


def _utc_timestamp(value: Optional[str] = None) -> datetime:
    if value:
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    return datetime.now(timezone.utc)


def parse_labels(values: Optional[Iterable[str]]) -> Dict[str, str]:
    labels: Dict[str, str] = {}
    for value in values or []:
        if "=" not in value:
            raise ValueError(f"label must use key=value syntax: {value}")
        key, item = value.split("=", 1)
        key = key.strip()
        if not key:
            raise ValueError("label key must not be empty")
        labels[key] = item.strip()
    return labels


def token_fingerprint(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]


def _derive_token_hash(token: str, salt_hex: str, iterations: int) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256",
        token.encode("utf-8"),
        bytes.fromhex(salt_hex),
        iterations,
    ).hex()


@dataclass
class RemoteAgentRegistration:
    agent_id: str
    name: str
    token_salt: str
    token_hash: str
    token_iterations: int = PBKDF2_ITERATIONS
    token_fingerprint: str = ""
    enabled: bool = True
    capabilities: List[str] = field(default_factory=list)
    labels: Dict[str, str] = field(default_factory=dict)
    created_at: str = field(default_factory=utc_now)
    updated_at: str = field(default_factory=utc_now)
    last_seen_at: Optional[str] = None

    @classmethod
    def create(
        cls,
        name: str,
        *,
        agent_id: Optional[str] = None,
        capabilities: Optional[Iterable[str]] = None,
        labels: Optional[Dict[str, str]] = None,
    ) -> Tuple["RemoteAgentRegistration", str]:
        if not name.strip():
            raise ValueError("name must not be empty")
        token = secrets.token_urlsafe(32)
        salt = secrets.token_hex(16)
        registration = cls(
            agent_id=agent_id or new_id("agent"),
            name=name.strip(),
            token_salt=salt,
            token_hash=_derive_token_hash(token, salt, PBKDF2_ITERATIONS),
            token_fingerprint=token_fingerprint(token),
            capabilities=sorted(set(capabilities or [])),
            labels=dict(labels or {}),
        )
        registration.validate()
        return registration, token

    def validate(self) -> None:
        if not self.agent_id.strip():
            raise ValueError("agent_id must not be empty")
        if not self.name.strip():
            raise ValueError("name must not be empty")
        if self.token_iterations < 100_000:
            raise ValueError("token_iterations is below the supported security floor")
        if not self.token_salt or not self.token_hash:
            raise ValueError("token hash material is incomplete")

    def verify_token(self, token: str) -> bool:
        if not token:
            return False
        candidate = _derive_token_hash(token, self.token_salt, self.token_iterations)
        return hmac.compare_digest(candidate, self.token_hash)

    def rotate_token(self) -> Tuple["RemoteAgentRegistration", str]:
        token = secrets.token_urlsafe(32)
        salt = secrets.token_hex(16)
        return (
            replace(
                self,
                token_salt=salt,
                token_hash=_derive_token_hash(token, salt, self.token_iterations),
                token_fingerprint=token_fingerprint(token),
                updated_at=utc_now(),
            ),
            token,
        )

    def updated(self, **changes: Any) -> "RemoteAgentRegistration":
        item = replace(self, **changes, updated_at=utc_now())
        item.validate()
        return item

    def to_storage_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload.pop("token_salt", None)
        payload.pop("token_hash", None)
        payload.pop("token_iterations", None)
        return payload

    @classmethod
    def from_storage_dict(cls, data: Dict[str, Any]) -> "RemoteAgentRegistration":
        return cls(**data)


@dataclass
class AgentHeartbeat:
    agent_id: str
    hostname: str
    version: str
    status: str = "ONLINE"
    queue_depth: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)
    heartbeat_id: str = field(default_factory=lambda: new_id("heartbeat"))
    timestamp: str = field(default_factory=utc_now)

    def validate(self) -> None:
        if not self.agent_id.strip():
            raise ValueError("agent_id must not be empty")
        if self.queue_depth < 0:
            raise ValueError("queue_depth must be >= 0")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentHeartbeat":
        item = cls(**data)
        item.validate()
        return item


@dataclass
class IngestBatch:
    agent_id: str
    observations: List[Dict[str, Any]] = field(default_factory=list)
    runs: List[Dict[str, Any]] = field(default_factory=list)
    captures: List[Dict[str, Any]] = field(default_factory=list)
    flows: List[Dict[str, Any]] = field(default_factory=list)
    batch_id: str = field(default_factory=lambda: new_id("batch"))
    sent_at: str = field(default_factory=utc_now)

    def validate(
        self, *, max_observations: int = 10_000, max_runs: int = 1_000,
        max_captures: int = 100, max_flows: int = 20_000,
    ) -> None:
        if not self.agent_id.strip():
            raise ValueError("agent_id must not be empty")
        if len(self.observations) > max_observations:
            raise ValueError(f"batch exceeds maximum observations: {max_observations}")
        if len(self.runs) > max_runs:
            raise ValueError(f"batch exceeds maximum collection runs: {max_runs}")
        if len(self.captures) > max_captures:
            raise ValueError(f"batch exceeds maximum captures: {max_captures}")
        if len(self.flows) > max_flows:
            raise ValueError(f"batch exceeds maximum flows: {max_flows}")
        _utc_timestamp(self.sent_at)

    def parsed_observations(self) -> List[Observation]:
        return [Observation.from_dict(item) for item in self.observations]

    def parsed_runs(self) -> List[CollectionRun]:
        return [CollectionRun.from_dict(item) for item in self.runs]

    def parsed_captures(self) -> List[CaptureSession]:
        return [CaptureSession.from_dict(item) for item in self.captures]

    def parsed_flows(self) -> List[FlowRecord]:
        return [FlowRecord.from_dict(item) for item in self.flows]

    def targets(self) -> List[str]:
        values = {str(item.get("target", "")) for item in self.observations if item.get("target")}
        values.update(str(item.get("target", "")) for item in self.captures if item.get("target"))
        values.update(str(item.get("target", "")) for item in self.flows if item.get("target"))
        return sorted(values)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "IngestBatch":
        item = cls(**data)
        item.validate()
        return item

    @classmethod
    def from_collection(
        cls,
        agent_id: str,
        observations: Iterable[Observation],
        runs: Iterable[CollectionRun] = (),
        captures: Iterable[CaptureSession] = (),
        flows: Iterable[FlowRecord] = (),
    ) -> "IngestBatch":
        return cls(
            agent_id=agent_id,
            observations=[item.to_dict() for item in observations],
            runs=[item.to_dict() for item in runs],
            captures=[item.to_dict() for item in captures],
            flows=[item.to_dict() for item in flows],
        )


@dataclass
class IngestReceipt:
    batch_id: str
    agent_id: str
    status: str
    observation_count: int
    run_count: int
    capture_count: int = 0
    flow_count: int = 0
    targets: List[str] = field(default_factory=list)
    duplicate: bool = False
    message: str = ""
    received_at: str = field(default_factory=utc_now)
    receipt_id: str = field(default_factory=lambda: new_id("receipt"))

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "IngestReceipt":
        return cls(**{"capture_count": 0, "flow_count": 0, **data})


class RemoteDeliveryError(RuntimeError):
    pass


class RemoteHubClient:
    def __init__(
        self,
        hub_url: str,
        agent_id: str,
        token: str,
        *,
        timeout: float = 10.0,
    ):
        self.hub_url = hub_url.rstrip("/")
        self.agent_id = agent_id
        self.token = token
        self.timeout = timeout

    def _post(self, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = request.Request(
            f"{self.hub_url}{path}",
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {self.token}",
                "X-KANSOKU-Agent": self.agent_id,
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "KANSOKU-edge/0.7",
            },
        )
        try:
            with request.urlopen(req, timeout=self.timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RemoteDeliveryError(f"hub returned HTTP {exc.code}: {detail}") from exc
        except (error.URLError, TimeoutError, OSError) as exc:
            raise RemoteDeliveryError(f"unable to reach remote hub: {exc}") from exc

    def heartbeat(self, heartbeat: AgentHeartbeat) -> Dict[str, Any]:
        return self._post("/api/v1/heartbeat", heartbeat.to_dict())

    def ingest(self, batch: IngestBatch) -> IngestReceipt:
        payload = self._post("/api/v1/ingest", batch.to_dict())
        return IngestReceipt.from_dict(payload["receipt"])


class SpoolQueue:
    def __init__(self, directory: str | Path):
        self.directory = Path(directory).expanduser()
        self.directory.mkdir(parents=True, exist_ok=True)
        try:
            self.directory.chmod(0o700)
        except OSError:
            pass

    def _path(self, batch_id: str) -> Path:
        return self.directory / f"{batch_id}.json"

    def enqueue(self, batch: IngestBatch) -> Path:
        batch.validate()
        final_path = self._path(batch.batch_id)
        temp_path = self.directory / f".{batch.batch_id}.{os.getpid()}.tmp"
        temp_path.write_text(json.dumps(batch.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
        try:
            temp_path.chmod(0o600)
        except OSError:
            pass
        temp_path.replace(final_path)
        return final_path

    def list_paths(self) -> List[Path]:
        return sorted(self.directory.glob("batch-*.json"), key=lambda item: item.stat().st_mtime)

    def count(self) -> int:
        return len(self.list_paths())

    def load(self, path: Path) -> IngestBatch:
        return IngestBatch.from_dict(json.loads(path.read_text(encoding="utf-8")))

    def flush(self, client: RemoteHubClient, *, limit: int = 100) -> Dict[str, Any]:
        delivered: List[str] = []
        failed: List[Dict[str, str]] = []
        for path in self.list_paths()[: max(1, limit)]:
            try:
                batch = self.load(path)
                receipt = client.ingest(batch)
                if receipt.status not in {"ACCEPTED", "DUPLICATE"}:
                    raise RemoteDeliveryError(f"unexpected receipt status={receipt.status}")
                path.unlink(missing_ok=True)
                delivered.append(batch.batch_id)
            except (RemoteDeliveryError, ValueError, json.JSONDecodeError, OSError) as exc:
                failed.append({"path": str(path), "error": str(exc)})
                break  # preserve FIFO ordering
        return {
            "delivered": delivered,
            "failed": failed,
            "remaining": self.count(),
        }
