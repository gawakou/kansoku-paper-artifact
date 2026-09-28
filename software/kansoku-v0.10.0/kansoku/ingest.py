from __future__ import annotations

from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

from .hub import Hub
from .remote import AgentHeartbeat, IngestBatch
from .workflow import evaluate_and_persist


class IngestAPIError(RuntimeError):
    def __init__(self, status: HTTPStatus, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def _bearer_token(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    scheme, _, token = value.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


def make_ingest_handler(
    hub: Hub,
    *,
    max_body_bytes: int = 4 * 1024 * 1024,
    auto_evaluate: bool = True,
):
    class IngestHandler(BaseHTTPRequestHandler):
        server_version = "KANSOKU-Ingest/0.8"

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            if parsed.path == "/health":
                self._json(
                    {
                        "status": "ok",
                        "service": "kansoku-ingest",
                        "version": "0.10.0",
                    }
                )
                return
            self._json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)

        def do_POST(self) -> None:  # noqa: N802
            try:
                agent_id, _registration = self._authenticate()
                payload = self._read_json()
                parsed = urlparse(self.path)
                if parsed.path == "/api/v1/heartbeat":
                    heartbeat = AgentHeartbeat.from_dict(payload)
                    if heartbeat.agent_id != agent_id:
                        raise IngestAPIError(
                            HTTPStatus.FORBIDDEN,
                            "heartbeat agent_id does not match authenticated agent",
                        )
                    hub.add_agent_heartbeat(heartbeat)
                    self._json({"status": "accepted", "heartbeat": heartbeat.to_dict()})
                    return
                if parsed.path == "/api/v1/ingest":
                    batch = IngestBatch.from_dict(payload)
                    if batch.agent_id != agent_id:
                        raise IngestAPIError(
                            HTTPStatus.FORBIDDEN,
                            "batch agent_id does not match authenticated agent",
                        )
                    receipt = hub.ingest_remote_batch(batch)
                    evaluated: list[Dict[str, Any]] = []
                    if auto_evaluate and not receipt.duplicate:
                        state_metrics = {
                            "rtt_ms", "packet_loss_pct", "throughput_mbps",
                            "reachability", "retransmits",
                        }
                        evaluable_targets = {
                            str(item.get("target"))
                            for item in batch.observations
                            if item.get("target") and item.get("metric") in state_metrics
                        }
                        for target in receipt.targets:
                            if target not in evaluable_targets:
                                evaluated.append({
                                    "target": target,
                                    "state": None,
                                    "state_id": None,
                                    "proposal_id": None,
                                    "skipped": "no state-engine metrics in batch",
                                })
                                continue
                            outcome = evaluate_and_persist(hub, target)
                            evaluated.append(
                                {
                                    "target": target,
                                    "state": outcome.state.state,
                                    "state_id": outcome.state.state_id,
                                    "proposal_id": (
                                        outcome.proposal.proposal_id if outcome.proposal else None
                                    ),
                                }
                            )
                    self._json({"receipt": receipt.to_dict(), "evaluated": evaluated})
                    return
                raise IngestAPIError(HTTPStatus.NOT_FOUND, "not found")
            except IngestAPIError as exc:
                self._json({"error": exc.message}, status=exc.status)
            except (ValueError, TypeError, json.JSONDecodeError) as exc:
                self._json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
            except Exception as exc:  # defensive API boundary
                self._json(
                    {"error": "internal ingest error", "detail": str(exc)},
                    status=HTTPStatus.INTERNAL_SERVER_ERROR,
                )

        def _authenticate(self) -> Tuple[str, Any]:
            agent_id = (self.headers.get("X-KANSOKU-Agent") or "").strip()
            token = _bearer_token(self.headers.get("Authorization"))
            if not agent_id or not token:
                raise IngestAPIError(
                    HTTPStatus.UNAUTHORIZED,
                    "X-KANSOKU-Agent and Bearer token are required",
                )
            registration = hub.get_remote_agent(agent_id)
            if not registration or not registration.enabled:
                raise IngestAPIError(HTTPStatus.UNAUTHORIZED, "agent is unknown or disabled")
            if not registration.verify_token(token):
                raise IngestAPIError(HTTPStatus.UNAUTHORIZED, "invalid agent token")
            return agent_id, registration

        def _read_json(self) -> Dict[str, Any]:
            content_type = self.headers.get("Content-Type", "")
            if "application/json" not in content_type.lower():
                raise IngestAPIError(
                    HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                    "Content-Type must be application/json",
                )
            raw_length = self.headers.get("Content-Length")
            if not raw_length:
                raise IngestAPIError(HTTPStatus.LENGTH_REQUIRED, "Content-Length is required")
            try:
                length = int(raw_length)
            except ValueError as exc:
                raise IngestAPIError(HTTPStatus.BAD_REQUEST, "invalid Content-Length") from exc
            if length < 0 or length > max_body_bytes:
                raise IngestAPIError(
                    HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                    f"request body exceeds {max_body_bytes} bytes",
                )
            body = self.rfile.read(length)
            payload = json.loads(body.decode("utf-8"))
            if not isinstance(payload, dict):
                raise IngestAPIError(HTTPStatus.BAD_REQUEST, "JSON body must be an object")
            return payload

        def _json(self, payload: Dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status.value)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt: str, *args: object) -> None:
            return

    return IngestHandler


def create_ingest_server(
    hub: Hub,
    host: str = "127.0.0.1",
    port: int = 8090,
    *,
    max_body_bytes: int = 4 * 1024 * 1024,
    auto_evaluate: bool = True,
) -> ThreadingHTTPServer:
    return ThreadingHTTPServer(
        (host, port),
        make_ingest_handler(
            hub,
            max_body_bytes=max_body_bytes,
            auto_evaluate=auto_evaluate,
        ),
    )


def serve_ingest(
    hub: Hub,
    host: str = "127.0.0.1",
    port: int = 8090,
    *,
    max_body_bytes: int = 4 * 1024 * 1024,
    auto_evaluate: bool = True,
) -> None:
    server = create_ingest_server(
        hub,
        host,
        port,
        max_body_bytes=max_body_bytes,
        auto_evaluate=auto_evaluate,
    )
    print(f"KANSOKU ingest API: http://{host}:{server.server_port}")
    if host not in {"127.0.0.1", "localhost", "::1"}:
        print("WARNING: the ingest API uses bearer tokens but no TLS; place it behind HTTPS.")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
