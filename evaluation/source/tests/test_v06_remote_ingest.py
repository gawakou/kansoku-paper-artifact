from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import tempfile
import threading
from urllib import error, request

import pytest

from kansoku.agent import SimulatedNetworkAgent
from kansoku.dashboard import make_handler
from kansoku.hub import Hub
from kansoku.ingest import create_ingest_server
from kansoku.remote import (
    AgentHeartbeat,
    IngestBatch,
    RemoteAgentRegistration,
    RemoteDeliveryError,
    RemoteHubClient,
    SpoolQueue,
)


def running_server(hub: Hub):
    server = create_ingest_server(hub, "127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def test_agent_token_hash_rotation_and_public_payload():
    agent, token = RemoteAgentRegistration.create(
        "Edge A", agent_id="edge-a", capabilities=["ping"], labels={"site": "lab"}
    )
    assert agent.verify_token(token)
    assert not agent.verify_token(token + "x")
    assert "token_hash" not in agent.to_dict()
    rotated, new_token = agent.rotate_token()
    assert not rotated.verify_token(token)
    assert rotated.verify_token(new_token)
    assert rotated.token_fingerprint != agent.token_fingerprint


def test_hub_remote_agent_heartbeat_and_migration_tables():
    with tempfile.TemporaryDirectory() as tmpdir:
        db = Path(tmpdir) / "legacy.db"
        with sqlite3.connect(db) as conn:
            conn.execute("CREATE TABLE observations (observation_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, target TEXT NOT NULL, source TEXT NOT NULL, domain TEXT NOT NULL, metric TEXT NOT NULL, value REAL NOT NULL, unit TEXT NOT NULL, method TEXT NOT NULL, payload TEXT NOT NULL)")
        hub = Hub(db)
        agent, _token = RemoteAgentRegistration.create("Edge", agent_id="edge")
        hub.set_remote_agent(agent)
        heartbeat = AgentHeartbeat(agent_id="edge", hostname="host", version="0.6.0", queue_depth=2)
        hub.add_agent_heartbeat(heartbeat)
        assert hub.latest_agent_heartbeat("edge").queue_depth == 2
        assert hub.get_remote_agent("edge").last_seen_at == heartbeat.timestamp
        with sqlite3.connect(db) as conn:
            tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"remote_agents", "agent_heartbeats", "ingest_batches"} <= tables


def test_authenticated_ingest_auto_evaluates_and_is_idempotent():
    with tempfile.TemporaryDirectory() as tmpdir:
        hub = Hub(Path(tmpdir) / "kansoku.db")
        agent, token = RemoteAgentRegistration.create("Edge", agent_id="edge")
        hub.set_remote_agent(agent)
        server, thread = running_server(hub)
        try:
            client = RemoteHubClient(
                f"http://127.0.0.1:{server.server_port}", "edge", token
            )
            observations = SimulatedNetworkAgent().observe("remote-path", profile="warning", count=2)
            batch = IngestBatch.from_collection("edge", observations)
            receipt = client.ingest(batch)
            assert receipt.status == "ACCEPTED"
            assert receipt.observation_count == len(observations)
            assert hub.latest_state("remote-path") is not None
            duplicate = client.ingest(batch)
            assert duplicate.status == "DUPLICATE"
            assert duplicate.duplicate is True
            assert len(hub.list_observations(target="remote-path", limit=100)) == len(observations)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


def test_ingest_rejects_bad_token_and_agent_mismatch():
    with tempfile.TemporaryDirectory() as tmpdir:
        hub = Hub(Path(tmpdir) / "kansoku.db")
        agent, token = RemoteAgentRegistration.create("Edge", agent_id="edge")
        hub.set_remote_agent(agent)
        server, thread = running_server(hub)
        try:
            bad = RemoteHubClient(f"http://127.0.0.1:{server.server_port}", "edge", "wrong")
            with pytest.raises(RemoteDeliveryError, match="HTTP 401"):
                bad.ingest(IngestBatch.from_collection("edge", []))
            mismatch = RemoteHubClient(f"http://127.0.0.1:{server.server_port}", "edge", token)
            with pytest.raises(RemoteDeliveryError, match="HTTP 403"):
                mismatch.ingest(IngestBatch.from_collection("other", []))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


def test_disabled_agent_is_rejected():
    with tempfile.TemporaryDirectory() as tmpdir:
        hub = Hub(Path(tmpdir) / "kansoku.db")
        agent, token = RemoteAgentRegistration.create("Edge", agent_id="edge")
        hub.set_remote_agent(agent.updated(enabled=False))
        server, thread = running_server(hub)
        try:
            client = RemoteHubClient(f"http://127.0.0.1:{server.server_port}", "edge", token)
            with pytest.raises(RemoteDeliveryError, match="HTTP 401"):
                client.heartbeat(AgentHeartbeat(agent_id="edge", hostname="h", version="0.6.0"))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


def test_spool_preserves_failed_batch_then_flushes_fifo():
    with tempfile.TemporaryDirectory() as tmpdir:
        spool = SpoolQueue(Path(tmpdir) / "spool")
        batch = IngestBatch.from_collection(
            "edge", SimulatedNetworkAgent().observe("path", profile="normal", count=1)
        )
        path = spool.enqueue(batch)
        assert path.exists() and spool.count() == 1
        offline = RemoteHubClient("http://127.0.0.1:1", "edge", "token", timeout=0.1)
        failed = spool.flush(offline)
        assert failed["remaining"] == 1
        assert failed["failed"]

        hub = Hub(Path(tmpdir) / "hub.db")
        agent, token = RemoteAgentRegistration.create("Edge", agent_id="edge")
        hub.set_remote_agent(agent)
        server, thread = running_server(hub)
        try:
            client = RemoteHubClient(f"http://127.0.0.1:{server.server_port}", "edge", token)
            delivered = spool.flush(client)
            assert delivered["delivered"] == [batch.batch_id]
            assert delivered["remaining"] == 0
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


def test_heartbeat_updates_queue_depth_and_last_seen():
    with tempfile.TemporaryDirectory() as tmpdir:
        hub = Hub(Path(tmpdir) / "hub.db")
        agent, token = RemoteAgentRegistration.create("Edge", agent_id="edge")
        hub.set_remote_agent(agent)
        server, thread = running_server(hub)
        try:
            client = RemoteHubClient(f"http://127.0.0.1:{server.server_port}", "edge", token)
            response = client.heartbeat(
                AgentHeartbeat(agent_id="edge", hostname="mac", version="0.6.0", queue_depth=4)
            )
            assert response["status"] == "accepted"
            assert hub.latest_agent_heartbeat("edge").queue_depth == 4
            assert hub.get_remote_agent("edge").last_seen_at is not None
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


def test_dashboard_agents_api_exposes_no_token_material():
    with tempfile.TemporaryDirectory() as tmpdir:
        hub = Hub(Path(tmpdir) / "hub.db")
        agent, _token = RemoteAgentRegistration.create("Edge", agent_id="edge")
        hub.set_remote_agent(agent)
        heartbeat = AgentHeartbeat(agent_id="edge", hostname="h", version="0.6.0")
        hub.add_agent_heartbeat(heartbeat)
        from http.server import ThreadingHTTPServer
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(hub))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with request.urlopen(f"http://127.0.0.1:{server.server_port}/api/agents") as response:
                payload = json.loads(response.read())
            raw = json.dumps(payload)
            assert payload["agents"][0]["agent"]["agent_id"] == "edge"
            assert "token_hash" not in raw
            assert "token_salt" not in raw
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


def test_cli_remote_agent_and_offline_edge_spool(capsys):
    from kansoku.cli import main
    with tempfile.TemporaryDirectory() as tmpdir:
        db = str(Path(tmpdir) / "hub.db")
        token_file = str(Path(tmpdir) / "edge.agent-token")
        spool_dir = str(Path(tmpdir) / "spool")
        assert main([
            "--db", db, "remote-agent", "create", "--name", "CLI Edge",
            "--agent-id", "cli-edge", "--label", "site=lab", "--token-file", token_file,
        ]) == 0
        assert Path(token_file).exists()
        assert Hub(db).get_remote_agent("cli-edge").labels == {"site": "lab"}
        assert main([
            "edge", "simulate", "--agent-id", "cli-edge", "--spool-dir", spool_dir,
            "--target", "offline-target", "--profile", "normal", "--spool-only",
        ]) == 0
        assert SpoolQueue(spool_dir).count() == 1
        assert main(["edge", "status", "--spool-dir", spool_dir]) == 0


def test_cli_agent_disable_and_rotate_token():
    from kansoku.cli import main
    with tempfile.TemporaryDirectory() as tmpdir:
        db = str(Path(tmpdir) / "hub.db")
        first = str(Path(tmpdir) / "first.agent-token")
        second = str(Path(tmpdir) / "second.agent-token")
        assert main(["--db", db, "remote-agent", "create", "--name", "Edge", "--agent-id", "edge", "--token-file", first]) == 0
        old_token = Path(first).read_text().strip()
        assert main(["--db", db, "remote-agent", "disable", "--agent-id", "edge"]) == 0
        assert Hub(db).get_remote_agent("edge").enabled is False
        assert main(["--db", db, "remote-agent", "rotate-token", "--agent-id", "edge", "--token-file", second]) == 0
        agent = Hub(db).get_remote_agent("edge")
        assert not agent.verify_token(old_token)
        assert agent.verify_token(Path(second).read_text().strip())
