from __future__ import annotations

from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import socket
import sqlite3
import struct
import tempfile
import threading
from urllib import request

from kansoku.capture import (
    CaptureRetentionManager,
    CaptureSession,
    build_tcpdump_command,
    summarize_pcap,
)
from kansoku.dashboard import build_snapshot, make_handler
from kansoku.hub import Hub
from kansoku.ingest import create_ingest_server
from kansoku.remote import IngestBatch, RemoteAgentRegistration, RemoteHubClient
from kansoku.sample_pcap import generate_sample_pcap, internet_checksum


def write_sample_pcap(path: Path) -> Path:
    return generate_sample_pcap(path)


def _read_ethernet_packets(path: Path) -> list[bytes]:
    packets: list[bytes] = []
    with path.open("rb") as handle:
        header = handle.read(24)
        assert len(header) == 24
        assert header[:4] == b"\xd4\xc3\xb2\xa1"
        while True:
            record = handle.read(16)
            if not record:
                break
            _ts_sec, _ts_usec, incl_len, _orig_len = struct.unpack("<IIII", record)
            packets.append(handle.read(incl_len))
    return packets


def _network_payload(frame: bytes) -> bytes:
    ethertype = struct.unpack("!H", frame[12:14])[0]
    offset = 14
    if ethertype == 0x8100:
        ethertype = struct.unpack("!H", frame[16:18])[0]
        offset = 18
    assert ethertype == 0x0800
    return frame[offset:]


def running_server(hub: Hub):
    server = create_ingest_server(hub, "127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def test_pcap_parser_aggregates_flows_and_privacy_metadata():
    with tempfile.TemporaryDirectory() as tmpdir:
        pcap = write_sample_pcap(Path(tmpdir) / "sample.pcap")
        summary = summarize_pcap(pcap, target="path-a", source="sensor-a")
        assert summary.session.packet_count == 4
        assert summary.session.flow_count == 3
        assert summary.session.metadata["tcp_packets"] == 3
        assert summary.session.metadata["udp_packets"] == 1
        assert summary.session.linktype == 1
        assert len(summary.session.sha256) == 64
        top = summary.flows[0]
        assert top.src_ip == "10.0.0.1"
        assert top.dst_port == 443
        assert top.packets == 2
        udp = [item for item in summary.flows if item.protocol == "UDP"][0]
        assert udp.vlan_id == 10
        metrics = {item.metric: item.value for item in summary.observations}
        assert metrics["capture_packet_count"] == 4
        assert metrics["capture_unique_flows"] == 3


def test_hub_capture_flow_migration_and_dashboard_snapshot():
    with tempfile.TemporaryDirectory() as tmpdir:
        db = Path(tmpdir) / "legacy.db"
        with sqlite3.connect(db) as conn:
            conn.execute("CREATE TABLE observations (observation_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, target TEXT NOT NULL, source TEXT NOT NULL, domain TEXT NOT NULL, metric TEXT NOT NULL, value REAL NOT NULL, unit TEXT NOT NULL, method TEXT NOT NULL, payload TEXT NOT NULL)")
        hub = Hub(db)
        summary = summarize_pcap(write_sample_pcap(Path(tmpdir) / "sample.pcap"), target="path-a")
        hub.add_capture_session(summary.session)
        hub.add_flow_records(summary.flows)
        hub.add_observations(summary.observations)
        assert hub.get_capture_session(summary.session.capture_id).packet_count == 4
        assert len(hub.list_flow_records(capture_id=summary.session.capture_id)) == 3
        snapshot = build_snapshot(hub, "path-a")
        assert snapshot["captures"][0]["capture_id"] == summary.session.capture_id
        assert snapshot["flows"][0]["packets"] == 2
        with sqlite3.connect(db) as conn:
            tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"capture_sessions", "flow_records"} <= tables


def test_remote_ingest_accepts_capture_metadata_and_flows_idempotently():
    with tempfile.TemporaryDirectory() as tmpdir:
        hub = Hub(Path(tmpdir) / "hub.db")
        agent, token = RemoteAgentRegistration.create("Capture Edge", agent_id="edge-cap")
        hub.set_remote_agent(agent)
        summary = summarize_pcap(
            write_sample_pcap(Path(tmpdir) / "sample.pcap"),
            target="remote-path",
            storage_scope="edge",
        )
        summary.session = summary.session.updated(storage_scope="edge")
        batch = IngestBatch.from_collection(
            "edge-cap", summary.observations, captures=[summary.session], flows=summary.flows
        )
        server, thread = running_server(hub)
        try:
            client = RemoteHubClient(f"http://127.0.0.1:{server.server_port}", "edge-cap", token)
            receipt = client.ingest(batch)
            assert receipt.capture_count == 1
            assert receipt.flow_count == 3
            assert hub.get_capture_session(summary.session.capture_id).storage_scope == "edge"
            assert len(hub.list_flow_records(target="remote-path")) == 3
            assert hub.latest_state("remote-path") is None
            duplicate = client.ingest(batch)
            assert duplicate.duplicate is True
            assert duplicate.capture_count == 1
            assert len(hub.list_capture_sessions(target="remote-path")) == 1
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


def test_capture_retention_prunes_expired_and_quota_files():
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        now = datetime.now(timezone.utc)
        old_file = root / "old.pcap"
        new_file = root / "new.pcap"
        old_file.write_bytes(b"x" * 100)
        new_file.write_bytes(b"y" * 100)
        common = dict(
            target="t", source="s", interface="i", bpf_filter="", snaplen=96,
            privacy_mode="headers-only", status="CAPTURED", packet_count=1,
            captured_bytes=1, wire_bytes=1, flow_count=1, file_size=100, sha256="x",
            linktype=1, duration_sec=1.0, retention_days=7, storage_scope="local",
        )
        old = CaptureSession(
            **common, pcap_path=str(old_file), started_at=(now - timedelta(days=10)).isoformat(),
            finished_at=(now - timedelta(days=10)).isoformat(),
        )
        new = CaptureSession(
            **common, pcap_path=str(new_file), started_at=now.isoformat(), finished_at=now.isoformat(),
        )
        result = CaptureRetentionManager(root).prune(
            [old, new], retention_days=7, quota_bytes=100, now=now
        )
        assert not old_file.exists()
        assert new_file.exists()
        assert result["deleted"][0]["reason"] == "retention"


def test_tcpdump_command_is_header_only_and_bpf_safe_by_default():
    command = build_tcpdump_command(
        interface="en0",
        output_path="capture.pcap",
        snaplen=96,
        packet_limit=10,
        bpf_filter="tcp port 443 and host 10.0.0.2",
    )
    assert command[:8] == ["tcpdump", "-i", "en0", "-U", "-n", "-s", "96", "-w"]
    assert "capture.pcap" in command
    assert command[-6:] == ["tcp", "port", "443", "and", "host", "10.0.0.2"]


def test_cli_pcap_summary_persists_capture_and_flows(capsys):
    from kansoku.cli import main
    with tempfile.TemporaryDirectory() as tmpdir:
        db = str(Path(tmpdir) / "kansoku.db")
        pcap = str(write_sample_pcap(Path(tmpdir) / "sample.pcap"))
        assert main(["--db", db, "capture", "summarize", "--pcap", pcap, "--target", "cli-path"]) == 0
        captured = json.loads(capsys.readouterr().out)
        assert captured["capture"]["packet_count"] == 4
        hub = Hub(db)
        assert len(hub.list_capture_sessions(target="cli-path")) == 1
        assert len(hub.list_flow_records(target="cli-path")) == 3


def test_dashboard_capture_api():
    with tempfile.TemporaryDirectory() as tmpdir:
        hub = Hub(Path(tmpdir) / "hub.db")
        summary = summarize_pcap(write_sample_pcap(Path(tmpdir) / "sample.pcap"), target="path-a")
        hub.add_capture_session(summary.session)
        hub.add_flow_records(summary.flows)
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(hub))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with request.urlopen(f"http://127.0.0.1:{server.server_port}/api/captures/{summary.session.capture_id}") as response:
                payload = json.loads(response.read())
            assert payload["capture"]["packet_count"] == 4
            assert len(payload["flows"]) == 3
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


def test_generated_sample_pcap_has_valid_checksums_and_dns_query():
    with tempfile.TemporaryDirectory() as tmpdir:
        pcap = generate_sample_pcap(Path(tmpdir) / "sample.pcap")
        packets = _read_ethernet_packets(pcap)
        assert len(packets) == 4
        for frame in packets:
            ip = _network_payload(frame)
            ihl = (ip[0] & 0x0F) * 4
            assert internet_checksum(ip[:ihl]) == 0
            protocol = ip[9]
            src = ip[12:16]
            dst = ip[16:20]
            transport = ip[ihl:]
            pseudo = src + dst + struct.pack("!BBH", 0, protocol, len(transport))
            assert internet_checksum(pseudo + transport) == 0
        udp_ip = _network_payload(packets[-1])
        udp_payload = udp_ip[20 + 8 :]
        assert len(udp_payload) >= 12
        transaction_id, flags, qdcount, ancount, nscount, arcount = struct.unpack(
            "!HHHHHH", udp_payload[:12]
        )
        assert transaction_id == 0
        assert flags == 0
        assert (qdcount, ancount, nscount, arcount) == (1, 0, 0, 0)
        assert b"_services" in udp_payload


def test_cli_duplicate_capture_is_idempotent_and_force_reimport_is_explicit(capsys):
    from kansoku.cli import main
    with tempfile.TemporaryDirectory() as tmpdir:
        db = str(Path(tmpdir) / "kansoku.db")
        pcap = str(generate_sample_pcap(Path(tmpdir) / "sample.pcap"))
        base = [
            "--db", db, "capture", "summarize", "--pcap", pcap,
            "--target", "dedupe-path", "--source", "sensor-a",
        ]
        assert main(base) == 0
        first = json.loads(capsys.readouterr().out)
        assert first["import_status"] == "IMPORTED"
        assert main(base) == 0
        duplicate = json.loads(capsys.readouterr().out)
        assert duplicate["import_status"] == "DUPLICATE"
        assert duplicate["duplicate_of"] == first["capture"]["capture_id"]
        hub = Hub(db)
        assert len(hub.list_capture_sessions(target="dedupe-path")) == 1
        assert len(hub.list_flow_records(target="dedupe-path")) == 3
        assert len(hub.list_observations(target="dedupe-path", limit=100)) == 8

        assert main(base + ["--force-reimport"]) == 0
        forced = json.loads(capsys.readouterr().out)
        assert forced["import_status"] == "FORCE_IMPORTED"
        assert len(hub.list_capture_sessions(target="dedupe-path")) == 2
        assert len(hub.list_flow_records(target="dedupe-path")) == 6
        assert len(hub.list_observations(target="dedupe-path", limit=100)) == 16


def test_remote_ingest_deduplicates_same_capture_across_different_batches():
    with tempfile.TemporaryDirectory() as tmpdir:
        hub = Hub(Path(tmpdir) / "hub.db")
        agent, token = RemoteAgentRegistration.create("Capture Edge", agent_id="edge-dedupe")
        hub.set_remote_agent(agent)
        pcap = generate_sample_pcap(Path(tmpdir) / "sample.pcap")
        first_summary = summarize_pcap(
            pcap, target="remote-dedupe", source="edge-sensor", storage_scope="edge"
        )
        second_summary = summarize_pcap(
            pcap, target="remote-dedupe", source="edge-sensor", storage_scope="edge"
        )
        first_batch = IngestBatch.from_collection(
            "edge-dedupe", first_summary.observations,
            captures=[first_summary.session], flows=first_summary.flows,
        )
        second_batch = IngestBatch.from_collection(
            "edge-dedupe", second_summary.observations,
            captures=[second_summary.session], flows=second_summary.flows,
        )
        server, thread = running_server(hub)
        try:
            client = RemoteHubClient(
                f"http://127.0.0.1:{server.server_port}", "edge-dedupe", token
            )
            first = client.ingest(first_batch)
            second = client.ingest(second_batch)
            assert first.capture_count == 1
            assert second.duplicate is False
            assert second.capture_count == 0
            assert second.flow_count == 0
            assert "skipped 1 duplicate capture" in second.message
            assert len(hub.list_capture_sessions(target="remote-dedupe")) == 1
            assert len(hub.list_flow_records(target="remote-dedupe")) == 3
            assert len(hub.list_observations(target="remote-dedupe", limit=100)) == 8
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


def test_legacy_v07_capture_table_migrates_fingerprints_with_duplicates():
    with tempfile.TemporaryDirectory() as tmpdir:
        db = Path(tmpdir) / "legacy-v07.db"
        pcap = generate_sample_pcap(Path(tmpdir) / "sample.pcap")
        first = summarize_pcap(pcap, target="legacy-path", source="legacy-sensor")
        second = summarize_pcap(pcap, target="legacy-path", source="legacy-sensor")
        with sqlite3.connect(db) as conn:
            conn.execute(
                """CREATE TABLE capture_sessions (
                capture_id TEXT PRIMARY KEY, target TEXT NOT NULL, source TEXT NOT NULL,
                started_at TEXT NOT NULL, finished_at TEXT NOT NULL, status TEXT NOT NULL,
                packet_count INTEGER NOT NULL, flow_count INTEGER NOT NULL,
                file_size INTEGER NOT NULL, storage_scope TEXT NOT NULL, payload TEXT NOT NULL
                )"""
            )
            for session in (first.session, second.session):
                conn.execute(
                    """INSERT INTO capture_sessions
                    (capture_id,target,source,started_at,finished_at,status,packet_count,
                     flow_count,file_size,storage_scope,payload)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        session.capture_id,
                        session.target,
                        session.source,
                        session.started_at,
                        session.finished_at,
                        session.status,
                        session.packet_count,
                        session.flow_count,
                        session.file_size,
                        session.storage_scope,
                        json.dumps(session.to_dict()),
                    ),
                )
        hub = Hub(db)
        with sqlite3.connect(db) as conn:
            columns = {row[1] for row in conn.execute("PRAGMA table_info(capture_sessions)")}
            rows = conn.execute(
                "SELECT sha256, dedupe_key FROM capture_sessions ORDER BY capture_id"
            ).fetchall()
        assert {"sha256", "dedupe_key"} <= columns
        assert all(row[0] == first.session.sha256 for row in rows)
        assert len({row[1] for row in rows}) == 2
        canonical = hub.find_capture_session_by_fingerprint(
            target="legacy-path", source="legacy-sensor", sha256=first.session.sha256
        )
        assert canonical is not None


def test_force_imported_capture_can_be_updated_without_losing_distinct_identity():
    with tempfile.TemporaryDirectory() as tmpdir:
        hub = Hub(Path(tmpdir) / "hub.db")
        pcap = generate_sample_pcap(Path(tmpdir) / "sample.pcap")
        first = summarize_pcap(pcap, target="update-path", source="sensor")
        second = summarize_pcap(pcap, target="update-path", source="sensor")
        assert hub.add_capture_session(first.session) is True
        assert hub.add_capture_session(second.session, force_reimport=True) is True
        updated = second.session.updated(status="PRUNED", pcap_path="")
        assert hub.add_capture_session(updated) is True
        assert hub.get_capture_session(second.session.capture_id).status == "PRUNED"
        assert len(hub.list_capture_sessions(target="update-path")) == 2
