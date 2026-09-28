from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import socket
import struct
import subprocess
import time
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

from .models import CollectionRun, Observation, new_id, utc_now


PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}

DLT_NULL = 0
DLT_EN10MB = 1
DLT_RAW = 101
DLT_LOOP = 108
DLT_LINUX_SLL = 113

IPPROTO_NAMES = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPV6",
    89: "OSPF",
    132: "SCTP",
}


@dataclass
class CaptureSession:
    target: str
    source: str
    interface: str
    bpf_filter: str
    snaplen: int
    privacy_mode: str
    pcap_path: str
    status: str
    packet_count: int = 0
    captured_bytes: int = 0
    wire_bytes: int = 0
    flow_count: int = 0
    file_size: int = 0
    sha256: str = ""
    linktype: int = -1
    duration_sec: float = 0.0
    retention_days: int = 7
    storage_scope: str = "local"
    metadata: Dict[str, Any] = field(default_factory=dict)
    capture_id: str = field(default_factory=lambda: new_id("capture"))
    started_at: str = field(default_factory=utc_now)
    finished_at: str = field(default_factory=utc_now)

    def validate(self) -> None:
        if not self.target.strip():
            raise ValueError("target must not be empty")
        if self.snaplen < 0 or self.snaplen > 262_144:
            raise ValueError("snaplen must be between 0 and 262144")
        if self.retention_days < 0:
            raise ValueError("retention_days must be >= 0")
        if self.privacy_mode not in {"headers-only", "full-packet", "offline"}:
            raise ValueError("unsupported privacy_mode")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CaptureSession":
        payload = {
            "storage_scope": "local",
            "metadata": {},
            "retention_days": 7,
            **data,
        }
        item = cls(**payload)
        item.validate()
        return item

    def updated(self, **changes: Any) -> "CaptureSession":
        item = replace(self, **changes)
        item.validate()
        return item


@dataclass
class FlowRecord:
    capture_id: str
    target: str
    source: str
    ip_version: int
    protocol: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    packets: int
    captured_bytes: int
    wire_bytes: int
    first_seen: str
    last_seen: str
    vlan_id: Optional[int] = None
    tcp_flags: Dict[str, int] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    flow_id: str = field(default_factory=lambda: new_id("flow"))

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FlowRecord":
        return cls(**{"tcp_flags": {}, "metadata": {}, **data})


@dataclass
class CaptureSummary:
    session: CaptureSession
    flows: List[FlowRecord]
    observations: List[Observation]


@dataclass
class CaptureResult:
    summary: CaptureSummary
    run: CollectionRun


@dataclass
class _PacketMeta:
    timestamp: str
    captured_len: int
    wire_len: int
    ip_version: int = 0
    protocol: str = "NON_IP"
    src_ip: str = ""
    dst_ip: str = ""
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    vlan_id: Optional[int] = None
    tcp_flags: Dict[str, int] = field(default_factory=dict)

    @property
    def flow_key(self) -> Optional[Tuple[Any, ...]]:
        if not self.src_ip or not self.dst_ip:
            return None
        return (
            self.ip_version,
            self.protocol,
            self.src_ip,
            self.dst_ip,
            self.src_port,
            self.dst_port,
            self.vlan_id,
        )


def _iso_timestamp(seconds: int, fraction: int, resolution: int) -> str:
    value = float(seconds) + float(fraction) / float(resolution)
    return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()


def _parse_transport(payload: bytes, protocol_num: int) -> Tuple[Optional[int], Optional[int], Dict[str, int]]:
    if protocol_num == 6 and len(payload) >= 20:
        src_port, dst_port = struct.unpack("!HH", payload[:4])
        flags_value = payload[13]
        flags = {
            "fin": int(bool(flags_value & 0x01)),
            "syn": int(bool(flags_value & 0x02)),
            "rst": int(bool(flags_value & 0x04)),
            "psh": int(bool(flags_value & 0x08)),
            "ack": int(bool(flags_value & 0x10)),
            "urg": int(bool(flags_value & 0x20)),
            "ece": int(bool(flags_value & 0x40)),
            "cwr": int(bool(flags_value & 0x80)),
        }
        return src_port, dst_port, flags
    if protocol_num in {17, 132} and len(payload) >= 4:
        src_port, dst_port = struct.unpack("!HH", payload[:4])
        return src_port, dst_port, {}
    return None, None, {}


def _parse_ipv4(payload: bytes, packet: _PacketMeta) -> None:
    if len(payload) < 20 or payload[0] >> 4 != 4:
        return
    ihl = (payload[0] & 0x0F) * 4
    if ihl < 20 or len(payload) < ihl:
        return
    packet.ip_version = 4
    packet.protocol = IPPROTO_NAMES.get(payload[9], f"IPPROTO_{payload[9]}")
    packet.src_ip = str(ipaddress.ip_address(payload[12:16]))
    packet.dst_ip = str(ipaddress.ip_address(payload[16:20]))
    flags_fragment = struct.unpack("!H", payload[6:8])[0]
    fragment_offset = flags_fragment & 0x1FFF
    if fragment_offset == 0:
        packet.src_port, packet.dst_port, packet.tcp_flags = _parse_transport(
            payload[ihl:], payload[9]
        )


def _parse_ipv6(payload: bytes, packet: _PacketMeta) -> None:
    if len(payload) < 40 or payload[0] >> 4 != 6:
        return
    packet.ip_version = 6
    packet.src_ip = str(ipaddress.ip_address(payload[8:24]))
    packet.dst_ip = str(ipaddress.ip_address(payload[24:40]))
    next_header = payload[6]
    offset = 40
    # Skip common IPv6 extension headers conservatively.
    for _ in range(8):
        if next_header in {0, 43, 60}:  # hop-by-hop, routing, destination options
            if len(payload) < offset + 2:
                break
            header_len = (payload[offset + 1] + 1) * 8
            next_header = payload[offset]
            offset += header_len
        elif next_header == 44:  # fragment
            if len(payload) < offset + 8:
                break
            fragment_field = struct.unpack("!H", payload[offset + 2 : offset + 4])[0]
            fragment_offset = (fragment_field >> 3) & 0x1FFF
            next_header = payload[offset]
            offset += 8
            if fragment_offset:
                break
        elif next_header == 51:  # AH
            if len(payload) < offset + 2:
                break
            header_len = (payload[offset + 1] + 2) * 4
            next_header = payload[offset]
            offset += header_len
        else:
            break
    packet.protocol = IPPROTO_NAMES.get(next_header, f"IPPROTO_{next_header}")
    if offset <= len(payload):
        packet.src_port, packet.dst_port, packet.tcp_flags = _parse_transport(
            payload[offset:], next_header
        )


def _parse_link_payload(data: bytes, linktype: int, endian: str, packet: _PacketMeta) -> None:
    ethertype: Optional[int] = None
    payload = data
    if linktype == DLT_EN10MB:
        if len(data) < 14:
            return
        ethertype = struct.unpack("!H", data[12:14])[0]
        offset = 14
        while ethertype in {0x8100, 0x88A8, 0x9100} and len(data) >= offset + 4:
            tci, ethertype = struct.unpack("!HH", data[offset : offset + 4])
            if packet.vlan_id is None:
                packet.vlan_id = tci & 0x0FFF
            offset += 4
        payload = data[offset:]
    elif linktype == DLT_LINUX_SLL:
        if len(data) < 16:
            return
        ethertype = struct.unpack("!H", data[14:16])[0]
        payload = data[16:]
    elif linktype in {DLT_NULL, DLT_LOOP}:
        if len(data) < 4:
            return
        family_endian = ">" if linktype == DLT_LOOP else endian
        family = struct.unpack(f"{family_endian}I", data[:4])[0]
        payload = data[4:]
        if family == socket.AF_INET:
            ethertype = 0x0800
        elif family in {socket.AF_INET6, 24, 28, 30}:
            ethertype = 0x86DD
    elif linktype == DLT_RAW:
        if not data:
            return
        ethertype = 0x0800 if data[0] >> 4 == 4 else 0x86DD if data[0] >> 4 == 6 else None
    else:
        return

    if ethertype == 0x0800:
        _parse_ipv4(payload, packet)
    elif ethertype == 0x86DD:
        _parse_ipv6(payload, packet)
    elif ethertype == 0x0806:
        packet.protocol = "ARP"


def iter_pcap_packets(path: str | Path) -> Iterator[Tuple[_PacketMeta, int]]:
    pcap_path = Path(path)
    with pcap_path.open("rb") as handle:
        magic = handle.read(4)
        if magic not in PCAP_MAGIC:
            if magic == b"\x0a\x0d\x0d\x0a":
                raise ValueError("pcapng is not supported in v0.7; capture with tcpdump -w classic pcap")
            raise ValueError("unsupported or corrupt pcap magic")
        endian, resolution = PCAP_MAGIC[magic]
        rest = handle.read(20)
        if len(rest) != 20:
            raise ValueError("truncated pcap global header")
        _version_major, _version_minor, _thiszone, _sigfigs, _snaplen, linktype = struct.unpack(
            f"{endian}HHiiii", rest
        )
        packet_header = struct.Struct(f"{endian}IIII")
        while True:
            raw = handle.read(packet_header.size)
            if not raw:
                break
            if len(raw) != packet_header.size:
                raise ValueError("truncated pcap packet header")
            ts_sec, ts_frac, incl_len, orig_len = packet_header.unpack(raw)
            if incl_len > 64 * 1024 * 1024:
                raise ValueError("pcap record exceeds safety limit")
            data = handle.read(incl_len)
            if len(data) != incl_len:
                raise ValueError("truncated pcap packet data")
            packet = _PacketMeta(
                timestamp=_iso_timestamp(ts_sec, ts_frac, resolution),
                captured_len=incl_len,
                wire_len=orig_len,
            )
            _parse_link_payload(data, linktype, endian, packet)
            yield packet, linktype


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def summarize_pcap(
    path: str | Path,
    *,
    target: str,
    source: Optional[str] = None,
    interface: str = "offline",
    bpf_filter: str = "",
    snaplen: int = 0,
    privacy_mode: str = "offline",
    retention_days: int = 7,
    storage_scope: str = "local",
    capture_id: Optional[str] = None,
    max_flows: int = 10_000,
) -> CaptureSummary:
    pcap_path = Path(path).expanduser().resolve()
    if not pcap_path.exists():
        raise FileNotFoundError(pcap_path)
    source = source or socket.gethostname()
    packet_count = captured_bytes = wire_bytes = 0
    counters = {
        "ipv4": 0,
        "ipv6": 0,
        "tcp": 0,
        "udp": 0,
        "icmp": 0,
        "arp": 0,
        "non_ip": 0,
    }
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    linktype = -1
    aggregates: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
    overflow_flows = 0

    for packet, packet_linktype in iter_pcap_packets(pcap_path):
        linktype = packet_linktype
        packet_count += 1
        captured_bytes += packet.captured_len
        wire_bytes += packet.wire_len
        first_seen = first_seen or packet.timestamp
        last_seen = packet.timestamp
        if packet.ip_version == 4:
            counters["ipv4"] += 1
        elif packet.ip_version == 6:
            counters["ipv6"] += 1
        else:
            counters["non_ip"] += 1
        if packet.protocol == "TCP":
            counters["tcp"] += 1
        elif packet.protocol == "UDP":
            counters["udp"] += 1
        elif packet.protocol in {"ICMP", "ICMPV6"}:
            counters["icmp"] += 1
        elif packet.protocol == "ARP":
            counters["arp"] += 1
        key = packet.flow_key
        if key is not None:
            item = aggregates.get(key)
            if item is None:
                if len(aggregates) >= max_flows:
                    overflow_flows += 1
                    continue
                item = {
                    "packets": 0,
                    "captured_bytes": 0,
                    "wire_bytes": 0,
                    "first_seen": packet.timestamp,
                    "last_seen": packet.timestamp,
                    "tcp_flags": {},
                }
                aggregates[key] = item
            item["packets"] += 1
            item["captured_bytes"] += packet.captured_len
            item["wire_bytes"] += packet.wire_len
            item["last_seen"] = packet.timestamp
            for flag, value in packet.tcp_flags.items():
                item["tcp_flags"][flag] = item["tcp_flags"].get(flag, 0) + value

    capture_id = capture_id or new_id("capture")
    flows: List[FlowRecord] = []
    for key, item in aggregates.items():
        ip_version, protocol, src_ip, dst_ip, src_port, dst_port, vlan_id = key
        flows.append(
            FlowRecord(
                capture_id=capture_id,
                target=target,
                source=source,
                ip_version=ip_version,
                protocol=protocol,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                vlan_id=vlan_id,
                packets=item["packets"],
                captured_bytes=item["captured_bytes"],
                wire_bytes=item["wire_bytes"],
                first_seen=item["first_seen"],
                last_seen=item["last_seen"],
                tcp_flags=item["tcp_flags"],
            )
        )
    flows.sort(key=lambda item: (item.wire_bytes, item.packets), reverse=True)

    started_at = first_seen or utc_now()
    finished_at = last_seen or started_at
    duration_sec = 0.0
    try:
        duration_sec = max(
            0.0,
            (datetime.fromisoformat(finished_at) - datetime.fromisoformat(started_at)).total_seconds(),
        )
    except ValueError:
        pass
    file_size = pcap_path.stat().st_size
    session = CaptureSession(
        capture_id=capture_id,
        target=target,
        source=source,
        interface=interface,
        bpf_filter=bpf_filter,
        snaplen=snaplen,
        privacy_mode=privacy_mode,
        pcap_path=str(pcap_path),
        status="SUMMARIZED",
        packet_count=packet_count,
        captured_bytes=captured_bytes,
        wire_bytes=wire_bytes,
        flow_count=len(flows),
        file_size=file_size,
        sha256=sha256_file(pcap_path),
        linktype=linktype,
        duration_sec=duration_sec,
        retention_days=retention_days,
        storage_scope=storage_scope,
        metadata={
            "ipv4_packets": counters["ipv4"],
            "ipv6_packets": counters["ipv6"],
            "tcp_packets": counters["tcp"],
            "udp_packets": counters["udp"],
            "icmp_packets": counters["icmp"],
            "arp_packets": counters["arp"],
            "non_ip_packets": counters["non_ip"],
            "flow_overflow_packets": overflow_flows,
            "max_flows": max_flows,
        },
        started_at=started_at,
        finished_at=finished_at,
    )
    session.validate()

    timestamp = finished_at
    labels = {"capture_id": capture_id, "privacy_mode": privacy_mode}
    observations = [
        Observation(target=target, source=source, domain="network", method="pcap", metric="capture_packet_count", value=float(packet_count), unit="packets", timestamp=timestamp, labels=labels),
        Observation(target=target, source=source, domain="network", method="pcap", metric="capture_wire_bytes", value=float(wire_bytes), unit="bytes", timestamp=timestamp, labels=labels),
        Observation(target=target, source=source, domain="network", method="pcap", metric="capture_unique_flows", value=float(len(flows)), unit="flows", timestamp=timestamp, labels=labels),
        Observation(target=target, source=source, domain="network", method="pcap", metric="capture_tcp_packets", value=float(counters["tcp"]), unit="packets", timestamp=timestamp, labels=labels),
        Observation(target=target, source=source, domain="network", method="pcap", metric="capture_udp_packets", value=float(counters["udp"]), unit="packets", timestamp=timestamp, labels=labels),
        Observation(target=target, source=source, domain="network", method="pcap", metric="capture_ipv4_packets", value=float(counters["ipv4"]), unit="packets", timestamp=timestamp, labels=labels),
        Observation(target=target, source=source, domain="network", method="pcap", metric="capture_ipv6_packets", value=float(counters["ipv6"]), unit="packets", timestamp=timestamp, labels=labels),
    ]
    if wire_bytes:
        top_share = (flows[0].wire_bytes / wire_bytes * 100.0) if flows else 0.0
        observations.append(
            Observation(target=target, source=source, domain="network", method="pcap", metric="capture_top_flow_share_pct", value=top_share, unit="%", timestamp=timestamp, labels=labels)
        )
    return CaptureSummary(session=session, flows=flows, observations=observations)


def build_tcpdump_command(
    *,
    interface: str,
    output_path: str | Path,
    snaplen: int = 96,
    packet_limit: int = 0,
    bpf_filter: str = "",
    tcpdump_bin: str = "tcpdump",
    use_sudo: bool = False,
) -> List[str]:
    if not interface.strip():
        raise ValueError("interface must not be empty")
    if snaplen < 0 or snaplen > 262_144:
        raise ValueError("snaplen must be between 0 and 262144")
    command = [tcpdump_bin, "-i", interface, "-U", "-n", "-s", str(snaplen), "-w", str(output_path)]
    if packet_limit > 0:
        command.extend(["-c", str(packet_limit)])
    if bpf_filter.strip():
        command.extend(shlex.split(bpf_filter))
    return (["sudo", "--"] + command) if use_sudo else command


class TcpdumpCaptureAgent:
    def __init__(self, *, source: Optional[str] = None, tcpdump_bin: str = "tcpdump"):
        self.source = source or socket.gethostname()
        self.tcpdump_bin = tcpdump_bin

    def list_interfaces(self) -> List[str]:
        result = subprocess.run(
            [self.tcpdump_bin, "-D"], capture_output=True, text=True, check=False
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "tcpdump -D failed")
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]

    def capture(
        self,
        target: str,
        *,
        interface: str,
        duration_sec: float = 10.0,
        packet_limit: int = 0,
        bpf_filter: str = "",
        snaplen: int = 96,
        output_dir: str | Path = "~/.kansoku/pcap",
        full_packet: bool = False,
        retention_days: int = 7,
        max_flows: int = 10_000,
        use_sudo: bool = False,
    ) -> CaptureResult:
        if duration_sec <= 0 and packet_limit <= 0:
            raise ValueError("duration_sec or packet_limit must be greater than zero")
        if full_packet:
            snaplen = 0
        directory = Path(output_dir).expanduser().resolve()
        directory.mkdir(parents=True, exist_ok=True)
        try:
            directory.chmod(0o700)
        except OSError:
            pass
        capture_id = new_id("capture")
        output_path = directory / f"{capture_id}.pcap"
        command = build_tcpdump_command(
            interface=interface,
            output_path=output_path,
            snaplen=snaplen,
            packet_limit=packet_limit,
            bpf_filter=bpf_filter,
            tcpdump_bin=self.tcpdump_bin,
            use_sudo=use_sudo,
        )
        started_at = utc_now()
        start_monotonic = time.monotonic()
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        timed_out = False
        try:
            stdout, stderr = proc.communicate(timeout=duration_sec if duration_sec > 0 else None)
        except subprocess.TimeoutExpired:
            timed_out = True
            proc.send_signal(signal.SIGINT)
            try:
                stdout, stderr = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proc.terminate()
                stdout, stderr = proc.communicate(timeout=5)
        finished_at = utc_now()
        elapsed = time.monotonic() - start_monotonic
        effective_returncode = proc.returncode
        # tcpdump interrupted by SIGINT after the requested duration is expected.
        successful = output_path.exists() and output_path.stat().st_size >= 24 and (
            effective_returncode == 0 or timed_out
        )
        run = CollectionRun(
            agent="tcpdump",
            target=target,
            source=self.source,
            command=command,
            returncode=0 if successful else int(effective_returncode or 1),
            stdout=stdout or "",
            stderr=stderr or "",
            started_at=started_at,
            finished_at=finished_at,
            metadata={
                "interface": interface,
                "bpf_filter": bpf_filter,
                "duration_sec": duration_sec,
                "elapsed_sec": elapsed,
                "packet_limit": packet_limit,
                "snaplen": snaplen,
                "privacy_mode": "full-packet" if full_packet else "headers-only",
                "pcap_path": str(output_path),
                "capture_id": capture_id,
                "timed_stop": timed_out,
            },
        )
        if not successful:
            raise RuntimeError(
                f"tcpdump capture failed rc={effective_returncode}: {(stderr or '').strip()}"
            )
        summary = summarize_pcap(
            output_path,
            target=target,
            source=self.source,
            interface=interface,
            bpf_filter=bpf_filter,
            snaplen=snaplen,
            privacy_mode="full-packet" if full_packet else "headers-only",
            retention_days=retention_days,
            capture_id=capture_id,
            max_flows=max_flows,
        )
        summary.session = summary.session.updated(
            status="CAPTURED",
            started_at=started_at,
            finished_at=finished_at,
            duration_sec=elapsed,
            metadata={**summary.session.metadata, "run_id": run.run_id},
        )
        for obs in summary.observations:
            obs.labels = {**obs.labels, "run_id": run.run_id}
        return CaptureResult(summary=summary, run=run)


class CaptureRetentionManager:
    def __init__(self, directory: str | Path):
        self.directory = Path(directory).expanduser().resolve()

    def prune(
        self,
        sessions: Iterable[CaptureSession],
        *,
        retention_days: int = 7,
        quota_bytes: int = 512 * 1024 * 1024,
        now: Optional[datetime] = None,
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        now = now or datetime.now(timezone.utc)
        candidates: List[Tuple[CaptureSession, Path, datetime, int]] = []
        for session in sessions:
            if session.storage_scope != "local" or not session.pcap_path:
                continue
            path = Path(session.pcap_path).expanduser()
            if not path.exists():
                continue
            try:
                finished = datetime.fromisoformat(session.finished_at)
                if finished.tzinfo is None:
                    finished = finished.replace(tzinfo=timezone.utc)
            except ValueError:
                finished = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
            candidates.append((session, path, finished, path.stat().st_size))
        candidates.sort(key=lambda item: item[2])
        total = sum(item[3] for item in candidates)
        deleted: List[Dict[str, Any]] = []
        cutoff = now - timedelta(days=max(0, retention_days))
        for session, path, finished, size in candidates:
            expired = retention_days == 0 or finished < cutoff
            over_quota = quota_bytes >= 0 and total > quota_bytes
            if not expired and not over_quota:
                continue
            deleted.append({"capture_id": session.capture_id, "path": str(path), "bytes": size, "reason": "retention" if expired else "quota"})
            if not dry_run:
                path.unlink(missing_ok=True)
            total -= size
        return {
            "deleted": deleted,
            "remaining_bytes": max(0, total),
            "quota_bytes": quota_bytes,
            "retention_days": retention_days,
            "dry_run": dry_run,
        }


def copy_capture_artifact(source: str | Path, destination_dir: str | Path) -> Path:
    source_path = Path(source).expanduser().resolve()
    destination = Path(destination_dir).expanduser().resolve()
    destination.mkdir(parents=True, exist_ok=True)
    output = destination / source_path.name
    shutil.copy2(source_path, output)
    return output
