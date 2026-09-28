from __future__ import annotations

from pathlib import Path
import socket
import struct
from typing import Iterable


def internet_checksum(data: bytes) -> int:
    """Return the RFC 1071 one's-complement checksum for *data*."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _ipv4_addresses(src: str, dst: str) -> tuple[bytes, bytes]:
    return socket.inet_aton(src), socket.inet_aton(dst)


def ipv4_packet(src: str, dst: str, protocol: int, transport: bytes, ident: int) -> bytes:
    src_raw, dst_raw = _ipv4_addresses(src, dst)
    total_len = 20 + len(transport)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        ident,
        0,
        64,
        protocol,
        0,
        src_raw,
        dst_raw,
    )
    checksum = internet_checksum(header)
    header = header[:10] + struct.pack("!H", checksum) + header[12:]
    return header + transport


def tcp_segment(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    *,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes = b"",
) -> bytes:
    src_raw, dst_raw = _ipv4_addresses(src_ip, dst_ip)
    header = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        seq,
        ack,
        0x50,
        flags,
        65535,
        0,
        0,
    )
    pseudo = src_raw + dst_raw + struct.pack("!BBH", 0, 6, len(header) + len(payload))
    checksum = internet_checksum(pseudo + header + payload)
    header = header[:16] + struct.pack("!H", checksum) + header[18:]
    return header + payload


def udp_datagram(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    payload: bytes,
) -> bytes:
    src_raw, dst_raw = _ipv4_addresses(src_ip, dst_ip)
    length = 8 + len(payload)
    header = struct.pack("!HHHH", src_port, dst_port, length, 0)
    pseudo = src_raw + dst_raw + struct.pack("!BBH", 0, 17, length)
    checksum = internet_checksum(pseudo + header + payload)
    if checksum == 0:
        checksum = 0xFFFF
    return struct.pack("!HHHH", src_port, dst_port, length, checksum) + payload


def dns_name(name: str) -> bytes:
    labels = name.rstrip(".").split(".")
    encoded = bytearray()
    for label in labels:
        raw = label.encode("ascii")
        if not raw or len(raw) > 63:
            raise ValueError(f"invalid DNS label: {label!r}")
        encoded.append(len(raw))
        encoded.extend(raw)
    encoded.append(0)
    return bytes(encoded)


def mdns_query(name: str = "_services._dns-sd._udp.local") -> bytes:
    # Transaction ID 0 is conventional for mDNS. One PTR question, no answers.
    header = struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0)
    question = dns_name(name) + struct.pack("!HH", 12, 1)
    return header + question


def ethernet_frame(payload: bytes, *, vlan: int | None = None, reverse: bool = False) -> bytes:
    client = b"\x00\x11\x22\x33\x44\x55"
    server = b"\x66\x77\x88\x99\xaa\xbb"
    src, dst = (server, client) if reverse else (client, server)
    if vlan is None:
        return dst + src + struct.pack("!H", 0x0800) + payload
    return dst + src + struct.pack("!HHH", 0x8100, vlan & 0x0FFF, 0x0800) + payload


def sample_packets() -> list[bytes]:
    client_ip = "10.0.0.1"
    server_ip = "10.0.0.2"
    mdns_src = "10.0.0.3"
    mdns_dst = "224.0.0.251"
    packets = [
        ethernet_frame(
            ipv4_packet(
                client_ip,
                server_ip,
                6,
                tcp_segment(client_ip, server_ip, 12345, 443, seq=1000, ack=0, flags=0x02),
                1,
            )
        ),
        ethernet_frame(
            ipv4_packet(
                server_ip,
                client_ip,
                6,
                tcp_segment(server_ip, client_ip, 443, 12345, seq=2000, ack=1001, flags=0x12),
                2,
            ),
            reverse=True,
        ),
        ethernet_frame(
            ipv4_packet(
                client_ip,
                server_ip,
                6,
                tcp_segment(client_ip, server_ip, 12345, 443, seq=1001, ack=2001, flags=0x10),
                3,
            )
        ),
        ethernet_frame(
            ipv4_packet(
                mdns_src,
                mdns_dst,
                17,
                udp_datagram(mdns_src, mdns_dst, 5353, 5353, mdns_query()),
                4,
            ),
            vlan=10,
        ),
    ]
    return packets


def generate_sample_pcap(path: str | Path) -> Path:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    packets: Iterable[bytes] = sample_packets()
    with output.open("wb") as handle:
        handle.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 96, 1))
        for index, packet in enumerate(packets):
            handle.write(
                struct.pack(
                    "<IIII",
                    1_700_000_000 + index,
                    index * 1000,
                    len(packet),
                    len(packet),
                )
            )
            handle.write(packet)
    return output
