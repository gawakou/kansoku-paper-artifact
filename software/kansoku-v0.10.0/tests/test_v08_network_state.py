from __future__ import annotations

from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
import threading
from urllib import request

from kansoku.capture import summarize_pcap
from kansoku.cli import main
from kansoku.dashboard import make_handler
from kansoku.hub import Hub
from kansoku.network_state import (
    NetworkDevice, correlate_flow, parse_frr_json, parse_nft_json, parse_ovs_json,
    select_route,
)
from kansoku.sample_pcap import generate_sample_pcap


ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "scenarios" / "virtual-lab"


def _imports():
    return (
        parse_frr_json(FIX / "frr-r1.json", device_id="r1"),
        parse_ovs_json(FIX / "ovs-sw1.json", device_id="sw1"),
        parse_nft_json(FIX / "nft-fw1.json", device_id="fw1"),
    )


def test_frr_import_normalizes_interfaces_and_routes():
    result, _, _ = _imports()
    assert result.snapshot.collector == "frr"
    assert result.snapshot.interface_count == 2
    assert result.snapshot.route_count == 2
    assert {item.name for item in result.interfaces} == {"eth0", "eth1"}
    route = select_route(result.routes, "10.0.0.2")
    assert route is not None
    assert route.prefix == "10.0.0.0/24"
    assert route.interface == "eth1"


def test_ovs_import_normalizes_access_trunk_vlan_and_link():
    _, result, _ = _imports()
    by_name = {item.name: item for item in result.interfaces}
    assert by_name["client-a"].access_vlan == 10
    assert by_name["uplink"].trunk_vlans == [10, 20]
    assert {item.vlan_id for item in result.vlans} == {10, 20}
    assert result.links[0].device_b == "fw1"


def test_nft_import_normalizes_ordered_policy_rules():
    _, _, result = _imports()
    assert result.snapshot.policy_count == 2
    allow, deny = sorted(result.policies, key=lambda x: x.priority)
    assert allow.action == "ALLOW"
    assert allow.protocol == "TCP"
    assert allow.src_network == "10.0.0.0/24"
    assert allow.dst_port == "443"
    assert deny.action == "DENY"


def test_hub_migrates_and_persists_vendor_neutral_network_state():
    with tempfile.TemporaryDirectory() as tmpdir:
        hub = Hub(Path(tmpdir) / "hub.db")
        frr, ovs, nft = _imports()
        for device in (
            NetworkDevice("r1", "Router 1", "router", "frr"),
            NetworkDevice("sw1", "Switch 1", "l2_switch", "openvswitch"),
            NetworkDevice("fw1", "Firewall 1", "firewall", "nftables"),
        ):
            hub.set_network_device(device)
        for result in (frr, ovs, nft):
            hub.add_network_snapshot(
                result.snapshot, interfaces=result.interfaces, vlans=result.vlans,
                links=result.links, routes=result.routes, policies=result.policies,
            )
        assert len(hub.list_network_devices()) == 3
        assert len(hub.list_network_interfaces(device_id="r1")) == 2
        assert len(hub.list_network_vlans(device_id="sw1")) == 2
        assert len(hub.list_network_routes(device_id="r1")) == 2
        assert len(hub.list_network_policies(device_id="fw1")) == 2


def test_flow_correlation_combines_route_policy_and_vlan_evidence():
    with tempfile.TemporaryDirectory() as tmpdir:
        summary = summarize_pcap(generate_sample_pcap(Path(tmpdir) / "sample.pcap"), target="sample")
        frr, ovs, nft = _imports()
        https_flow = next(item for item in summary.flows if item.dst_port == 443 and item.src_ip == "10.0.0.1")
        allowed = correlate_flow(
            https_flow, ingress_device_id="fw1", routes=frr.routes,
            rules=nft.policies, vlans=ovs.vlans,
        )
        assert allowed.verdict == "ALLOW"
        assert allowed.route_status == "FOUND"
        assert allowed.policy_status == "ALLOW"
        mdns = next(item for item in summary.flows if item.protocol == "UDP")
        denied = correlate_flow(
            mdns, ingress_device_id="fw1", routes=frr.routes,
            rules=nft.policies, vlans=ovs.vlans,
        )
        assert denied.verdict == "DENY"
        assert denied.vlan_status == "KNOWN"


def test_missing_route_is_reported_as_unroutable_when_policy_is_not_denying():
    with tempfile.TemporaryDirectory() as tmpdir:
        summary = summarize_pcap(generate_sample_pcap(Path(tmpdir) / "sample.pcap"), target="sample")
        flow = next(item for item in summary.flows if item.dst_port == 443)
        result = correlate_flow(flow, ingress_device_id="r1", routes=[], rules=[])
        assert result.verdict == "UNROUTABLE"
        assert result.route_status == "NO_ROUTE"


def test_cli_imports_open_source_snapshots_and_correlates_pcap(capsys):
    with tempfile.TemporaryDirectory() as tmpdir:
        db = str(Path(tmpdir) / "hub.db")
        pcap = str(generate_sample_pcap(Path(tmpdir) / "sample.pcap"))
        for kind, device_id, filename in (
            ("frr", "r1", "frr-r1.json"),
            ("ovs", "sw1", "ovs-sw1.json"),
            ("nft", "fw1", "nft-fw1.json"),
        ):
            assert main(["--db", db, "network", "import", kind, "--device-id", device_id, "--file", str(FIX / filename)]) == 0
            capsys.readouterr()
        assert main(["--db", db, "capture", "summarize", "--pcap", pcap, "--target", "sample-path"]) == 0
        capture_payload = json.loads(capsys.readouterr().out)
        capture_id = capture_payload["capture"]["capture_id"]
        assert main([
            "--db", db, "network", "correlate", "--capture-id", capture_id,
            "--ingress-device", "fw1", "--route-device", "r1",
            "--policy-device", "fw1", "--vlan-device", "sw1",
        ]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["summary"]["flows"] == 3
        assert payload["summary"]["verdicts"]["ALLOW"] >= 1
        assert len(Hub(db).list_flow_assessments(capture_id=capture_id)) == 3


def test_dashboard_network_api_and_target_assessments():
    with tempfile.TemporaryDirectory() as tmpdir:
        hub = Hub(Path(tmpdir) / "hub.db")
        frr, ovs, nft = _imports()
        for device in (
            NetworkDevice("r1", "Router 1", "router", "frr"),
            NetworkDevice("sw1", "Switch 1", "l2_switch", "openvswitch"),
            NetworkDevice("fw1", "Firewall 1", "firewall", "nftables"),
        ):
            hub.set_network_device(device)
        for result in (frr, ovs, nft):
            hub.add_network_snapshot(result.snapshot, interfaces=result.interfaces, vlans=result.vlans, links=result.links, routes=result.routes, policies=result.policies)
        summary = summarize_pcap(generate_sample_pcap(Path(tmpdir) / "sample.pcap"), target="sample")
        hub.add_capture_session(summary.session)
        hub.add_flow_records(summary.flows)
        assessments = [correlate_flow(flow, ingress_device_id="fw1", routes=frr.routes, rules=nft.policies, vlans=ovs.vlans) for flow in summary.flows]
        hub.add_flow_assessments(assessments)
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(hub))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with request.urlopen(f"http://127.0.0.1:{server.server_port}/api/network") as response:
                payload = json.loads(response.read())
            assert payload["summary"]["devices"] == 3
            assert payload["summary"]["routes"] == 2
            with request.urlopen(f"http://127.0.0.1:{server.server_port}/api/snapshot?target=sample") as response:
                snapshot = json.loads(response.read())
            assert len(snapshot["flow_assessments"]) == 3
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

def test_frr_native_interface_json_is_detected_without_wrapper():
    raw = {
        "eth9": {
            "interfaceName": "eth9",
            "flags": "<UP,RUNNING>",
            "mtu": 9000,
            "ipAddresses": [{"address": "198.51.100.1/24"}],
        }
    }
    result = parse_frr_json(raw, device_id="r-native")
    assert len(result.interfaces) == 1
    assert result.interfaces[0].name == "eth9"
    assert result.interfaces[0].mtu == 9000
    assert result.routes == []
