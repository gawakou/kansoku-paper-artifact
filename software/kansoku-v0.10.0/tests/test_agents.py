from kansoku.agent import AgentConfig, Iperf3Agent, PingAgent


LINUX_PING = """4 packets transmitted, 4 received, 0% packet loss, time 3004ms
rtt min/avg/max/mdev = 10.100/12.250/15.000/1.200 ms
"""

MAC_PING = """4 packets transmitted, 4 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 8.000/9.500/11.000/1.100 ms
"""


def test_ping_parses_linux_and_macos():
    agent = PingAgent(AgentConfig(source="test"), system_name="Linux")
    linux = agent.parse_output("example", LINUX_PING)
    assert {o.metric: o.value for o in linux}["rtt_ms"] == 12.25
    assert {o.metric: o.value for o in linux}["packet_loss_pct"] == 0.0

    mac = agent.parse_output("example", MAC_PING)
    assert {o.metric: o.value for o in mac}["rtt_ms"] == 9.5
    assert {o.metric: o.value for o in mac}["reachability"] == 1.0


def test_ping_command_timeout_units(monkeypatch):
    monkeypatch.setattr("kansoku.agent.shutil.which", lambda _: "/sbin/ping")
    mac = PingAgent(system_name="Darwin").build_command("127.0.0.1", timeout=2.5)
    linux = PingAgent(system_name="Linux").build_command("127.0.0.1", timeout=2.5)
    assert mac[mac.index("-W") + 1] == "2500"
    assert linux[linux.index("-W") + 1] == "2"


def test_iperf3_tcp_json_parser():
    payload = {
        "end": {
            "sum_sent": {"bits_per_second": 920_000_000, "retransmits": 3},
            "sum_received": {"bits_per_second": 900_000_000},
            "cpu_utilization_percent": {"host_total": 12.5, "remote_total": 8.0},
        }
    }
    observations = Iperf3Agent(AgentConfig(source="test")).parse_json("server", payload)
    metrics = {o.metric: o.value for o in observations}
    assert metrics["throughput_mbps"] == 900.0
    assert metrics["sender_throughput_mbps"] == 920.0
    assert metrics["retransmits"] == 3.0
    assert metrics["local_cpu_total_pct"] == 12.5


def test_iperf3_udp_json_parser():
    payload = {
        "end": {
            "sum": {
                "bits_per_second": 98_000_000,
                "jitter_ms": 1.25,
                "lost_percent": 0.75,
                "lost_packets": 9,
            }
        }
    }
    observations = Iperf3Agent(AgentConfig(source="test")).parse_json("server", payload, udp=True)
    metrics = {o.metric: o.value for o in observations}
    assert metrics == {
        "throughput_mbps": 98.0,
        "jitter_ms": 1.25,
        "packet_loss_pct": 0.75,
        "lost_packets": 9.0,
    }


def test_ping_execution_error_is_not_network_failure():
    agent = PingAgent(AgentConfig(source="test"), system_name="Linux")
    observations = agent.parse_output("example", "ping: socket: Operation not permitted", returncode=2)
    assert observations == []
