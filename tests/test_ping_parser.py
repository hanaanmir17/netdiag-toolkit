"""Tests for parse_ping_output() using realistic captured `ping` command output.

These tests do not invoke the network at all - they feed literal text that
mirrors real `ping` output on Linux (iputils-ping) and macOS (BSD ping) to
confirm the regex-based parser extracts packet loss and RTT stats correctly.
They therefore always run in CI regardless of ICMP permissions.
"""

from app.network_ops import parse_ping_output

LINUX_PING_OUTPUT = """PING google.com (142.250.premise) 56(84) bytes of data.
64 bytes from lga25s71-in-f14.1e100.net (142.250.premise): icmp_seq=1 ttl=118 time=11.2 ms
64 bytes from lga25s71-in-f14.1e100.net (142.250.premise): icmp_seq=2 ttl=118 time=10.8 ms
64 bytes from lga25s71-in-f14.1e100.net (142.250.premise): icmp_seq=3 ttl=118 time=12.1 ms
64 bytes from lga25s71-in-f14.1e100.net (142.250.premise): icmp_seq=4 ttl=118 time=11.5 ms

--- google.com ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3004ms
rtt min/avg/max/mdev = 10.800/11.400/12.100/0.478 ms
"""

MACOS_PING_OUTPUT = """PING google.com (142.250.80.14): 56 data bytes
64 bytes from 142.250.80.14: icmp_seq=0 ttl=115 time=14.221 ms
64 bytes from 142.250.80.14: icmp_seq=1 ttl=115 time=13.998 ms
64 bytes from 142.250.80.14: icmp_seq=2 ttl=115 time=15.104 ms
64 bytes from 142.250.80.14: icmp_seq=3 ttl=115 time=14.502 ms

--- google.com ping statistics ---
4 packets transmitted, 4 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 13.998/14.456/15.104/0.412 ms
"""

PARTIAL_LOSS_OUTPUT = """PING 10.0.0.99 (10.0.0.99) 56(84) bytes of data.
64 bytes from 10.0.0.99: icmp_seq=1 ttl=64 time=1.02 ms
64 bytes from 10.0.0.99: icmp_seq=3 ttl=64 time=0.98 ms

--- 10.0.0.99 ping statistics ---
4 packets transmitted, 2 received, 50% packet loss, time 3060ms
rtt min/avg/max/mdev = 0.980/1.000/1.020/0.020 ms
"""

TOTAL_LOSS_OUTPUT = """PING 10.255.255.1 (10.255.255.1) 56(84) bytes of data.

--- 10.255.255.1 ping statistics ---
4 packets transmitted, 0 received, 100% packet loss, time 3060ms
"""


class TestParsePingOutputLinux:
    def test_packet_loss_zero(self):
        result = parse_ping_output(LINUX_PING_OUTPUT)
        assert result["packet_loss_pct"] == 0.0

    def test_packets_transmitted_and_received(self):
        result = parse_ping_output(LINUX_PING_OUTPUT)
        assert result["packets_transmitted"] == 4
        assert result["packets_received"] == 4

    def test_avg_rtt(self):
        result = parse_ping_output(LINUX_PING_OUTPUT)
        assert result["avg_rtt_ms"] == 11.4

    def test_min_max_mdev_rtt(self):
        result = parse_ping_output(LINUX_PING_OUTPUT)
        assert result["min_rtt_ms"] == 10.8
        assert result["max_rtt_ms"] == 12.1
        assert result["mdev_rtt_ms"] == 0.478


class TestParsePingOutputMacOS:
    def test_packet_loss_zero(self):
        result = parse_ping_output(MACOS_PING_OUTPUT)
        assert result["packet_loss_pct"] == 0.0

    def test_avg_rtt(self):
        result = parse_ping_output(MACOS_PING_OUTPUT)
        assert result["avg_rtt_ms"] == 14.456

    def test_packets_counts(self):
        result = parse_ping_output(MACOS_PING_OUTPUT)
        assert result["packets_transmitted"] == 4
        assert result["packets_received"] == 4


class TestParsePingOutputLossScenarios:
    def test_partial_packet_loss(self):
        result = parse_ping_output(PARTIAL_LOSS_OUTPUT)
        assert result["packet_loss_pct"] == 50.0
        assert result["packets_received"] == 2

    def test_total_packet_loss_has_no_rtt(self):
        result = parse_ping_output(TOTAL_LOSS_OUTPUT)
        assert result["packet_loss_pct"] == 100.0
        assert result["avg_rtt_ms"] is None

    def test_garbage_input_returns_all_none(self):
        result = parse_ping_output("not a real ping output at all")
        assert result["packet_loss_pct"] is None
        assert result["avg_rtt_ms"] is None
        assert result["packets_transmitted"] is None
