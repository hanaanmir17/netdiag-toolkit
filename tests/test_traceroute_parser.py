"""Tests for parse_traceroute_output() using realistic captured `traceroute` output.

Like the ping parser tests, these use literal sample text rather than
invoking the network, so they run reliably in any CI environment.
"""

from app.network_ops import parse_traceroute_output

LINUX_TRACEROUTE_OUTPUT = """traceroute to google.com (142.250.80.14), 30 hops max, 60 byte packets
 1  _gateway (192.168.1.1)  1.203 ms  1.041 ms  0.987 ms
 2  10.10.10.1 (10.10.10.1)  5.412 ms  5.201 ms  5.099 ms
 3  * * *
 4  108.170.242.1 (108.170.242.1)  12.883 ms  12.771 ms  12.650 ms
 5  142.250.80.14 (142.250.80.14)  14.221 ms  14.109 ms  13.998 ms
"""

MACOS_TRACEROUTE_OUTPUT = """traceroute to google.com (142.250.80.14), 64 hops max, 52 byte packets
 1  192.168.1.1 (192.168.1.1)  2.145 ms  1.876 ms  1.654 ms
 2  * * *
 3  96.120.0.1 (96.120.0.1)  9.887 ms  9.665 ms  9.443 ms
"""

SINGLE_RTT_OUTPUT = """traceroute to 1.1.1.1 (1.1.1.1), 30 hops max, 60 byte packets
 1  router.local (192.168.0.1)  0.842 ms
 2  1.1.1.1 (1.1.1.1)  8.331 ms
"""


class TestParseTracerouteOutput:
    def test_correct_number_of_hops_linux(self):
        hops = parse_traceroute_output(LINUX_TRACEROUTE_OUTPUT)
        assert len(hops) == 5

    def test_hop_numbers_are_sequential(self):
        hops = parse_traceroute_output(LINUX_TRACEROUTE_OUTPUT)
        assert [h.hop for h in hops] == [1, 2, 3, 4, 5]

    def test_first_hop_parses_host_and_ip(self):
        hops = parse_traceroute_output(LINUX_TRACEROUTE_OUTPUT)
        assert hops[0].host == "_gateway"
        assert hops[0].ip == "192.168.1.1"

    def test_first_hop_rtts_parsed(self):
        hops = parse_traceroute_output(LINUX_TRACEROUTE_OUTPUT)
        assert hops[0].rtts_ms == [1.203, 1.041, 0.987]

    def test_timed_out_hop_flagged(self):
        hops = parse_traceroute_output(LINUX_TRACEROUTE_OUTPUT)
        assert hops[2].timed_out is True
        assert hops[2].host is None
        assert hops[2].ip is None

    def test_last_hop_reaches_destination_ip(self):
        hops = parse_traceroute_output(LINUX_TRACEROUTE_OUTPUT)
        assert hops[-1].ip == "142.250.80.14"

    def test_macos_output_parses(self):
        hops = parse_traceroute_output(MACOS_TRACEROUTE_OUTPUT)
        assert len(hops) == 3
        assert hops[1].timed_out is True
        assert hops[2].ip == "96.120.0.1"

    def test_single_rtt_per_hop(self):
        hops = parse_traceroute_output(SINGLE_RTT_OUTPUT)
        assert hops[0].rtts_ms == [0.842]
        assert hops[1].rtts_ms == [8.331]

    def test_empty_output_returns_no_hops(self):
        hops = parse_traceroute_output("")
        assert hops == []

    def test_garbage_output_returns_no_hops(self):
        hops = parse_traceroute_output("this is not traceroute output")
        assert hops == []
