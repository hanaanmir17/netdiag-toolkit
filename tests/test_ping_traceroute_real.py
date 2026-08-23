"""Tests that invoke the REAL system ping/traceroute binaries end to end.

These are marked `network` and skip cleanly when the sandbox lacks the
binary, ICMP permissions, or outbound connectivity - which is common in CI
runners. They are not required for CI to pass, but they do run and verify
real behavior on a normal developer machine or the sandbox this project was
built and verified in.
"""

import pytest

from app.network_ops import run_ping, run_traceroute


# A well-known, highly-available public DNS resolver. Used instead of
# 127.0.0.1 because some sandboxed/containerized environments drop ICMP to
# the loopback interface even though outbound ICMP to the real internet
# works fine - pinging a real host is also more representative of what this
# tool is actually used for.
PUBLIC_TARGET = "1.1.1.1"


@pytest.mark.network
class TestRealPing:
    def test_ping_public_host_succeeds(self, has_ping, has_internet):
        if not has_ping:
            pytest.skip("ping binary not available in this sandbox")
        if not has_internet:
            pytest.skip("no outbound network access in this sandbox")
        result = run_ping(PUBLIC_TARGET, count=2)
        assert result.success is True
        assert result.packet_loss_pct == 0.0
        assert result.avg_rtt_ms is not None

    def test_ping_rejects_injection_before_subprocess(self, has_ping):
        # validate_target() is called inside run_ping(); this must raise
        # rather than ever reaching subprocess.run().
        from app.network_ops import ValidationError

        with pytest.raises(ValidationError):
            run_ping("127.0.0.1; echo pwned")


@pytest.mark.network
class TestRealTraceroute:
    def test_traceroute_public_host_runs(self, has_traceroute, has_internet):
        if not has_traceroute:
            pytest.skip("traceroute binary not available in this sandbox")
        if not has_internet:
            pytest.skip("no outbound network access in this sandbox")
        result = run_traceroute(PUBLIC_TARGET, max_hops=5)
        assert result.error is None
        assert len(result.hops) >= 1

    def test_traceroute_rejects_injection_before_subprocess(self, has_traceroute):
        from app.network_ops import ValidationError

        with pytest.raises(ValidationError):
            run_traceroute("127.0.0.1 && echo pwned")
