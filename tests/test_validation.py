"""Tests for the hostname/IP input validation that guards every subprocess call.

This is the most security-critical module in the project: validate_target()
is the sole gate between user input and `subprocess.run(["ping", ..., target])`
/ `subprocess.run(["traceroute", ..., target])`. These tests assert that
shell metacharacters and injection payloads are rejected outright.
"""

import pytest

from app.network_ops import ValidationError, validate_port, validate_target


class TestValidHostnamesAndIPs:
    def test_simple_hostname(self):
        assert validate_target("google.com") == "google.com"

    def test_subdomain_hostname(self):
        assert validate_target("mail.google.com") == "mail.google.com"

    def test_hostname_with_hyphen(self):
        assert validate_target("my-server-01.example.com") == "my-server-01.example.com"

    def test_ipv4_address(self):
        assert validate_target("8.8.8.8") == "8.8.8.8"

    def test_ipv4_loopback(self):
        assert validate_target("127.0.0.1") == "127.0.0.1"

    def test_ipv6_address(self):
        assert validate_target("::1") == "::1"

    def test_ipv6_full_address(self):
        assert validate_target("2001:4860:4860::8888") == "2001:4860:4860::8888"

    def test_strips_surrounding_whitespace(self):
        assert validate_target("  google.com  ") == "google.com"

    def test_single_label_hostname(self):
        assert validate_target("localhost") == "localhost"


class TestRejectsInjectionAttempts:
    @pytest.mark.parametrize(
        "payload",
        [
            "8.8.8.8; rm -rf /",
            "8.8.8.8 && rm -rf /",
            "8.8.8.8; ls",
            "8.8.8.8 | cat /etc/passwd",
            "$(reboot)",
            "`reboot`",
            "8.8.8.8\nrm -rf /",
            "8.8.8.8 & shutdown now",
            "google.com; cat /etc/shadow",
            "127.0.0.1' OR '1'='1",
            "google.com$(whoami)",
            "test; echo pwned > /tmp/pwned",
        ],
    )
    def test_rejects_shell_injection_payloads(self, payload):
        with pytest.raises(ValidationError):
            validate_target(payload)


class TestRejectsGarbageInput:
    def test_rejects_empty_string(self):
        with pytest.raises(ValidationError):
            validate_target("")

    def test_rejects_none(self):
        with pytest.raises(ValidationError):
            validate_target(None)

    def test_rejects_whitespace_only(self):
        with pytest.raises(ValidationError):
            validate_target("   ")

    def test_rejects_double_dot(self):
        with pytest.raises(ValidationError):
            validate_target("exa..mple.com")

    def test_rejects_leading_dot(self):
        with pytest.raises(ValidationError):
            validate_target(".example.com")

    def test_rejects_trailing_dot_edge_case(self):
        with pytest.raises(ValidationError):
            validate_target("example.com.")

    def test_rejects_invalid_ipv4_out_of_range(self):
        with pytest.raises(ValidationError):
            validate_target("999.999.999.999")

    def test_rejects_overly_long_input(self):
        with pytest.raises(ValidationError):
            validate_target("a" * 300)

    def test_rejects_slash_path_injection(self):
        with pytest.raises(ValidationError):
            validate_target("/etc/passwd")

    def test_rejects_spaces_inside_target(self):
        with pytest.raises(ValidationError):
            validate_target("google .com")


class TestValidatePort:
    def test_accepts_valid_port(self):
        assert validate_port(80) == 80

    def test_accepts_string_port(self):
        assert validate_port("443") == 443

    def test_rejects_port_zero(self):
        with pytest.raises(ValidationError):
            validate_port(0)

    def test_rejects_negative_port(self):
        with pytest.raises(ValidationError):
            validate_port(-1)

    def test_rejects_port_above_max(self):
        with pytest.raises(ValidationError):
            validate_port(70000)

    def test_rejects_non_numeric_port(self):
        with pytest.raises(ValidationError):
            validate_port("eighty")
