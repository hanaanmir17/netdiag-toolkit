"""Tests for lookup_dns().

Structural tests (return shape, validation gating) run unconditionally.
Tests that perform a real DNS resolution against a public domain are marked
`network` and skipped automatically when the sandbox has no outbound network
access, so the suite stays green in restrictive CI environments.
"""

import pytest

from app.network_ops import DNS_RECORD_TYPES, ValidationError, lookup_dns


class TestLookupDnsValidation:
    def test_rejects_invalid_hostname_before_any_query(self):
        with pytest.raises(ValidationError):
            lookup_dns("bad; rm -rf /")

    def test_rejects_empty_hostname(self):
        with pytest.raises(ValidationError):
            lookup_dns("")


@pytest.mark.network
class TestLookupDnsReal:
    def test_returns_all_requested_record_types(self, has_internet):
        if not has_internet:
            pytest.skip("no outbound network access in this sandbox")
        results = lookup_dns("google.com")
        for rtype in DNS_RECORD_TYPES:
            assert rtype in results

    def test_a_record_contains_ip_like_strings(self, has_internet):
        if not has_internet:
            pytest.skip("no outbound network access in this sandbox")
        results = lookup_dns("google.com", record_types=["A"])
        a_records = results["A"]
        assert isinstance(a_records, list)
        assert len(a_records) > 0
        assert all(part.isdigit() for part in a_records[0].split(".") if a_records[0].count(".") == 3)

    def test_mx_record_structure(self, has_internet):
        if not has_internet:
            pytest.skip("no outbound network access in this sandbox")
        results = lookup_dns("google.com", record_types=["MX"])
        mx_records = results["MX"]
        assert isinstance(mx_records, list)
        assert len(mx_records) > 0

    def test_nonexistent_domain_reports_error_per_type(self, has_internet):
        if not has_internet:
            pytest.skip("no outbound network access in this sandbox")
        results = lookup_dns(
            "this-domain-should-not-exist-netdiag-toolkit-test.invalid",
            record_types=["A"],
        )
        assert isinstance(results["A"], dict)
        assert "error" in results["A"]
