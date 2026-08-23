"""Shared pytest fixtures and markers for the NetDiag Toolkit test suite.

Tests that require actually shelling out to `ping`/`traceroute` or reaching
the public internet are marked with the custom `network` marker. Many CI
sandboxes (including GitHub-hosted runners in restrictive configurations)
lack raw ICMP socket permissions or outbound network access, so those tests
are skipped automatically when the required binaries aren't usable rather
than failing the whole build. Pure parsing/validation/logic tests carry no
such dependency and always run.
"""

import shutil
import socket

import pytest


def pytest_configure(config):
    config.addinivalue_line("markers", "network: requires real ICMP/network access")


def _can_reach_internet() -> bool:
    try:
        socket.setdefaulttimeout(3)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect(("1.1.1.1", 53))
        return True
    except OSError:
        return False


@pytest.fixture(scope="session")
def has_ping():
    return shutil.which("ping") is not None


@pytest.fixture(scope="session")
def has_traceroute():
    return shutil.which("traceroute") is not None


@pytest.fixture(scope="session")
def has_internet():
    return _can_reach_internet()
