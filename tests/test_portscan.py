"""Tests for the TCP port scanner, exercised against REAL local sockets.

Rather than mocking socket behavior, these tests spin up an actual
TCP listener on 127.0.0.1 on an OS-assigned free port and confirm the
scanner correctly reports it open, then confirm a definitely-closed port
reports closed. This exercises the real connect_ex() code path.
"""

import socket
import threading
import time

import pytest

from app.network_ops import ValidationError, scan_port, scan_ports


@pytest.fixture
def open_local_port():
    """Start a real TCP server on localhost and yield its port number."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(5)
    port = server.getsockname()[1]

    stop_event = threading.Event()

    def accept_loop():
        server.settimeout(0.5)
        while not stop_event.is_set():
            try:
                conn, _ = server.accept()
                conn.close()
            except socket.timeout:
                continue
            except OSError:
                break

    thread = threading.Thread(target=accept_loop, daemon=True)
    thread.start()
    time.sleep(0.1)  # give the listener a moment to be ready

    yield port

    stop_event.set()
    server.close()
    thread.join(timeout=2)


def find_closed_port():
    """Find a TCP port on localhost that nothing is listening on."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()  # closed immediately - nothing listens here now
    return port


class TestScanPortReal:
    def test_open_port_detected_as_open(self, open_local_port):
        result = scan_port("127.0.0.1", open_local_port)
        assert result.status == "open"
        assert result.port == open_local_port

    def test_closed_port_detected_as_closed(self):
        closed_port = find_closed_port()
        result = scan_port("127.0.0.1", closed_port)
        assert result.status == "closed"

    def test_rejects_invalid_port_number(self):
        with pytest.raises(ValidationError):
            scan_port("127.0.0.1", 99999)


class TestScanPortsReal:
    def test_scan_ports_reports_open_and_closed_correctly(self, open_local_port):
        closed_port = find_closed_port()
        results = scan_ports("127.0.0.1", ports=[open_local_port, closed_port])
        by_port = {r.port: r.status for r in results}
        assert by_port[open_local_port] == "open"
        assert by_port[closed_port] == "closed"

    def test_scan_ports_returns_sorted_results(self, open_local_port):
        closed_port = find_closed_port()
        ports = sorted([open_local_port, closed_port], reverse=True)
        results = scan_ports("127.0.0.1", ports=ports)
        assert [r.port for r in results] == sorted(ports)

    def test_scan_ports_rejects_invalid_host(self):
        with pytest.raises(ValidationError):
            scan_ports("bad; rm -rf /", ports=[80])

    def test_scan_ports_uses_default_common_ports_when_none_given(self):
        # 127.0.0.1 always resolves; this just confirms it runs end-to-end
        # without error using the default COMMON_PORTS list.
        results = scan_ports("127.0.0.1")
        assert len(results) == len(set(r.port for r in results))
        assert len(results) > 0
