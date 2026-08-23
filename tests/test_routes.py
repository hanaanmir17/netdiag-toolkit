"""HTTP-layer tests using Flask's test client.

These confirm the web layer wires validation errors into clean 400
responses (never a 500 crash or, worse, an executed subprocess) and that
the index page renders.
"""

import pytest

from app import create_app


@pytest.fixture
def client():
    app = create_app()
    app.testing = True
    with app.test_client() as client:
        yield client


class TestIndexPage:
    def test_index_loads(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        assert b"NetDiag Toolkit" in resp.data


class TestApiInputValidation:
    def test_ping_rejects_injection_payload(self, client):
        resp = client.post("/api/ping", json={"target": "8.8.8.8; ls"})
        assert resp.status_code == 400
        assert resp.get_json()["ok"] is False

    def test_ping_rejects_empty_target(self, client):
        resp = client.post("/api/ping", json={"target": ""})
        assert resp.status_code == 400

    def test_traceroute_rejects_injection_payload(self, client):
        resp = client.post("/api/traceroute", json={"target": "8.8.8.8 && reboot"})
        assert resp.status_code == 400

    def test_dns_rejects_injection_payload(self, client):
        resp = client.post("/api/dns", json={"hostname": "`whoami`"})
        assert resp.status_code == 400

    def test_portscan_rejects_injection_payload(self, client):
        resp = client.post("/api/portscan", json={"target": "$(id)"})
        assert resp.status_code == 400

    def test_portscan_rejects_invalid_port(self, client):
        resp = client.post("/api/portscan", json={"target": "127.0.0.1", "ports": [99999]})
        assert resp.status_code == 400

    def test_portscan_localhost_default_ports(self, client):
        resp = client.post("/api/portscan", json={"target": "127.0.0.1"})
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["ok"] is True
        assert len(body["results"]) > 0
