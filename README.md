# NetDiag Toolkit

A real, working network diagnostics dashboard: ping, traceroute, DNS lookup,
and TCP port scanning, all backed by actual system networking calls — not
simulated or canned output.

## Description

NetDiag Toolkit is a Flask web application that wraps real networking
primitives (ICMP ping, traceroute, DNS resolution, TCP connect scans) behind
a clean, dark-mode dashboard UI. Every result on screen comes from an actual
network operation performed at request time:

- **Ping** shells out to the system `ping` binary and parses real round-trip
  time and packet loss statistics from its output.
- **Traceroute** shells out to the system `traceroute` binary and parses the
  real hop-by-hop path (IP/hostname and latency per hop).
- **DNS Lookup** uses `dnspython` to perform live resolution of A, AAAA, MX,
  TXT, NS, and CNAME records against real DNS servers.
- **Port Scanner** opens real TCP sockets (`connect_ex`) against a target
  host across a configurable port list, using a thread pool for speed, and
  reports each port as open, closed, or filtered.

## Features

- Tabbed single-page dashboard: Ping, Traceroute, DNS Lookup, Port Scanner
- Real-time results with a loading spinner while operations run
- Graceful error handling for unreachable hosts, DNS failures, and invalid
  input — the app never crashes on bad input, it returns a clear message
- Strict input validation on every target before it ever reaches a
  subprocess call (see **Security** below)
- Concurrent port scanning via a thread pool for fast results
- Clean separation between web routes (`app/routes.py`) and network logic
  (`app/network_ops.py`), so the diagnostic logic is independently
  unit-testable without Flask

## Tech Stack

- **Backend:** Python 3.11, Flask
- **DNS resolution:** dnspython
- **Frontend:** vanilla HTML/CSS/JS, Tailwind CSS via CDN
- **Testing:** pytest
- **CI:** GitHub Actions
- **Containerization:** Docker

## Project Structure

```
netdiag-toolkit/
├── app/
│   ├── __init__.py        # Flask application factory
│   ├── routes.py          # HTTP endpoints (thin — delegates to network_ops)
│   ├── network_ops.py     # Real ping/traceroute/DNS/port-scan logic + validation
│   ├── templates/
│   │   └── index.html     # Dashboard UI (Tailwind CSS, vanilla JS)
│   └── static/
├── tests/
│   ├── conftest.py
│   ├── test_validation.py
│   ├── test_ping_parser.py
│   ├── test_traceroute_parser.py
│   ├── test_dns.py
│   ├── test_portscan.py
│   ├── test_ping_traceroute_real.py
│   └── test_routes.py
├── .github/workflows/ci.yml
├── Dockerfile
├── requirements.txt
├── requirements-dev.txt
├── run.py
├── LICENSE
└── README.md
```

## Setup

```bash
git clone <this-repository>
cd netdiag-toolkit
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python run.py
```

The app will be available at `http://localhost:5000`.

### Requirements

- Python 3.11+
- The system `ping` and `traceroute` binaries must be installed and on
  `PATH` (present by default on macOS and most Linux distributions).
- Traceroute and ICMP ping may require elevated privileges on some systems.

## Security

**All target input is validated before it is ever used in a subprocess
call.** Because the Ping and Traceroute features shell out to the system
`ping`/`traceroute` binaries, unvalidated user input passed to those calls
would be a classic command-injection vulnerability.

To prevent this, `app/network_ops.py::validate_target()` enforces a strict
allowlist regex (`^[A-Za-z0-9]([A-Za-z0-9\-\.:]*[A-Za-z0-9])?$`, length- and
structure-checked) before any target string is used. Only characters that
can legitimately appear in a hostname or IPv4/IPv6 literal are accepted —
semicolons, pipes, backticks, `$()`, `&&`, whitespace, and similar shell
metacharacters are rejected outright. `subprocess.run()` is always called
with an explicit argument list (never `shell=True` and never a concatenated
shell string), which is a second, independent layer of protection.

This validation is applied at both the web-route layer and again inside the
`network_ops` functions themselves (`run_ping`, `run_traceroute`, `scan_ports`,
`lookup_dns`), so it cannot be bypassed by calling the underlying functions
directly. `tests/test_validation.py` specifically exercises rejection of
shell-injection payloads such as `"8.8.8.8; rm -rf /"`, `` `reboot` ``, and
`$(whoami)`.

## Running Tests

```bash
pip install -r requirements-dev.txt
pytest -v
```

To run only the tests that don't require real ICMP/network access (what CI
runs):

```bash
pytest -v -m "not network"
```

The suite includes 40+ tests covering:

- Input validation (valid hostnames/IPs, rejection of injection payloads
  and garbage input)
- The ping output parser, against realistic Linux and macOS `ping` output
- The traceroute output parser, against realistic `traceroute` output
- DNS lookup structure and validation gating
- The port scanner, run against a real local TCP server started during the
  test to confirm open vs. closed detection over an actual socket
- HTTP-layer validation behavior via Flask's test client

Tests marked `network` perform real subprocess calls or live DNS queries and
are skipped automatically when the sandbox lacks the required binary or
network access; they still run on a normal developer machine.

## Docker & Permissions

```bash
docker build -t netdiag-toolkit .
docker run -p 5000:5000 --cap-add=NET_RAW --cap-add=NET_ADMIN netdiag-toolkit
```

`ping` and `traceroute` need raw socket access to send ICMP packets. Most
container runtimes drop the `NET_RAW`/`NET_ADMIN` capabilities by default, so
the container must be run with `--cap-add=NET_RAW --cap-add=NET_ADMIN` (or
`--privileged`, which is broader than necessary and not recommended) for
those two features to work inside Docker. DNS lookups and the port scanner
do not require any extra capabilities.

## Author

Hanaan Mir
