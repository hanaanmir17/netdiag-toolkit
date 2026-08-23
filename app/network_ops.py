"""Core network diagnostics logic for NetDiag Toolkit.

Every function in this module performs a REAL network operation (ICMP ping via
the system ping binary, traceroute via the system traceroute binary, DNS
resolution via dnspython, and TCP port scanning via raw sockets). Nothing here
is simulated or canned.

This module is intentionally kept free of any Flask imports so it can be
unit-tested in isolation and reused from any interface (CLI, web, etc).
"""

from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional

import dns.exception
import dns.resolver

# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------
#
# SECURITY: Every value that ends up on a subprocess command line (ping,
# traceroute) MUST pass through validate_target() first. We never build a
# shell string and never pass shell=True; subprocess is always invoked with
# an argument list. The regex below is a strict allowlist: only characters
# that can legitimately appear in a hostname or IPv4/IPv6 literal are
# accepted. Anything else (semicolons, pipes, backticks, spaces, `&&`, `$()`,
# etc.) is rejected outright, which closes off classic shell/argument
# injection vectors such as "8.8.8.8; rm -rf /" or "$(reboot)".

# First-pass allowlist: letters, digits, dots, hyphens, colons (for IPv6)
# only. This is the hard security boundary - anything not matching this is
# rejected before any further processing.
_ALLOWED_CHARS_RE = re.compile(r"^[A-Za-z0-9.\-:]+$")

# Strict hostname shape (no colons - those are only valid in IPv6
# literals, which are handled separately). Must start and end with an
# alphanumeric character; hyphens allowed only in the interior of labels.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9\-\.]*[A-Za-z0-9])?$"
)


class ValidationError(ValueError):
    """Raised when user-supplied target input fails validation."""


def validate_target(raw_target: str) -> str:
    """Validate a hostname or IP address before it is ever used in a subprocess call.

    Returns the stripped, validated target string. Raises ValidationError if
    the input contains anything outside the strict hostname/IP allowlist, or
    is otherwise structurally invalid.
    """
    if raw_target is None:
        raise ValidationError("Target must not be empty.")

    target = raw_target.strip()

    if not target:
        raise ValidationError("Target must not be empty.")

    if len(target) > 253:
        raise ValidationError("Target is too long to be a valid hostname or IP.")

    # Reject anything containing whitespace outright (defense in depth,
    # although the checks below would already reject it).
    if any(ch.isspace() for ch in target):
        raise ValidationError("Target must not contain whitespace.")

    # Every character in the target must come from a strict allowlist,
    # regardless of whether it turns out to be a hostname or an IP literal.
    # This is checked first and unconditionally, so no code path below can
    # ever hand a string containing shell metacharacters to ipaddress or a
    # subprocess call.
    if not _ALLOWED_CHARS_RE.match(target):
        raise ValidationError(
            "Target contains invalid characters. Only letters, digits, "
            "dots, hyphens, and colons (for IPv6) are permitted."
        )

    # IPv6 literals (contain a colon) are validated directly via the
    # standard library rather than the hostname regex, since ':' is not a
    # valid hostname character but is required for IPv6.
    if ":" in target:
        try:
            ipaddress.ip_address(target)
        except ValueError as exc:
            raise ValidationError(f"'{target}' is not a valid IPv6 address.") from exc
        return target

    # If it looks like an IP address, make sure it actually parses as one.
    # (Pure digits-and-dots strings that aren't valid IPv4 are rejected here
    # rather than being handed to ping/traceroute, which would just fail
    # anyway but with a confusing error.)
    if re.fullmatch(r"[0-9.]+", target):
        try:
            ipaddress.ip_address(target)
        except ValueError as exc:
            raise ValidationError(f"'{target}' is not a valid IPv4 address.") from exc
        return target

    # Otherwise it must be a well-formed hostname: alphanumeric labels
    # (optionally hyphenated) separated by single dots, starting and ending
    # with an alphanumeric character.
    if not _HOSTNAME_RE.match(target):
        raise ValidationError(
            "Target is not a valid hostname. Labels must be alphanumeric "
            "(hyphens allowed in the middle) and separated by single dots."
        )

    # Reject empty label segments (e.g. "exa..mple.com") which the regex
    # above would otherwise permit since '.' is an allowed interior char.
    if ".." in target or target.startswith(".") or target.endswith("."):
        raise ValidationError("Target must not contain empty label segments.")

    return target


def validate_port(port) -> int:
    """Validate that a value is a usable TCP port number (1-65535)."""
    try:
        port_int = int(port)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"'{port}' is not a valid port number.") from exc

    if not (1 <= port_int <= 65535):
        raise ValidationError("Port must be between 1 and 65535.")

    return port_int


COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 8080]


# ---------------------------------------------------------------------------
# Ping
# ---------------------------------------------------------------------------

@dataclass
class PingResult:
    target: str
    success: bool
    packet_loss_pct: Optional[float] = None
    packets_transmitted: Optional[int] = None
    packets_received: Optional[int] = None
    min_rtt_ms: Optional[float] = None
    avg_rtt_ms: Optional[float] = None
    max_rtt_ms: Optional[float] = None
    mdev_rtt_ms: Optional[float] = None
    raw_output: str = ""
    error: Optional[str] = None


def parse_ping_output(output: str) -> dict:
    """Parse the text output of the system `ping` command.

    Supports both Linux (iputils) and macOS (BSD ping) output formats.
    Returns a dict with packet loss percentage, counts, and rtt stats.
    Any field that cannot be found is left as None.
    """
    result = {
        "packets_transmitted": None,
        "packets_received": None,
        "packet_loss_pct": None,
        "min_rtt_ms": None,
        "avg_rtt_ms": None,
        "max_rtt_ms": None,
        "mdev_rtt_ms": None,
    }

    # e.g. "4 packets transmitted, 4 received, 0% packet loss, time 3005ms"
    # or macOS: "4 packets transmitted, 4 packets received, 0.0% packet loss"
    stats_match = re.search(
        r"(\d+)\s+packets transmitted,\s*(\d+)\s+(?:packets\s+)?received,"
        r".*?([\d.]+)%\s*packet loss",
        output,
        re.DOTALL,
    )
    if stats_match:
        result["packets_transmitted"] = int(stats_match.group(1))
        result["packets_received"] = int(stats_match.group(2))
        result["packet_loss_pct"] = float(stats_match.group(3))

    # Linux: "rtt min/avg/max/mdev = 0.020/0.025/0.030/0.005 ms"
    # macOS:  "round-trip min/avg/max/stddev = 0.020/0.025/0.030/0.005 ms"
    rtt_match = re.search(
        r"(?:rtt|round-trip)\s+min/avg/max/(?:mdev|stddev)\s*=\s*"
        r"([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)\s*ms",
        output,
    )
    if rtt_match:
        result["min_rtt_ms"] = float(rtt_match.group(1))
        result["avg_rtt_ms"] = float(rtt_match.group(2))
        result["max_rtt_ms"] = float(rtt_match.group(3))
        result["mdev_rtt_ms"] = float(rtt_match.group(4))

    return result


def run_ping(target: str, count: int = 4, timeout: int = 10) -> PingResult:
    """Run a real ICMP ping against `target` using the system ping binary.

    `target` MUST already have passed validate_target() - this function
    re-validates defensively as well, since it is the last line of defense
    before a subprocess call is made.
    """
    target = validate_target(target)

    cmd = ["ping", "-c", str(int(count)), target]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return PingResult(
            target=target,
            success=False,
            error=f"Ping to {target} timed out after {timeout} seconds.",
        )
    except FileNotFoundError:
        return PingResult(
            target=target,
            success=False,
            error="The 'ping' command is not available on this system.",
        )

    output = proc.stdout + "\n" + proc.stderr
    parsed = parse_ping_output(output)

    # ping returns 0 on success (host reachable, at least one reply), 1 when
    # the host did not respond, 2 on other errors (e.g. unknown host).
    if proc.returncode not in (0, 1) and parsed["packets_transmitted"] is None:
        return PingResult(
            target=target,
            success=False,
            raw_output=output.strip(),
            error=f"Could not reach '{target}'. It may not exist or DNS resolution failed.",
        )

    success = proc.returncode == 0 and (parsed["packet_loss_pct"] or 0) < 100

    return PingResult(
        target=target,
        success=success,
        raw_output=output.strip(),
        error=None if parsed["packets_transmitted"] is not None else "No response received.",
        **parsed,
    )


# ---------------------------------------------------------------------------
# Traceroute
# ---------------------------------------------------------------------------

@dataclass
class TracerouteHop:
    hop: int
    host: Optional[str]
    ip: Optional[str]
    rtts_ms: list = field(default_factory=list)
    timed_out: bool = False


@dataclass
class TracerouteResult:
    target: str
    success: bool
    hops: list = field(default_factory=list)
    raw_output: str = ""
    error: Optional[str] = None


_HOP_LINE_RE = re.compile(r"^\s*(\d+)\s+(.*)$")
_RTT_RE = re.compile(r"([\d.]+)\s*ms")
_HOST_IP_RE = re.compile(r"([A-Za-z0-9\.\-_]+)\s*\(([\da-fA-F:.]+)\)")
_BARE_IP_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+:[0-9a-fA-F:]+)$")


def parse_traceroute_output(output: str) -> list:
    """Parse the text output of the system `traceroute` command into hops.

    Handles both the "host (ip)  1.234 ms  1.456 ms  1.678 ms" format and
    the "* * *" timeout format, on both Linux and macOS.
    """
    hops = []
    for line in output.splitlines():
        match = _HOP_LINE_RE.match(line)
        if not match:
            continue
        hop_num = int(match.group(1))
        rest = match.group(2).strip()

        if not rest or set(rest.replace(" ", "")) <= {"*"}:
            hops.append(TracerouteHop(hop=hop_num, host=None, ip=None, timed_out=True))
            continue

        host = None
        ip = None
        host_ip_match = _HOST_IP_RE.search(rest)
        if host_ip_match:
            host, ip = host_ip_match.group(1), host_ip_match.group(2)
        else:
            first_token = rest.split()[0] if rest.split() else None
            if first_token and _BARE_IP_RE.match(first_token):
                ip = first_token
            elif first_token and first_token != "*":
                host = first_token

        rtts = [float(v) for v in _RTT_RE.findall(rest)]

        hops.append(
            TracerouteHop(
                hop=hop_num,
                host=host,
                ip=ip,
                rtts_ms=rtts,
                timed_out=not rtts and not host and not ip,
            )
        )
    return hops


def run_traceroute(target: str, max_hops: int = 30, timeout: int = 30) -> TracerouteResult:
    """Run a real traceroute against `target` using the system traceroute binary."""
    target = validate_target(target)

    cmd = ["traceroute", "-m", str(int(max_hops)), "-w", "2", "-q", "1", target]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return TracerouteResult(
            target=target,
            success=False,
            error=f"Traceroute to {target} timed out after {timeout} seconds.",
        )
    except FileNotFoundError:
        return TracerouteResult(
            target=target,
            success=False,
            error="The 'traceroute' command is not available on this system.",
        )

    output = proc.stdout + "\n" + proc.stderr

    if "unknown host" in output.lower() or "name or service not known" in output.lower():
        return TracerouteResult(
            target=target,
            success=False,
            raw_output=output.strip(),
            error=f"Could not resolve host '{target}'.",
        )

    hops = parse_traceroute_output(output)

    return TracerouteResult(
        target=target,
        success=len(hops) > 0,
        hops=hops,
        raw_output=output.strip(),
        error=None if hops else "No hops recorded; the host may be unreachable.",
    )


# ---------------------------------------------------------------------------
# DNS lookup
# ---------------------------------------------------------------------------

DNS_RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME"]


def lookup_dns(hostname: str, record_types=None, timeout: float = 5.0) -> dict:
    """Perform real DNS resolution for the given hostname across several record types.

    Returns a dict keyed by record type. Each value is either a list of
    string records, or a dict {"error": "..."} if that record type could not
    be resolved (e.g. NXDOMAIN, no such record, timeout).
    """
    hostname = validate_target(hostname)
    record_types = record_types or DNS_RECORD_TYPES

    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    results = {}

    for rtype in record_types:
        try:
            answer = resolver.resolve(hostname, rtype)
            records = []
            for rdata in answer:
                if rtype == "MX":
                    records.append(f"{rdata.preference} {rdata.exchange}")
                else:
                    records.append(str(rdata))
            results[rtype] = records
        except dns.resolver.NXDOMAIN:
            results[rtype] = {"error": "Domain does not exist (NXDOMAIN)."}
        except dns.resolver.NoAnswer:
            results[rtype] = {"error": f"No {rtype} record found."}
        except dns.resolver.NoNameservers:
            results[rtype] = {"error": "No nameservers could be reached."}
        except dns.exception.Timeout:
            results[rtype] = {"error": "DNS query timed out."}
        except Exception as exc:  # noqa: BLE001 - surface any dnspython error cleanly
            results[rtype] = {"error": str(exc)}

    return results


# ---------------------------------------------------------------------------
# Port scanner
# ---------------------------------------------------------------------------

@dataclass
class PortScanResult:
    port: int
    status: str  # "open", "closed", "filtered"
    service: Optional[str] = None


def _well_known_service(port: int) -> Optional[str]:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return None


def scan_port(host: str, port: int, timeout: float = 0.75) -> PortScanResult:
    """Scan a single TCP port on `host` using a real socket connect_ex call."""
    port = validate_port(port)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result_code = sock.connect_ex((host, port))
        if result_code == 0:
            status = "open"
        elif result_code in (
            getattr(__import__("errno"), "ECONNREFUSED", 111),
        ):
            status = "closed"
        else:
            status = "filtered"
    except socket.timeout:
        status = "filtered"
    except socket.gaierror:
        status = "filtered"
    finally:
        sock.close()

    return PortScanResult(port=port, status=status, service=_well_known_service(port))


def scan_ports(host: str, ports=None, timeout: float = 0.75, max_workers: int = 50) -> list:
    """Scan multiple TCP ports concurrently using a thread pool of real socket connections."""
    host = validate_target(host)
    ports = ports or COMMON_PORTS
    ports = [validate_port(p) for p in ports]

    # Resolve hostname once up front so scan_port's socket calls use a
    # concrete IP and a single clear resolution error path.
    try:
        resolved_ip = socket.gethostbyname(host)
    except socket.gaierror as exc:
        raise ValidationError(f"Could not resolve host '{host}': {exc}") from exc

    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(scan_port, resolved_ip, port, timeout): port for port in ports
        }
        for future in as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda r: r.port)
    return results
