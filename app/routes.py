"""HTTP routes for NetDiag Toolkit.

These are thin wrappers: all real network work happens in network_ops.py.
Routes are responsible only for input handling, calling the right function,
serializing results to JSON, and turning validation/runtime errors into
clean HTTP error responses instead of letting the process crash.
"""

from dataclasses import asdict

from flask import Blueprint, jsonify, render_template, request

from app import network_ops as net

bp = Blueprint("main", __name__)


@bp.route("/")
def index():
    return render_template("index.html", common_ports=net.COMMON_PORTS)


@bp.route("/api/ping", methods=["POST"])
def api_ping():
    data = request.get_json(silent=True) or {}
    target_raw = data.get("target", "")

    try:
        target = net.validate_target(target_raw)
    except net.ValidationError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400

    result = net.run_ping(target)
    payload = asdict(result)
    payload["ok"] = result.error is None
    return jsonify(payload)


@bp.route("/api/traceroute", methods=["POST"])
def api_traceroute():
    data = request.get_json(silent=True) or {}
    target_raw = data.get("target", "")

    try:
        target = net.validate_target(target_raw)
    except net.ValidationError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400

    result = net.run_traceroute(target)
    payload = {
        "target": result.target,
        "success": result.success,
        "error": result.error,
        "raw_output": result.raw_output,
        "hops": [asdict(h) for h in result.hops],
    }
    payload["ok"] = result.error is None
    return jsonify(payload)


@bp.route("/api/dns", methods=["POST"])
def api_dns():
    data = request.get_json(silent=True) or {}
    hostname_raw = data.get("hostname", "")

    try:
        hostname = net.validate_target(hostname_raw)
    except net.ValidationError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400

    try:
        results = net.lookup_dns(hostname)
    except Exception as exc:  # noqa: BLE001
        return jsonify({"ok": False, "error": f"DNS lookup failed: {exc}"}), 502

    return jsonify({"ok": True, "hostname": hostname, "records": results})


@bp.route("/api/portscan", methods=["POST"])
def api_portscan():
    data = request.get_json(silent=True) or {}
    target_raw = data.get("target", "")
    ports_raw = data.get("ports")

    try:
        target = net.validate_target(target_raw)
    except net.ValidationError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400

    if ports_raw:
        try:
            ports = [net.validate_port(p) for p in ports_raw]
        except net.ValidationError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
    else:
        ports = net.COMMON_PORTS

    try:
        results = net.scan_ports(target, ports)
    except net.ValidationError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    except Exception as exc:  # noqa: BLE001
        return jsonify({"ok": False, "error": f"Port scan failed: {exc}"}), 502

    return jsonify(
        {
            "ok": True,
            "target": target,
            "results": [asdict(r) for r in results],
        }
    )
