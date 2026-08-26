#!/usr/bin/env python3

import socket
from urllib.parse import urlparse


DEFAULT_PORTS = {
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    22: "SSH",
}


def check_tcp(host, port, timeout=2):
    result = {
        "host": host,
        "port": port,
        "service": DEFAULT_PORTS.get(port, "UNKNOWN"),
        "reachable": False,
    }

    try:
        with socket.create_connection(
            (host, port),
            timeout=timeout,
        ):
            result["reachable"] = True
            result["status"] = "PASS"
            return result

    except (OSError, ValueError) as exc:
        result["status"] = "FAIL"
        result["error"] = str(exc)
        return result


def validate_url_target(url):
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        return {
            "valid": False,
            "reason": "Only HTTP/HTTPS targets are supported",
        }

    if not parsed.hostname:
        return {
            "valid": False,
            "reason": "Target hostname is missing",
        }

    return {
        "valid": True,
        "scheme": parsed.scheme,
        "hostname": parsed.hostname,
        "port": parsed.port or (
            443 if parsed.scheme == "https" else 80
        ),
    }


def assess_authorized_services(
    host,
    ports=(53, 80, 443),
):
    return [
        check_tcp(host, port)
        for port in ports
    ]
