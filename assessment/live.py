#!/usr/bin/env python3

import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
EVIDENCE = BASE / "evidence"


def command(cmd):
    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
        )
        return {
            "command": cmd,
            "returncode": p.returncode,
            "stdout": p.stdout.strip(),
            "stderr": p.stderr.strip(),
        }
    except FileNotFoundError as exc:
        return {
            "command": cmd,
            "returncode": 127,
            "stdout": "",
            "stderr": str(exc),
        }


def wifi_connection():
    if not shutil.which("termux-wifi-connectioninfo"):
        return {
            "available": False,
            "reason": "termux-wifi-connectioninfo unavailable",
        }

    r = command(["termux-wifi-connectioninfo"])

    if r["returncode"] != 0:
        return {
            "available": False,
            "reason": r["stderr"] or "Wi-Fi API failed",
            "raw": r,
        }

    try:
        data = json.loads(r["stdout"])
    except json.JSONDecodeError:
        return {
            "available": False,
            "reason": "invalid JSON from Termux:API",
            "raw": r,
        }

    return {
        "available": True,
        "data": data,
    }


def wifi_scan():
    if not shutil.which("termux-wifi-scaninfo"):
        return {
            "available": False,
            "reason": "termux-wifi-scaninfo unavailable",
        }

    r = command(["termux-wifi-scaninfo"])

    if r["returncode"] != 0:
        return {
            "available": False,
            "reason": r["stderr"] or "Wi-Fi scan failed",
            "raw": r,
        }

    try:
        data = json.loads(r["stdout"])
    except json.JSONDecodeError:
        return {
            "available": False,
            "reason": "invalid JSON from Wi-Fi scan API",
            "raw": r,
        }

    return {
        "available": True,
        "data": data,
    }


def routes():
    if not shutil.which("ip"):
        return {
            "available": False,
            "reason": "iproute2 not installed",
        }

    r = command(["ip", "route"])
    r["available"] = r["returncode"] == 0
    return r


def gateway(route_info):
    if not route_info.get("available"):
        return None

    for line in route_info.get("stdout", "").splitlines():
        parts = line.split()

        if parts and parts[0] == "default":
            if "via" in parts:
                try:
                    return parts[parts.index("via") + 1]
                except (ValueError, IndexError):
                    return None

    return None


def ping(host):
    if not host:
        return {
            "status": "NOT_TESTED",
            "reason": "No gateway available",
        }

    r = command(
        ["ping", "-c", "2", "-W", "2", host]
    )

    return {
        "status": "PASS" if r["returncode"] == 0 else "FAIL",
        "target": host,
        "output": r["stdout"],
        "error": r["stderr"],
    }


def classify_connection(info):
    if not info.get("available"):
        return "UNKNOWN"

    data = info.get("data", {})

    ssid = data.get("ssid")
    bssid = data.get("bssid")
    ip = data.get("ip")

    if (
        not ssid
        or ssid == "<unknown ssid>"
        or not bssid
        or not ip
        or ip == "0.0.0.0"
    ):
        return "NOT_CONNECTED"

    return "IP_ACQUIRED"


def main():
    EVIDENCE.mkdir(exist_ok=True)

    started = datetime.now(
        timezone.utc
    ).isoformat()

    print("=" * 68)
    print("          LIVE WI-FI SECURITY ASSESSMENT")
    print("=" * 68)

    print("\n[1] WIFI DISCOVERY")
    scan = wifi_scan()

    if scan.get("available"):
        raw_networks = scan.get("data", [])

        # Termux:API versions may return either:
        #   1. a list of network dictionaries
        #   2. a dictionary containing the network list
        # Never assume the returned JSON shape.

        if isinstance(raw_networks, list):
            networks = [
                item for item in raw_networks
                if isinstance(item, dict)
            ]
        elif isinstance(raw_networks, dict):
            candidate = (
                raw_networks.get("networks")
                or raw_networks.get("results")
                or raw_networks.get("scanResults")
                or []
            )
            networks = [
                item for item in candidate
                if isinstance(item, dict)
            ]
        else:
            networks = []

        print(f"Networks observed : {len(networks)}")

        for n in networks:
            print(
                "  "
                f"{n.get('ssid') or '<hidden>'}"
                " | "
                f"{n.get('bssid') or 'unknown'}"
                " | "
                f"{n.get('frequency_mhz', n.get('frequency', '?'))} MHz"
                " | "
                f"RSSI {n.get('rssi', '?')}"
            )
    else:
        networks = []
        print(
            "Scan unavailable:",
            scan.get("reason"),
        )

    print("\n[2] CURRENT ASSOCIATION")
    connection = wifi_connection()
    state = classify_connection(connection)

    print("State :", state)

    if connection.get("available"):
        data = connection["data"]

        print("SSID  :", data.get("ssid"))
        print("BSSID :", data.get("bssid"))
        print("IP    :", data.get("ip"))
        print("RSSI  :", data.get("rssi"))
    else:
        print(
            "Reason:",
            connection.get("reason"),
        )

    print("\n[3] ROUTING")
    route_info = routes()
    gw = gateway(route_info)

    if gw:
        print("Gateway:", gw)
    else:
        print(
            "Gateway unavailable:",
            route_info.get("reason")
            or route_info.get("stderr")
        )

    print("\n[4] GATEWAY VALIDATION")
    gateway_result = ping(gw)
    print(
        "Status:",
        gateway_result["status"]
    )

    if gw:
        print("Target:", gw)

    print("\n[5] ASSESSMENT STATE")

    if state == "NOT_CONNECTED":
        overall = "STOPPED — TARGET NOT CONNECTED"
    elif gateway_result["status"] == "PASS":
        overall = "CONNECTED — GATEWAY VERIFIED"
    else:
        overall = "CONNECTED — GATEWAY NOT VERIFIED"

    print(overall)

    evidence = {
        "timestamp": started,
        "tool": "wifi-security-audit-lab",
        "mode": "LIVE",
        "discovery": scan,
        "connection": connection,
        "connection_state": state,
        "routes": route_info,
        "gateway": gw,
        "gateway_validation": gateway_result,
        "overall_state": overall,
    }

    path = (
        EVIDENCE
        / "live_assessment.json"
    )

    path.write_text(
        json.dumps(
            evidence,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    print("\nEvidence:", path)
    print("=" * 68)


if __name__ == "__main__":
    main()
