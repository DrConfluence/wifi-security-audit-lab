#!/usr/bin/env python3

import json
import shutil
import socket
import subprocess
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
EVIDENCE_DIR = BASE_DIR / "evidence"


def run_command(command):
    """Run a command without raising on non-zero exit."""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        return {
            "command": command,
            "returncode": 127,
            "stdout": "",
            "stderr": str(exc),
        }

    return {
        "command": command,
        "returncode": result.returncode,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
    }


def get_interface_info(interface="wlan0"):
    """
    Obtain Linux interface information when Android permits netlink access.

    Android/Termux may deny `ip addr`, so callers must treat an unsuccessful
    result as unavailable information rather than proof of disconnection.
    """
    if not shutil.which("ip"):
        return {
            "command": ["ip", "addr", "show", "dev", interface],
            "returncode": 127,
            "stdout": "",
            "stderr": "ip command not installed",
            "available": False,
        }

    result = run_command(["ip", "addr", "show", "dev", interface])
    result["available"] = result["returncode"] == 0
    return result


def get_routes():
    """
    Obtain routing information when Android permits netlink access.
    """
    if not shutil.which("ip"):
        return {
            "command": ["ip", "route"],
            "returncode": 127,
            "stdout": "",
            "stderr": "ip command not installed",
            "available": False,
        }

    result = run_command(["ip", "route"])
    result["available"] = result["returncode"] == 0
    return result


def get_termux_connection_info():
    """
    Obtain Android Wi-Fi connection information through Termux:API.

    This is the preferred source on a non-rooted Android device when
    `ip route`/netlink access is restricted.
    """
    if not shutil.which("termux-wifi-connectioninfo"):
        return {
            "available": False,
            "reason": "termux-wifi-connectioninfo not installed",
        }

    result = run_command(["termux-wifi-connectioninfo"])

    if result["returncode"] != 0:
        return {
            "available": False,
            "reason": result["stderr"] or "Termux Wi-Fi API failed",
            "raw": result,
        }

    try:
        data = json.loads(result["stdout"])
    except json.JSONDecodeError:
        return {
            "available": False,
            "reason": "Termux:API returned invalid JSON",
            "raw": result,
        }

    return {
        "available": True,
        "data": data,
    }


def connection_state(connection_info):
    """
    Classify the currently observed Android Wi-Fi state.

    This function does not infer access from SSID visibility.
    """
    if not connection_info.get("available"):
        return "UNKNOWN"

    data = connection_info.get("data", {})

    ssid = data.get("ssid")
    ip = data.get("ip")
    bssid = data.get("bssid")

    if (
        not ssid
        or ssid == "<unknown ssid>"
        or not bssid
        or ip in (None, "", "0.0.0.0")
    ):
        return "NOT_CONNECTED"

    if ip:
        return "DHCP_ACQUIRED"

    return "CONNECTED_NO_IP"


def gateway_from_routes(route_output):
    """
    Extract an IPv4 default gateway from `ip route` output.
    """
    for line in route_output.splitlines():
        parts = line.split()

        if parts and parts[0] == "default":
            try:
                return parts[parts.index("via") + 1]
            except (ValueError, IndexError):
                return None

    return None


def gateway_from_connection_info(connection_info):
    """
    Best-effort gateway discovery from available Android information.

    Termux:API does not normally expose the gateway directly, so this
    function deliberately returns None rather than guessing.
    """
    if not connection_info.get("available"):
        return None

    return None


def check_gateway(gateway, count=3):
    if not gateway:
        return {
            "target": None,
            "reachable": False,
            "reason": "No default gateway identified",
        }

    result = run_command(
        ["ping", "-c", str(count), "-W", "2", gateway]
    )

    return {
        "target": gateway,
        "reachable": result["returncode"] == 0,
        "output": result["stdout"],
        "error": result["stderr"],
    }


def collect_connectivity_evidence(
    assessment_id,
    ssid,
    bssid,
    authorization_ref,
    interface="wlan0",
):
    timestamp = datetime.now().astimezone().isoformat()

    interface_info = get_interface_info(interface)
    routes = get_routes()
    connection_info = get_termux_connection_info()

    gateway = gateway_from_routes(routes["stdout"])

    if gateway is None:
        gateway = gateway_from_connection_info(connection_info)

    gateway_test = check_gateway(gateway)

    evidence = {
        "assessment_id": assessment_id,
        "timestamp": timestamp,
        "ssid": ssid,
        "bssid": bssid,
        "authorization_ref": authorization_ref,
        "interface": interface,

        "connection_state": connection_state(connection_info),

        "connection_info": connection_info,

        "interface_info": interface_info,

        "routes": routes,

        "gateway": gateway,

        "gateway_test": gateway_test,
    }

    EVIDENCE_DIR.mkdir(exist_ok=True)

    output = EVIDENCE_DIR / f"{assessment_id}_connectivity.json"

    output.write_text(
        json.dumps(evidence, indent=2),
        encoding="utf-8",
    )

    return evidence


if __name__ == "__main__":
    print("Connectivity evidence module.")
    print("Use only within the explicitly authorized assessment scope.")
