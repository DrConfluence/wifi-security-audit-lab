#!/usr/bin/env python3

import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
EVIDENCE_DIR = BASE_DIR / "evidence"


def run_command(command):
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
    if not shutil.which("ip"):
        return {
            "available": False,
            "reason": "ip command not installed",
        }

    result = run_command(
        ["ip", "addr", "show", "dev", interface]
    )
    result["available"] = result["returncode"] == 0
    return result


def get_routes():
    if not shutil.which("ip"):
        return {
            "available": False,
            "reason": "ip command not installed",
        }

    result = run_command(["ip", "route"])
    result["available"] = result["returncode"] == 0
    return result


def get_termux_connection_info():
    command = "termux-wifi-connectioninfo"

    if not shutil.which(command):
        return {
            "available": False,
            "reason": f"{command} not installed",
        }

    result = run_command([command])

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
    if not connection_info.get("available"):
        return "UNKNOWN"

    data = connection_info.get("data", {})

    ssid = data.get("ssid")
    bssid = data.get("bssid")
    ip = data.get("ip")

    if (
        not ssid
        or ssid == "<unknown ssid>"
        or not bssid
        or ip in (None, "", "0.0.0.0")
    ):
        return "NOT_CONNECTED"

    return "DHCP_ACQUIRED"


def gateway_from_routes(route_output):
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
    Termux:API does not expose a reliable default gateway field.

    Therefore this function deliberately refuses to infer or guess
    a gateway from unrelated connection information.
    """
    if not connection_info.get("available"):
        return None

    return None


def check_gateway(gateway, count=3):
    if not gateway:
        return {
            "target": None,
            "reachable": False,
            "status": "NOT_AVAILABLE",
            "reason": "No default gateway identified",
        }

    result = run_command(
        ["ping", "-c", str(count), "-W", "2", gateway]
    )

    return {
        "target": gateway,
        "reachable": result["returncode"] == 0,
        "status": (
            "PASS"
            if result["returncode"] == 0
            else "FAIL"
        ),
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
    timestamp = datetime.now(timezone.utc).isoformat()

    connection_info = get_termux_connection_info()
    interface_info = get_interface_info(interface)
    routes = get_routes()

    gateway = gateway_from_routes(
        routes.get("stdout", "")
    )

    if gateway is None:
        gateway = gateway_from_connection_info(
            connection_info
        )

    evidence = {
        "assessment_id": assessment_id,
        "timestamp": timestamp,
        "target": {
            "ssid": ssid,
            "bssid": bssid,
        },
        "authorization_ref": authorization_ref,
        "connection_state": connection_state(
            connection_info
        ),
        "connection_info": connection_info,
        "interface_info": interface_info,
        "routes": routes,
        "gateway": gateway,
        "gateway_test": check_gateway(gateway),
    }

    EVIDENCE_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    output = (
        EVIDENCE_DIR
        / f"{assessment_id}_connectivity.json"
    )

    output.write_text(
        json.dumps(evidence, indent=2),
        encoding="utf-8",
    )

    return evidence


if __name__ == "__main__":
    print("Connectivity evidence module.")
    print(
        "Use only within the explicitly authorized "
        "assessment scope."
    )
