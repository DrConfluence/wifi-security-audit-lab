#!/usr/bin/env python3

import argparse
import ipaddress
import json
import socket
import struct
import subprocess
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
EVIDENCE = BASE / "evidence"


def now():
    return datetime.now(timezone.utc).isoformat()


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


def wifi_scan():
    result = command(["termux-wifi-scaninfo"])

    if result["returncode"] != 0:
        return {
            "available": False,
            "reason": result["stderr"],
            "networks": [],
        }

    try:
        raw = json.loads(result["stdout"])
    except json.JSONDecodeError:
        return {
            "available": False,
            "reason": "Invalid JSON from Termux:API",
            "networks": [],
        }

    if isinstance(raw, dict) and "API_ERROR" in raw:
        return {
            "available": False,
            "reason": raw["API_ERROR"],
            "networks": [],
        }

    if not isinstance(raw, list):
        return {
            "available": False,
            "reason": "Unexpected scan response",
            "networks": [],
        }

    networks = []

    for item in raw:
        if not isinstance(item, dict):
            continue

        capabilities = item.get("capabilities", "")
        frequency = item.get("frequency_mhz")

        networks.append({
            "ssid": item.get("ssid") or "<hidden>",
            "bssid": item.get("bssid"),
            "rssi": item.get("rssi"),
            "frequency_mhz": frequency,
            "bandwidth_mhz": item.get("channel_bandwidth_mhz"),
            "center_frequency_mhz": item.get(
                "center_frequency_mhz"
            ),
            "capabilities": capabilities,
            "security": classify_security(capabilities),
            "wps_advertised": "[WPS]" in capabilities.upper(),
            "band": classify_band(frequency),
            "timestamp": item.get("timestamp"),
        })

    return {
        "available": True,
        "timestamp": now(),
        "count": len(networks),
        "networks": networks,
    }


def classify_security(capabilities):
    value = (capabilities or "").upper()

    if "SAE" in value and "WPA2" in value:
        return "WPA2/WPA3"

    if "SAE" in value or "WPA3" in value:
        return "WPA3"

    if "WPA2" in value:
        return "WPA2"

    if "WPA" in value:
        return "WPA"

    if "WEP" in value:
        return "WEP"

    if "[ESS]" in value:
        return "OPEN/UNSPECIFIED"

    return "UNKNOWN"


def classify_band(frequency):
    try:
        frequency = int(frequency)
    except (TypeError, ValueError):
        return "UNKNOWN"

    if 2400 <= frequency < 2500:
        return "2.4 GHz"

    if 4900 <= frequency < 5900:
        return "5 GHz"

    if 5925 <= frequency <= 7125:
        return "6 GHz"

    return "UNKNOWN"


def connection_info():
    result = command(["termux-wifi-connectioninfo"])

    if result["returncode"] != 0:
        return {
            "available": False,
            "reason": result["stderr"],
        }

    try:
        return {
            "available": True,
            "data": json.loads(result["stdout"]),
        }
    except json.JSONDecodeError:
        return {
            "available": False,
            "reason": "Invalid connection JSON",
        }


def route_from_proc():
    """
    Android may deny `ip route` through netlink.
    /proc/net/route can still expose the IPv4 route table
    to an unprivileged process on some Android builds.
    """

    path = Path("/proc/net/route")

    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return {
            "available": False,
            "reason": str(exc),
        }

    routes = []

    lines = text.splitlines()

    if not lines:
        return {
            "available": False,
            "reason": "Empty /proc/net/route",
        }

    for line in lines[1:]:
        fields = line.split()

        if len(fields) < 8:
            continue

        interface = fields[0]
        destination = fields[1]
        gateway_hex = fields[2]
        flags = fields[3]
        mask_hex = fields[7]

        try:
            destination_int = int(destination, 16)
            gateway_int = int(gateway_hex, 16)
            mask_int = int(mask_hex, 16)

            destination_ip = socket.inet_ntoa(
                struct.pack("<I", destination_int)
            )

            gateway_ip = socket.inet_ntoa(
                struct.pack("<I", gateway_int)
            )

            mask_ip = socket.inet_ntoa(
                struct.pack("<I", mask_int)
            )

        except (ValueError, OSError, struct.error):
            continue

        routes.append({
            "interface": interface,
            "destination": destination_ip,
            "gateway": gateway_ip,
            "mask": mask_ip,
            "flags": flags,
        })

    default_routes = [
        route
        for route in routes
        if route["destination"] == "0.0.0.0"
    ]

    if not default_routes:
        return {
            "available": True,
            "routes": routes,
            "default_gateway": None,
        }

    return {
        "available": True,
        "routes": routes,
        "default_gateway": default_routes[0]["gateway"],
        "interface": default_routes[0]["interface"],
        "mask": default_routes[0]["mask"],
    }


def route_info():
    ip_result = command(["ip", "route"])

    if ip_result["returncode"] == 0:
        gateway = None

        for line in ip_result["stdout"].splitlines():
            parts = line.split()

            if parts and parts[0] == "default" and "via" in parts:
                gateway = parts[
                    parts.index("via") + 1
                ]
                break

        return {
            "source": "ip route",
            "available": True,
            "raw": ip_result,
            "gateway": gateway,
        }

    proc_result = route_from_proc()

    if proc_result.get("available"):
        return {
            "source": "/proc/net/route",
            **proc_result,
        }

    return {
        "source": "none",
        "available": False,
        "reason": (
            "ip route unavailable and "
            "/proc/net/route unavailable"
        ),
        "ip_error": ip_result["stderr"],
        "proc_error": proc_result.get("reason"),
    }


def validate_target(scan, target_ssid):
    matches = [
        network
        for network in scan.get("networks", [])
        if network.get("ssid") == target_ssid
    ]

    return {
        "found": bool(matches),
        "count": len(matches),
        "matches": matches,
    }


def verify_association(connection, target_ssid):
    if not connection.get("available"):
        return {
            "associated": False,
            "reason": connection.get("reason"),
        }

    data = connection.get("data", {})

    ssid = data.get("ssid")
    bssid = data.get("bssid")
    ip = data.get("ip")

    associated = (
        ssid == target_ssid
        and bool(bssid)
        and ip not in (None, "", "0.0.0.0")
    )

    return {
        "associated": associated,
        "ssid": ssid,
        "bssid": bssid,
        "ip": ip,
        "rssi": data.get("rssi"),
        "frequency_mhz": data.get("frequency_mhz"),
        "supplicant_state": data.get(
            "supplicant_state"
        ),
        "link_speed_mbps": data.get(
            "link_speed_mbps"
        ),
    }


def tcp_check(host, port, timeout=2):
    services = {
        22: "SSH",
        53: "DNS",
        80: "HTTP",
        443: "HTTPS",
    }

    result = {
        "host": host,
        "port": port,
        "service": services.get(
            port,
            "UNKNOWN"
        ),
        "reachable": False,
    }

    try:
        with socket.create_connection(
            (host, port),
            timeout=timeout,
        ):
            result["reachable"] = True
            result["status"] = "PASS"

    except OSError as exc:
        result["status"] = "FAIL"
        result["error"] = str(exc)

    return result


def authorized_service_validation(
    gateway,
    ports=(53, 80, 443, 22),
):
    if not gateway:
        return {
            "status": "NOT_TESTED",
            "reason": "No gateway available",
            "results": [],
        }

    results = [
        tcp_check(gateway, port)
        for port in ports
    ]

    return {
        "status": "COMPLETED",
        "target": gateway,
        "results": results,
        "reachable": sum(
            1
            for item in results
            if item["reachable"]
        ),
    }


def save_evidence(data):
    EVIDENCE.mkdir(
        parents=True,
        exist_ok=True,
    )

    path = EVIDENCE / "live_authorized_assessment.json"

    path.write_text(
        json.dumps(
            data,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    return path


def print_discovery(scan):
    print("\n[1] REAL WI-FI DISCOVERY")
    print("-" * 110)

    print(
        f"Networks observed: "
        f"{scan.get('count', 0)}"
    )

    print(
        f"{'SSID':24} "
        f"{'BAND':9} "
        f"{'RSSI':7} "
        f"{'SECURITY':13} "
        f"{'WPS':5} "
        f"BSSID"
    )

    for item in scan.get("networks", []):
        print(
            f"{str(item['ssid'])[:23]:24} "
            f"{item['band']:9} "
            f"{str(item['rssi']):7} "
            f"{item['security']:13} "
            f"{'YES' if item['wps_advertised'] else 'NO':5} "
            f"{item['bssid']}"
        )


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Live authorized Wi-Fi assessment"
        )
    )

    parser.add_argument(
        "--ssid",
        required=True,
        help="SSID explicitly in assessment scope",
    )

    parser.add_argument(
        "--authorization-ref",
        required=True,
        help="Authorization reference supplied by assessor",
    )

    args = parser.parse_args()

    assessment_id = (
        "LIVE-"
        + datetime.now().strftime(
            "%Y%m%d-%H%M%S"
        )
    )

    print("=" * 110)
    print("             LIVE AUTHORIZED WI-FI ASSESSMENT")
    print("=" * 110)
    print("Assessment       :", assessment_id)
    print("Target SSID      :", args.ssid)
    print("Authorization ref:", args.authorization_ref)

    scan = wifi_scan()
    print_discovery(scan)

    target = validate_target(
        scan,
        args.ssid,
    )

    print("\n[2] TARGET VALIDATION")
    print("-" * 110)

    if target["found"]:
        print(
            "Target observed  : YES"
        )
        print(
            "BSSID records    :",
            target["count"],
        )
    else:
        print(
            "Target observed  : NO"
        )
        print(
            "No assessment access is inferred."
        )

    connection = connection_info()

    association = verify_association(
        connection,
        args.ssid,
    )

    print("\n[3] ACTUAL ASSOCIATION")
    print("-" * 110)
    print(
        "Associated        :",
        association["associated"],
    )
    print(
        "Current SSID      :",
        association.get("ssid"),
    )
    print(
        "BSSID             :",
        association.get("bssid"),
    )
    print(
        "IP                :",
        association.get("ip"),
    )
    print(
        "Supplicant        :",
        association.get("supplicant_state"),
    )

    routes = route_info()

    print("\n[4] ROUTING")
    print("-" * 110)
    print(
        "Route source      :",
        routes.get("source"),
    )
    print(
        "Gateway           :",
        routes.get("gateway")
        or routes.get("default_gateway"),
    )

    gateway = (
        routes.get("gateway")
        or routes.get("default_gateway")
    )

    if not association["associated"]:
        services = {
            "status": "NOT_TESTED",
            "reason": (
                "Target is not currently "
                "associated on this device"
            ),
            "results": [],
        }
    else:
        services = authorized_service_validation(
            gateway
        )

    print("\n[5] AUTHORIZED SERVICE VALIDATION")
    print("-" * 110)

    print(
        "Status            :",
        services["status"],
    )

    for item in services.get("results", []):
        print(
            f"{item['service']:6} "
            f"{item['host']}:{item['port']} "
            f"{item['status']}"
        )

    evidence = {
        "assessment_id": assessment_id,
        "timestamp": now(),
        "authorization_ref": args.authorization_ref,
        "target_ssid": args.ssid,
        "discovery": scan,
        "target_validation": target,
        "connection": connection,
        "association": association,
        "routing": routes,
        "services": services,
    }

    path = save_evidence(evidence)

    print("\n[6] EVIDENCE")
    print("-" * 110)
    print("Written           :", path)

    print("\n" + "=" * 110)

    if association["associated"] and gateway:
        print(
            "RESULT: TARGET ASSOCIATED + GATEWAY IDENTIFIED"
        )
    elif target["found"]:
        print(
            "RESULT: TARGET DISCOVERED — NOT ASSOCIATED"
        )
    else:
        print(
            "RESULT: TARGET NOT OBSERVED"
        )

    print("=" * 110)


if __name__ == "__main__":
    main()
