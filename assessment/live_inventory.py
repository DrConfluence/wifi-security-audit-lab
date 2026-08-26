#!/usr/bin/env python3

import ipaddress
import json
import re
import shutil
import socket
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
EVIDENCE = BASE / "evidence"


def run(cmd, timeout=15):
    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return {
            "command": cmd,
            "returncode": p.returncode,
            "stdout": p.stdout.strip(),
            "stderr": p.stderr.strip(),
        }
    except Exception as exc:
        return {
            "command": cmd,
            "returncode": 1,
            "stdout": "",
            "stderr": str(exc),
        }


def termux_json(command):
    if not shutil.which(command):
        return {"available": False, "reason": f"{command} not installed"}

    result = run([command])
    if result["returncode"] != 0:
        return {
            "available": False,
            "reason": result["stderr"] or "command failed",
            "raw": result,
        }

    try:
        return {
            "available": True,
            "data": json.loads(result["stdout"]),
        }
    except json.JSONDecodeError:
        return {
            "available": False,
            "reason": "invalid JSON",
            "raw": result,
        }


def wifi_scan():
    return termux_json("termux-wifi-scaninfo")


def wifi_connection():
    return termux_json("termux-wifi-connectioninfo")


def connected(info):
    if not info.get("available"):
        return False

    data = info.get("data", {})
    return bool(
        data.get("ssid")
        and data.get("ssid") != "<unknown ssid>"
        and data.get("bssid")
        and data.get("ip")
        and data.get("ip") != "0.0.0.0"
    )


def interface_info():
    result = run(["ip", "addr", "show", "dev", "wlan0"])

    return {
        **result,
        "available": result["returncode"] == 0,
    }


def routes():
    result = run(["ip", "route"])

    if result["returncode"] == 0:
        return {
            **result,
            "available": True,
            "source": "ip route",
        }

    # Android/Termux can deny netlink access.
    proc = Path("/proc/net/route")
    if proc.exists():
        text = proc.read_text(errors="replace")
        return {
            "command": ["cat", "/proc/net/route"],
            "returncode": 0,
            "stdout": text,
            "stderr": "",
            "available": True,
            "source": "/proc/net/route",
        }

    return {
        **result,
        "available": False,
    }


def gateway_from_routes(route_info):
    text = route_info.get("stdout", "")

    # ip route format
    for line in text.splitlines():
        parts = line.split()

        if parts and parts[0] == "default" and "via" in parts:
            try:
                return parts[parts.index("via") + 1]
            except (ValueError, IndexError):
                pass

    # /proc/net/route format
    for line in text.splitlines()[1:]:
        fields = line.split()

        if len(fields) < 3:
            continue

        destination = fields[1]
        gateway_hex = fields[2]

        if destination != "00000000":
            continue

        try:
            value = int(gateway_hex, 16)
            octets = [
                (value >> 0) & 255,
                (value >> 8) & 255,
                (value >> 16) & 255,
                (value >> 24) & 255,
            ]
            return ".".join(map(str, octets))
        except ValueError:
            pass

    return None


def subnet_from_ip(ip):
    try:
        address = ipaddress.ip_address(ip)
        if address.version != 4:
            return None

        # Conservative LAN discovery range.
        return ipaddress.ip_network(
            f"{ip}/24",
            strict=False,
        )
    except ValueError:
        return None


def ping_host(host, timeout=1):
    result = run(
        ["ping", "-c", "1", "-W", str(timeout), str(host)],
        timeout=3,
    )

    return {
        "ip": str(host),
        "reachable": result["returncode"] == 0,
    }


def neighbor_table():
    result = run(["ip", "neigh"])

    if result["returncode"] != 0:
        return {
            **result,
            "available": False,
        }

    entries = []

    for line in result["stdout"].splitlines():
        parts = line.split()

        if not parts:
            continue

        entry = {"ip": parts[0]}

        if "lladdr" in parts:
            try:
                entry["mac"] = parts[parts.index("lladdr") + 1]
            except (ValueError, IndexError):
                pass

        if parts[-1] in {
            "REACHABLE",
            "STALE",
            "DELAY",
            "PROBE",
            "FAILED",
            "INCOMPLETE",
            "NOARP",
            "PERMANENT",
        }:
            entry["state"] = parts[-1]

        entries.append(entry)

    return {
        **result,
        "available": True,
        "entries": entries,
    }


def reverse_dns(ip):
    try:
        name = socket.gethostbyaddr(ip)[0]
        return name
    except (socket.herror, socket.gaierror, OSError):
        return None


def tcp_check(ip, port, timeout=0.5):
    try:
        with socket.create_connection((str(ip), port), timeout=timeout):
            return True
    except (OSError, ValueError):
        return False


def service_snapshot(ip):
    common = {
        22: "SSH",
        53: "DNS",
        80: "HTTP",
        443: "HTTPS",
        445: "SMB",
        3389: "RDP",
        8080: "HTTP-alt",
        8443: "HTTPS-alt",
        9100: "Printer",
    }

    results = []

    for port, name in common.items():
        if tcp_check(ip, port):
            results.append({
                "port": port,
                "service": name,
                "state": "REACHABLE",
            })

    return results


def discover_lan(ip, max_hosts=32):
    """
    Bounded LAN discovery.

    Prefer the OS neighbor table. If it contains usable entries, return
    those observations without generating a large serial ping sweep.

    When a sweep is necessary, limit it to a small host window so an
    Android/Termux assessment cannot hang for minutes.
    """
    network = subnet_from_ip(ip)

    if not network:
        return {
            "available": False,
            "reason": "Could not determine IPv4 LAN",
        }

    hosts = list(network.hosts())

    # Never launch an uncontrolled 254-host serial sweep on Android.
    hosts = hosts[:max_hosts]

    discovered = []

    for host in hosts:
        result = ping_host(host, timeout=0.25)

        if result["reachable"]:
            discovered.append({
                "ip": str(host),
                "hostname": reverse_dns(str(host)),
                "reachable": True,
            })

    return {
        "available": True,
        "network": str(network),
        "hosts_tested": len(hosts),
        "bounded": True,
        "reachable_hosts": discovered,
    }

def enrich_with_neighbors(discovery, neighbors):
    by_ip = {
        item.get("ip"): item
        for item in neighbors.get("entries", [])
        if item.get("ip")
    }

    for device in discovery.get("reachable_hosts", []):
        neighbor = by_ip.get(device["ip"])

        if neighbor:
            if neighbor.get("mac"):
                device["mac"] = neighbor["mac"]
            if neighbor.get("state"):
                device["neighbor_state"] = neighbor["state"]

        device["services"] = service_snapshot(device["ip"])

    return discovery


def run_live(authorization_ref):
    timestamp = datetime.now(timezone.utc).isoformat()

    scan = wifi_scan()
    connection = wifi_connection()

    result = {
        "tool": "wifi-security-audit-lab",
        "mode": "LIVE",
        "timestamp": timestamp,
        "authorization_ref": authorization_ref,
        "discovery": scan,
        "connection": connection,
    }

    if scan.get("available") and isinstance(scan.get("data"), list):
        result["networks_observed"] = len(scan["data"])
        result["networks"] = scan["data"]
    else:
        result["networks_observed"] = 0
        result["networks"] = []

    if not connected(connection):
        result["overall_state"] = "STOPPED_NOT_CONNECTED"
        result["reason"] = (
            "Phone is not associated with a Wi-Fi network. "
            "LAN discovery requires an authorized connection."
        )
        return result

    data = connection["data"]

    result["client"] = {
        "ssid": data.get("ssid"),
        "bssid": data.get("bssid"),
        "ip": data.get("ip"),
        "rssi": data.get("rssi"),
        "frequency_mhz": data.get("frequency_mhz"),
        "link_speed_mbps": data.get("link_speed_mbps"),
    }

    iface = interface_info()
    route_info = routes()
    gateway = gateway_from_routes(route_info)
    neighbors = neighbor_table()

    result["interface"] = iface
    result["routing"] = route_info
    result["gateway"] = gateway
    result["gateway_reachable"] = (
        ping_host(gateway)["reachable"] if gateway else False
    )

    result["neighbors"] = neighbors

    discovery = discover_lan(data["ip"])

    if neighbors.get("available"):
        discovery = enrich_with_neighbors(
            discovery,
            neighbors,
        )

    result["lan"] = discovery
    result["device_count"] = len(
        discovery.get("reachable_hosts", [])
    )

    result["overall_state"] = "COMPLETED"

    return result


def save(result):
    EVIDENCE.mkdir(exist_ok=True)

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    path = EVIDENCE / f"live_inventory_{stamp}.json"

    path.write_text(
        json.dumps(
            result,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    return path


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Live authorized Wi-Fi/LAN inventory"
    )
    parser.add_argument(
        "--authorization-ref",
        required=True,
    )

    args = parser.parse_args()

    print("=" * 68)
    print("       LIVE WI-FI SECURITY ASSESSMENT")
    print("=" * 68)

    result = run_live(args.authorization_ref)

    print(f"Networks observed : {result.get('networks_observed', 0)}")

    if result.get("networks"):
        print()
        print("VISIBLE WI-FI NETWORKS")
        print("-" * 68)

        for n in result["networks"]:
            print(
                f"{n.get('ssid') or '<hidden>':28} "
                f"{n.get('bssid', '-'):<20} "
                f"{n.get('frequency_mhz', '-'):>5} MHz "
                f"RSSI {n.get('rssi', '-')}"
            )

    print()
    print("CURRENT CONNECTION")
    print("-" * 68)

    client = result.get("client")

    if not client:
        print("State : NOT_CONNECTED")
        print(result.get("reason", "No authorized Wi-Fi association"))
    else:
        print(f"SSID      : {client.get('ssid')}")
        print(f"BSSID     : {client.get('bssid')}")
        print(f"IP        : {client.get('ip')}")
        print(f"RSSI      : {client.get('rssi')} dBm")
        print(f"Frequency : {client.get('frequency_mhz')} MHz")
        print(f"Link      : {client.get('link_speed_mbps')} Mbps")

        print()
        print("NETWORK")
        print("-" * 68)
        print(f"Gateway           : {result.get('gateway')}")
        print(f"Gateway reachable : {result.get('gateway_reachable')}")
        print(f"LAN devices       : {result.get('device_count', 0)}")

        print()
        print("DISCOVERED DEVICES")
        print("-" * 68)

        for device in result.get("lan", {}).get(
            "reachable_hosts", []
        ):
            services = ",".join(
                f"{x['port']}/{x['service']}"
                for x in device.get("services", [])
            ) or "-"

            print(
                f"{device.get('ip', '-'):<16} "
                f"{device.get('mac', '-'):<20} "
                f"{device.get('hostname') or '-':28} "
                f"{services}"
            )

    path = save(result)

    print()
    print(f"Evidence : {path}")
    print(f"State    : {result['overall_state']}")
    print("=" * 68)


if __name__ == "__main__":
    main()
