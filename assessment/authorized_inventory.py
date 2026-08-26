#!/usr/bin/env python3
import argparse, concurrent.futures, ipaddress, json, socket, subprocess
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
EVIDENCE = BASE / "evidence"

PORTS = {
    22: "SSH", 53: "DNS", 80: "HTTP",
    443: "HTTPS", 445: "SMB", 8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
}

def run(cmd, timeout=5):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, check=False)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except Exception as e:
        return -1, "", str(e)

def wifi_connection():
    rc, out, err = run(["termux-wifi-connectioninfo"])
    if rc != 0:
        raise RuntimeError(err or "Wi-Fi connection API failed")
    return json.loads(out)

def wifi_scan():
    rc, out, err = run(["termux-wifi-scaninfo"], 10)
    if rc != 0:
        return {"error": err or "Wi-Fi scan API failed"}
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return {"error": "Invalid Wi-Fi scan JSON"}

def network_from_ip(ip):
    try:
        a = ipaddress.ip_address(ip)
        if a.version != 4 or a.is_unspecified:
            return None
        return ipaddress.ip_network(f"{ip}/24", strict=False)
    except ValueError:
        return None

def probe(ip, port):
    started = datetime.now(timezone.utc)
    try:
        with socket.create_connection((str(ip), port), timeout=0.4):
            elapsed = (
                datetime.now(timezone.utc) - started
            ).total_seconds() * 1000
            return {
                "port": port,
                "service": PORTS[port],
                "reachable": True,
                "latency_ms": round(elapsed, 2),
            }
    except OSError:
        return None

def inspect_host(ip):
    services = []
    for port in PORTS:
        result = probe(ip, port)
        if result:
            services.append(result)

    if not services:
        return None

    hostname = None
    try:
        hostname = socket.gethostbyaddr(str(ip))[0]
    except Exception:
        pass

    return {
        "ip": str(ip),
        "hostname": hostname,
        "services": services,
    }

def discover(network):
    hosts = list(network.hosts())

    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
        futures = [pool.submit(inspect_host, h) for h in hosts]
        results = []

        for f in concurrent.futures.as_completed(futures):
            try:
                value = f.result()
                if value:
                    results.append(value)
            except Exception:
                pass

    return sorted(
        results,
        key=lambda x: ipaddress.ip_address(x["ip"])
    )

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("authorization_ref")
    args = parser.parse_args()

    connection = wifi_connection()

    if connection.get("supplicant_state") != "COMPLETED":
        raise SystemExit(
            "ERROR: device is not connected to Wi-Fi."
        )

    ip = connection.get("ip")
    network = network_from_ip(ip)

    if network is None:
        raise SystemExit(
            f"ERROR: usable IPv4 network unavailable: {ip}"
        )

    print("=" * 70)
    print("REAL AUTHORIZED LAN INVENTORY")
    print("=" * 70)
    print(f"Authorization : {args.authorization_ref}")
    print(f"SSID          : {connection.get('ssid')}")
    print(f"BSSID         : {connection.get('bssid')}")
    print(f"Client IP     : {ip}")
    print(f"RSSI          : {connection.get('rssi')} dBm")
    print(f"Frequency     : {connection.get('frequency_mhz')} MHz")
    print(f"Link speed    : {connection.get('link_speed_mbps')} Mbps")
    print(f"LAN scope     : {network}")
    print("=" * 70)

    print("\n[1] REAL AP DISCOVERY")
    scan = wifi_scan()

    if isinstance(scan, list):
        print(f"Nearby APs: {len(scan)}")
    else:
        print(f"Scan unavailable: {scan}")

    print("\n[2] AUTHORIZED LAN DISCOVERY")
    print(f"Scanning {network} with bounded concurrency...")

    hosts = discover(network)

    print(f"Reachable hosts with selected services: {len(hosts)}")

    for host in hosts:
        services = ", ".join(
            f"{x['port']}/{x['service']}"
            for x in host["services"]
        )
        print(
            f"{host['ip']:15} "
            f"{(host['hostname'] or '-'):30} "
            f"{services}"
        )

    evidence = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "mode": "LIVE_AUTHORIZED_LAN",
        "authorization_ref": args.authorization_ref,
        "connection": connection,
        "wifi_scan": scan,
        "lan_scope": str(network),
        "reachable_host_count": len(hosts),
        "hosts": hosts,
        "limitations": [
            "Android netlink access may be unavailable.",
            "MAC addresses are not inferred when unavailable.",
            "Only observed reachable services are reported.",
        ],
    }

    EVIDENCE.mkdir(exist_ok=True)
    path = EVIDENCE / "authorized_lan_inventory.json"

    path.write_text(
        json.dumps(evidence, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print("\n[3] EVIDENCE")
    print(path)

if __name__ == "__main__":
    main()
