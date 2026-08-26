#!/usr/bin/env python3

import argparse
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
EVIDENCE = BASE / "evidence"
EVIDENCE.mkdir(exist_ok=True)

def run(cmd, timeout=90):
    try:
        p = subprocess.run(
            cmd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
        return {
            "returncode": p.returncode,
            "stdout": p.stdout,
            "stderr": p.stderr,
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as e:
        return {
            "returncode": 124,
            "stdout": e.stdout or "",
            "stderr": e.stderr or "",
            "timed_out": True,
        }

def wifi():
    r = run(["termux-wifi-connectioninfo"], 10)
    try:
        return json.loads(r["stdout"])
    except Exception:
        return {}

def parse_hosts(xml):
    import xml.etree.ElementTree as ET

    hosts = []
    try:
        root = ET.fromstring(xml)
    except Exception:
        return hosts

    for h in root.findall(".//host"):
        status = h.find("status")
        if status is not None and status.get("state") != "up":
            continue

        addresses = []
        for a in h.findall("address"):
            if a.get("addr"):
                addresses.append({
                    "address": a.get("addr"),
                    "type": a.get("addrtype")
                })

        hostnames = [
            x.get("name")
            for x in h.findall("./hostnames/hostname")
            if x.get("name")
        ]

        hosts.append({
            "addresses": addresses,
            "hostnames": hostnames
        })

    return hosts

def parse_services(xml):
    import xml.etree.ElementTree as ET

    results = []

    try:
        root = ET.fromstring(xml)
    except Exception:
        return results

    for h in root.findall(".//host"):
        address = None

        for a in h.findall("address"):
            if a.get("addrtype") == "ipv4":
                address = a.get("addr")
                break

        if not address:
            continue

        for p in h.findall("./ports/port"):
            state = p.find("state")
            if state is None or state.get("state") != "open":
                continue

            service = p.find("service")

            item = {
                "host": address,
                "protocol": p.get("protocol"),
                "port": int(p.get("portid")),
                "state": "open",
                "reason": state.get("reason"),
            }

            if service is not None:
                item["service"] = service.get("name")
                item["product"] = service.get("product")
                item["version"] = service.get("version")
                item["extrainfo"] = service.get("extrainfo")

            results.append(item)

    return results

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("authorization_ref")
    args = parser.parse_args()

    c = wifi()

    ssid = c.get("ssid")
    bssid = c.get("bssid")
    ip = c.get("ip")

    if not ip or ip == "0.0.0.0":
        raise SystemExit("ERROR: device is not connected to Wi-Fi")

    prefix = ip.rsplit(".", 1)[0]
    target = f"{prefix}.0/24"

    timestamp = datetime.now(timezone.utc).isoformat()

    print("=" * 68)
    print("        AUTHORIZED REAL LAN ASSESSMENT")
    print("=" * 68)
    print(f"Authorization : {args.authorization_ref}")
    print(f"SSID          : {ssid}")
    print(f"BSSID         : {bssid}")
    print(f"Device IP     : {ip}")
    print(f"Target        : {target}")
    print("=" * 68)

    # ------------------------------------------------------------
    # HOST DISCOVERY
    # ------------------------------------------------------------
    print("\n[1] HOST DISCOVERY")
    print("-" * 68)

    host_xml = EVIDENCE / f"{args.authorization_ref}_hosts.xml"

    r = run([
        "nmap",
        "-n",
        "-sn",
        "--max-retries", "1",
        "--host-timeout", "5s",
        "-oX", str(host_xml),
        target,
    ], timeout=45)

    host_xml_text = host_xml.read_text(errors="replace") if host_xml.exists() else ""

    hosts = parse_hosts(host_xml_text)

    print(f"Hosts observed: {len(hosts)}")

    for h in hosts:
        ips = [
            a["address"]
            for a in h["addresses"]
            if a["type"] == "ipv4"
        ]

        print("  " + ", ".join(ips))

    # ------------------------------------------------------------
    # SERVICE DISCOVERY
    # ------------------------------------------------------------
    print("\n[2] SERVICE DISCOVERY")
    print("-" * 68)

    addresses = []

    for h in hosts:
        for a in h["addresses"]:
            if a["type"] == "ipv4" and a["address"] != ip:
                addresses.append(a["address"])

    service_xml = EVIDENCE / f"{args.authorization_ref}_services.xml"

    services = []

    if addresses:
        r = run([
            "nmap",
            "-n",
            "-sT",
            "-sV",
            "--version-light",
            "--open",
            "--reason",
            "--max-retries", "1",
            "--host-timeout", "20s",
            "-p",
            "22,53,80,443,139,445,3389,8080,8443",
            "-oX",
            str(service_xml),
            *addresses,
        ], timeout=90)

        service_xml_text = (
            service_xml.read_text(errors="replace")
            if service_xml.exists()
            else ""
        )

        services = parse_services(service_xml_text)

    print(f"Open services observed: {len(services)}")

    for s in services:
        print(
            f"  {s['host']}:{s['port']}/"
            f"{s['protocol']} "
            f"{s.get('service', '')} "
            f"{s.get('product', '')} "
            f"{s.get('version', '')}"
        )

    # ------------------------------------------------------------
    # EVIDENCE
    # ------------------------------------------------------------
    report = {
        "timestamp": timestamp,
        "authorization": {
            "reference": args.authorization_ref,
            "scope": "connected Wi-Fi LAN",
        },
        "network": {
            "ssid": ssid,
            "bssid": bssid,
        },
        "device": {
            "ip": ip,
        },
        "target": target,
        "hosts_observed": len(hosts),
        "hosts": hosts,
        "services_observed": len(services),
        "services": services,
        "limitations": [
            "Android/Termux may restrict direct kernel network telemetry.",
            "Host discovery reflects devices observable from the assessment device.",
            "Open TCP services do not prove that the underlying application is vulnerable."
        ],
    }

    out = EVIDENCE / f"{args.authorization_ref}_real_assessment.json"
    out.write_text(json.dumps(report, indent=2) + "\n")

    print("\n[3] EVIDENCE")
    print("-" * 68)
    print(f"JSON : {out}")
    print(f"XML  : {host_xml}")

    if service_xml.exists():
        print(f"XML  : {service_xml}")

    print("\n" + "=" * 68)
    print("ASSESSMENT COMPLETE")
    print("=" * 68)


if __name__ == "__main__":
    main()
