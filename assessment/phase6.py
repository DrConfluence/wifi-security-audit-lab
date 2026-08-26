#!/usr/bin/env python3
import json
import re
from datetime import datetime, timezone
from pathlib import Path
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "evidence"
OUT = EVIDENCE / "phase6_snapshot.json"

def load_json(name, default):
    p = EVIDENCE / name
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return default

def services_from_xml():
    p = EVIDENCE / "lan_services.xml"
    result = []
    if not p.exists():
        return result
    try:
        root = ET.parse(p).getroot()
        for host in root.findall(".//host"):
            addr = host.find("address")
            ip = addr.get("addr") if addr is not None else None
            for port in host.findall("./ports/port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                service = port.find("service")
                result.append({
                    "ip": ip,
                    "port": int(port.get("port")),
                    "protocol": port.get("protocol", "tcp"),
                    "state": state.get("state"),
                    "service": service.get("name") if service is not None else "unknown",
                    "product": service.get("product") if service is not None else None,
                    "version": service.get("version") if service is not None else None,
                })
    except Exception:
        pass
    return result

connection = load_json("live_assessment.json", {}).get("connection", {}).get("data", {})
if not connection:
    for name in ("connectivity.json", "LAB-001_inventory.json"):
        data = load_json(name, {})
        if data.get("network"):
            connection = data.get("device", {})
            break

discovery = load_json("wifi_discovery.json", {})
networks = discovery.get("networks", [])
hosts = load_json("lan_hosts.json", {}).get("hosts", [])
services = services_from_xml()

findings = []
if not networks:
    findings.append({
        "severity": "INFO",
        "title": "Wireless discovery unavailable",
        "detail": "No current Wi-Fi discovery evidence is available."
    })

for service in services:
    if service.get("port") in {22, 23, 21, 445, 3389, 5900, 8080, 8443}:
        findings.append({
            "severity": "REVIEW",
            "title": "Reachable service requires review",
            "detail": f"{service['ip']}:{service['port']} {service['service']}"
        })

snapshot = {
    "schema": "wifi-audit.phase6.v1",
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "assessment": "LAB-001",
    "scope": {
        "mode": "authorized",
        "note": "Telemetry is limited to data legitimately exposed to the assessment environment."
    },
    "network": {
        "ssid": connection.get("ssid"),
        "bssid": connection.get("bssid"),
        "device_ip": connection.get("ip"),
        "rssi": connection.get("rssi"),
        "frequency_mhz": connection.get("frequency_mhz"),
        "supplicant_state": connection.get("supplicant_state"),
    },
    "wireless": {
        "networks_observed": len(networks),
        "networks": networks,
    },
    "assets": {
        "hosts_observed": len(hosts),
        "hosts": hosts,
    },
    "services": {
        "services_observed": len(services),
        "services": services,
    },
    "detections": findings,
    "capabilities": {
        "asset_discovery": True,
        "service_inventory": True,
        "evidence_generation": True,
        "traffic_metadata": "environment-dependent",
        "packet_payload_capture": False,
        "screen_capture": False,
        "credential_interception": False,
    },
}

OUT.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
print(f"Created: {OUT}")
print(json.dumps({
    "hosts": len(hosts),
    "services": len(services),
    "wireless_networks": len(networks),
    "detections": len(findings)
}, indent=2))
