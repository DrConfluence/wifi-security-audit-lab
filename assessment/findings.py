#!/usr/bin/env python3

def generate_findings(connectivity, services):
    findings = []

    state = connectivity.get("connection_state")

    if state == "NOT_CONNECTED":
        findings.append({
            "id": "CONN-001",
            "severity": "INFO",
            "title": "Target not connected",
            "description": "The assessment device is not currently associated with the target network.",
            "status": "BLOCKED",
        })

    elif state == "UNKNOWN":
        findings.append({
            "id": "CONN-002",
            "severity": "INFO",
            "title": "Connection state unavailable",
            "description": "Android did not expose sufficient connection information.",
            "status": "UNKNOWN",
        })

    gateway_status = connectivity.get("gateway_test", {}).get("status")

    if gateway_status == "PASS":
        findings.append({
            "id": "NET-001",
            "severity": "INFO",
            "title": "Default gateway reachable",
            "description": "The configured gateway responded to the connectivity check.",
            "status": "VERIFIED",
        })

    elif gateway_status == "NOT_AVAILABLE":
        findings.append({
            "id": "NET-002",
            "severity": "INFO",
            "title": "Gateway validation unavailable",
            "description": "No usable default gateway was exposed by the Android environment.",
            "status": "NOT_TESTED",
        })

    for item in services:
        if item.get("status") == "PASS":
            findings.append({
                "id": f"SVC-{item['port']}",
                "severity": "INFO",
                "title": f"{item['service']} reachable",
                "description": f"TCP port {item['port']} accepted a connection.",
                "status": "VERIFIED",
            })

    return findings
