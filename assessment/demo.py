#!/usr/bin/env python3

from assessment.report import build_report, write_report
from assessment.findings import generate_findings
from assessment.executive import build_executive_summary


def main():
    session = {
        "assessment_id": "DEMO-PHASE1-001",
        "ssid": "LAB-NETWORK",
        "bssid": "02:00:00:00:00:01",
        "authorization_ref": "LAB-DEMO-001",
        "scope_status": "AUTHORIZED",
    }

    connectivity = {
        "connection_state": "DHCP_ACQUIRED",
        "gateway": "192.168.10.1",
        "gateway_test": {
            "status": "PASS",
        },
    }

    services = [
        {
            "host": "192.168.10.1",
            "port": 53,
            "service": "DNS",
            "reachable": True,
            "status": "PASS",
        },
        {
            "host": "192.168.10.1",
            "port": 80,
            "service": "HTTP",
            "reachable": True,
            "status": "PASS",
        },
        {
            "host": "192.168.10.1",
            "port": 443,
            "service": "HTTPS",
            "reachable": False,
            "status": "FAIL",
        },
    ]

    report = build_report(
        session=session,
        connectivity=connectivity,
        services=services,
    )

    report["findings"] = generate_findings(
        connectivity,
        services,
    )

    report["executive"] = build_executive_summary(
        report
    )

    path = write_report(report)

    print("=" * 60)
    print("DEMO ASSESSMENT")
    print("=" * 60)
    print("Assessment :", session["assessment_id"])
    print("Target     :", session["ssid"])
    print("Connection :", connectivity["connection_state"])
    print("Gateway    :", connectivity["gateway"])
    print(
        "Gateway    :",
        connectivity["gateway_test"]["status"],
    )
    print("Services   :", len(services))
    print("Report     :", path)
    print()
    print(
        "DEMO DATA ONLY — NOT A REAL NETWORK ASSESSMENT"
    )
    print("=" * 60)


if __name__ == "__main__":
    main()
