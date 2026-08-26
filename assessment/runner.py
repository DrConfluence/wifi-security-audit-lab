#!/usr/bin/env python3

from pathlib import Path

from assessment.engine import run_assessment
from assessment.report import build_report, write_report
from assessment.findings import generate_findings
from assessment.executive import build_executive_summary

BASE_DIR = Path(__file__).resolve().parent.parent


def run_end_to_end(
    ssid,
    bssid=None,
    authorization_ref=None,
    phase2_host=None,
    phase2_ports=(53, 80, 443),
):
    result = run_assessment(
        ssid=ssid,
        bssid=bssid,
        authorization_ref=authorization_ref,
    )

    session = result["session"]
    connectivity = result.get("connectivity", {})

    services = []

    if phase2_host:
        from assessment.services import assess_authorized_services

        services = assess_authorized_services(
            phase2_host,
            ports=phase2_ports,
        )

    report = build_report(
        session=session,
        connectivity=connectivity,
        services=services,
    )

    findings = generate_findings(
        connectivity,
        services,
    )

    report["findings"] = findings
    report["executive"] = build_executive_summary(report)

    report_path = write_report(report)

    summary = {
        "assessment_id": session["assessment_id"],
        "ssid": session.get("ssid"),
        "bssid": session.get("bssid"),
        "authorization_ref": session.get(
            "authorization_ref"
        ),
        "scope_status": session.get(
            "scope_status"
        ),
        "connection_state": connectivity.get(
            "connection_state",
            "NOT_AVAILABLE",
        ),
        "gateway": connectivity.get(
            "gateway"
        ),
        "gateway_status": connectivity.get(
            "gateway_test", {}
        ).get(
            "status",
            "NOT_AVAILABLE",
        ),
        "services_tested": len(services),
        "services_reachable": sum(
            1
            for item in services
            if item.get("status") == "PASS"
        ),
        "findings": len(findings),
        "overall_status": report[
            "executive"
        ]["overall_status"],
        "report_path": str(report_path),
    }

    return {
        "assessment_id": session["assessment_id"],
        "ssid": session.get("ssid"),
        "authorization_ref": session.get(
            "authorization_ref"
        ),
        "connection_state": connectivity.get(
            "connection_state",
            "NOT_AVAILABLE",
        ),
        "gateway": connectivity.get(
            "gateway"
        ),
        "gateway_status": connectivity.get(
            "gateway_test", {}
        ).get(
            "status",
            "NOT_AVAILABLE",
        ),
        "services_tested": len(services),
        "services_reachable": summary[
            "services_reachable"
        ],
        "findings": findings,
        "executive": report["executive"],
        "report": report,
        "report_path": str(report_path),
    }
