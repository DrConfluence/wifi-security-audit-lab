#!/usr/bin/env python3

from datetime import datetime, timezone


def build_executive_summary(report):
    phase1 = report.get("phase_1", {})
    phase2 = report.get("phase_2", {})
    findings = report.get("findings", [])

    connection = phase1.get(
        "connection_state",
        "NOT_AVAILABLE",
    )

    gateway = phase1.get(
        "gateway_status",
        "NOT_AVAILABLE",
    )

    services_tested = phase2.get(
        "services_tested",
        0,
    )

    services_reachable = phase2.get(
        "services_reachable",
        0,
    )

    blocked = sum(
        1
        for item in findings
        if item.get("status") == "BLOCKED"
    )

    verified = sum(
        1
        for item in findings
        if item.get("status") == "VERIFIED"
    )

    if blocked:
        overall = "BLOCKED"
    elif verified:
        overall = "PARTIAL"
    else:
        overall = "NOT_ESTABLISHED"

    return {
        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "overall_status": overall,
        "connection_state": connection,
        "gateway_status": gateway,
        "services_tested": services_tested,
        "services_reachable": services_reachable,
        "findings_total": len(findings),
        "findings_verified": verified,
        "findings_blocked": blocked,
        "assessment_statement": (
            "Assessment evidence was collected within "
            "the recorded authorization scope. "
            "Unavailable platform telemetry is reported "
            "as unavailable rather than inferred."
        ),
    }
