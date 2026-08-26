#!/usr/bin/env python3

from datetime import datetime, timezone

from assessment.connectivity import (
    collect_connectivity_evidence,
)
from assessment.evidence import (
    create_evidence,
    write_evidence,
)
from assessment.report import (
    build_report,
    write_report,
)
from assessment.session import (
    create_session,
    is_in_scope,
)
from assessment.services import (
    assess_authorized_services,
)


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def start_assessment(
    ssid,
    bssid=None,
    authorization_ref=None,
):
    session = create_session(
        ssid=ssid,
        bssid=bssid,
        authorization_ref=authorization_ref,
    )

    if not is_in_scope(session):
        raise PermissionError(
            "Assessment target is outside the recorded authorization scope"
        )

    return session


def run_phase1(session):
    return collect_connectivity_evidence(
        assessment_id=session["assessment_id"],
        ssid=session["ssid"],
        bssid=session.get("bssid"),
        authorization_ref=session["authorization_ref"],
    )


def run_phase2(session, host, ports=(53, 80, 443)):
    if not is_in_scope(session):
        raise PermissionError(
            "Phase 2 target is outside the recorded authorization scope"
        )

    results = assess_authorized_services(
        host,
        ports=ports,
    )

    evidence = create_evidence(
        session,
        {
            "service_validation": {
                "status": "COMPLETE",
                "host": host,
                "results": results,
            }
        },
    )

    write_evidence(evidence)

    return results


def complete_report(session, connectivity, services):
    report = build_report(
        session=session,
        connectivity=connectivity,
        services=services,
    )

    return write_report(report)


def run_assessment(
    ssid,
    bssid=None,
    authorization_ref=None,
    phase2_host=None,
):
    session = start_assessment(
        ssid,
        bssid,
        authorization_ref,
    )

    connectivity = run_phase1(session)

    services = []

    if phase2_host:
        services = run_phase2(
            session,
            phase2_host,
        )

    report_path = complete_report(
        session,
        connectivity,
        services,
    )

    return {
        "session": session,
        "connectivity": connectivity,
        "services": services,
        "report": str(report_path),
        "completed_at": utc_now(),
    }
