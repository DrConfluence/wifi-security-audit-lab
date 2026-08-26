#!/usr/bin/env python3

import json
from datetime import datetime, timezone
from pathlib import Path

from assessment.engine import run_assessment
from assessment.report import build_report, write_report
from assessment.findings import generate_findings

BASE_DIR = Path(__file__).resolve().parent.parent
RUN_DIR = BASE_DIR / "evidence"


def now():
    return datetime.now(timezone.utc).isoformat()


def run_end_to_end(
    ssid,
    bssid=None,
    authorization_ref=None,
    phase2_host=None,
):
    started = now()

    result = run_assessment(
        ssid=ssid,
        bssid=bssid,
        authorization_ref=authorization_ref,
        phase2_host=phase2_host,
    )

    session = result["session"]
    connectivity = result["connectivity"]
    services = result["services"]

    findings = generate_findings(
        connectivity,
        services,
    )

    report = build_report(
        session=session,
        connectivity=connectivity,
        services=services,
    )

    report["findings"] = findings

    report["workflow"] = {
        "started_at": started,
        "completed_at": now(),
        "phase_1": "COMPLETE",
        "phase_2": "COMPLETE" if phase2_host else "NOT_RUN",
    }

    report_path = write_report(report)

    summary = {
        "assessment_id": session["assessment_id"],
        "ssid": session["ssid"],
        "authorization_ref": session["authorization_ref"],
        "connection_state": connectivity["connection_state"],
        "gateway": connectivity["gateway"],
        "gateway_status": connectivity["gateway_test"]["status"],
        "services_tested": len(services),
        "services_reachable": sum(
            1
            for item in services
            if item.get("status") == "PASS"
        ),
        "findings": len(findings),
        "report": str(report_path),
    }

    RUN_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    summary_path = (
        RUN_DIR
        / f"{session['assessment_id']}_summary.json"
    )

    summary_path.write_text(
        json.dumps(summary, indent=2),
        encoding="utf-8",
    )

    return summary
