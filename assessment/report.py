#!/usr/bin/env python3

import json
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
REPORT_DIR = BASE_DIR / "evidence"


def build_report(session, connectivity=None, services=None):
    connectivity = connectivity or {}
    services = services or []

    service_passes = sum(
        1 for item in services
        if item.get("status") == "PASS"
    )

    return {
        "assessment_id": session["assessment_id"],
        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "target": {
            "ssid": session.get("ssid"),
            "bssid": session.get("bssid"),
        },
        "authorization": {
            "reference": session.get(
                "authorization_ref"
            ),
            "status": session.get(
                "scope_status"
            ),
        },
        "phase_1": {
            "connection_state": connectivity.get(
                "connection_state",
                "NOT_AVAILABLE",
            ),
            "gateway": connectivity.get(
                "gateway"
            ),
            "gateway_status": connectivity.get(
                "gateway_test",
                {},
            ).get(
                "status",
                "NOT_AVAILABLE",
            ),
        },
        "phase_2": {
            "services_tested": len(services),
            "services_reachable": service_passes,
            "results": services,
        },
    }


def write_report(report):
    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    path = REPORT_DIR / (
        f"{report['assessment_id']}_report.json"
    )

    path.write_text(
        json.dumps(
            report,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    return path
