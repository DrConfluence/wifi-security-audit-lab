#!/usr/bin/env python3

import json
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
EVIDENCE_DIR = BASE_DIR / "evidence"


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def create_evidence(session, observations):
    """Create a timestamped evidence record for an authorized assessment."""
    return {
        "assessment_id": session["assessment_id"],
        "timestamp": utc_now(),
        "target": {
            "ssid": session.get("ssid"),
            "bssid": session.get("bssid"),
        },
        "authorization_ref": session.get("authorization_ref"),
        "scope_status": session.get("scope_status"),
        "observations": observations,
    }


def write_evidence(evidence):
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

    assessment_id = evidence["assessment_id"]
    path = EVIDENCE_DIR / f"{assessment_id}.json"

    path.write_text(
        json.dumps(evidence, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    return path


def record_observation(session, name, status, details=None):
    evidence = create_evidence(
        session,
        {
            name: {
                "status": status,
                "details": details or {},
            }
        },
    )

    return write_evidence(evidence)
