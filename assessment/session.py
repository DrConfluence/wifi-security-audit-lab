#!/usr/bin/env python3

import uuid
from datetime import datetime, timezone


def create_session(ssid, bssid=None, authorization_ref=None):
    return {
        "assessment_id": f"WA-{uuid.uuid4().hex[:10].upper()}",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "ssid": ssid,
        "bssid": bssid,
        "authorization_ref": authorization_ref,
        "scope_status": (
            "AUTHORIZED"
            if authorization_ref
            else "UNAUTHORIZED"
        ),
    }


def is_in_scope(session):
    return (
        bool(session.get("ssid"))
        and bool(session.get("authorization_ref"))
        and session.get("scope_status") == "AUTHORIZED"
    )
