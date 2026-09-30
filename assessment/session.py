#!/usr/bin/env python3

import csv
import uuid
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
AUTH_FILE = BASE_DIR / "authorized_networks.csv"

DISALLOWED_REFS = {
    "",
    "none",
    "null",
    "undefined",
    "default",
    "test",
    "authorized-lab",
}


def load_authorizations(auth_file=None):
    """
    Load scope records from an authorization file.
    Fails closed if the file is missing, empty, malformed, or invalid.
    Never falls back to authorized_networks.example.csv or any default file.
    """
    path = Path(auth_file) if auth_file else AUTH_FILE
    if not path.exists() or not path.is_file():
        return {}

    authorizations = {}
    try:
        with path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            required = {"ssid", "bssid", "authorization_ref", "scope"}
            if not reader.fieldnames or not required.issubset(set(reader.fieldnames)):
                return {}
            valid_count = 0
            for row in reader:
                if not row:
                    continue
                bssid = (row.get("bssid") or "").strip().lower()
                ssid = (row.get("ssid") or "").strip()
                ref = (row.get("authorization_ref") or "").strip()
                scope = (row.get("scope") or "").strip()
                if not ref or ref.lower() in DISALLOWED_REFS:
                    continue
                if not ssid and not bssid:
                    continue
                rec = {
                    "ssid": ssid,
                    "bssid": bssid,
                    "authorization_ref": ref,
                    "scope": scope,
                }
                if bssid:
                    authorizations.setdefault(bssid, []).append(rec)
                if ssid:
                    authorizations.setdefault(ssid.lower(), []).append(rec)
                valid_count += 1
            if valid_count == 0:
                return {}
    except Exception:
        return {}
    return authorizations


def validate_scope(ssid, bssid=None, authorization_ref=None, auth_file=None):
    """
    Explicitly validate that a target (SSID/BSSID) is covered by the authorization reference.
    Fails closed if the reference is empty, generic, or not found in the recorded scope.
    """
    if not authorization_ref or not str(authorization_ref).strip():
        return False, "Missing explicit authorization reference"

    cleaned_ref = str(authorization_ref).strip()
    if cleaned_ref.lower() in DISALLOWED_REFS:
        return False, f"Invalid or generic authorization reference: '{authorization_ref}'"

    if not ssid and not bssid:
        return False, "Target SSID or BSSID must be specified"

    auths = load_authorizations(auth_file)
    if not auths:
        return False, "Authorization scope file not found or contains no records"

    bssid_key = (bssid or "").strip().lower()
    if bssid_key and bssid_key in auths:
        entries = auths[bssid_key]
        if any(e["authorization_ref"].lower() == cleaned_ref.lower() for e in entries):
            return True, "Authorized by BSSID match"
        return False, f"Authorization reference '{cleaned_ref}' does not match record for BSSID {bssid}"

    ssid_key = (ssid or "").strip().lower()
    if ssid_key and ssid_key in auths:
        entries = auths[ssid_key]
        if any(e["authorization_ref"].lower() == cleaned_ref.lower() for e in entries):
            return True, "Authorized by SSID match"
        return False, f"Authorization reference '{cleaned_ref}' does not match record for SSID {ssid}"

    return False, f"Target '{ssid or bssid}' is not in recorded authorization scope"


def create_session(ssid, bssid=None, authorization_ref=None, auth_file=None):
    valid, reason = validate_scope(
        ssid=ssid,
        bssid=bssid,
        authorization_ref=authorization_ref,
        auth_file=auth_file,
    )
    return {
        "assessment_id": f"WA-{uuid.uuid4().hex[:10].upper()}",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "ssid": ssid,
        "bssid": bssid,
        "authorization_ref": authorization_ref,
        "scope_status": "AUTHORIZED" if valid else "UNAUTHORIZED",
        "scope_reason": reason,
    }


def is_in_scope(session):
    return (
        bool(session.get("ssid"))
        and bool(session.get("authorization_ref"))
        and session.get("scope_status") == "AUTHORIZED"
    )
