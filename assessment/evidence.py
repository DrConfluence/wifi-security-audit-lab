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


def get_collision_safe_path(target_path):
    """
    Return a collision-safe Path that does not already exist on disk.
    If target_path exists, appends _1, _2, etc. before the suffix.
    """
    target_path = Path(target_path)
    if not target_path.exists():
        return target_path

    parent = target_path.parent
    stem = target_path.stem
    suffix = target_path.suffix

    counter = 1
    while True:
        candidate = parent / f"{stem}_{counter}{suffix}"
        if not candidate.exists():
            return candidate
        counter += 1


def write_collision_safe(target_path, content, encoding="utf-8"):
    """
    Write content to a file atomically without overwriting any existing evidence.
    If target_path already exists (including when multiple writes occur in the same second),
    an incremental suffix (_1, _2, ...) is appended.
    Returns the Path of the newly created file.
    """
    target_path = Path(target_path)
    target_path.parent.mkdir(parents=True, exist_ok=True)

    parent = target_path.parent
    stem = target_path.stem
    suffix = target_path.suffix

    candidate = target_path
    counter = 1
    while True:
        try:
            with candidate.open("x", encoding=encoding) as handle:
                handle.write(content)
            return candidate
        except FileExistsError:
            candidate = parent / f"{stem}_{counter}{suffix}"
            counter += 1


def write_evidence(evidence, collision_safe=False):
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

    assessment_id = evidence["assessment_id"]
    path = EVIDENCE_DIR / f"{assessment_id}.json"

    if collision_safe:
        content = json.dumps(evidence, indent=2, ensure_ascii=False)
        return write_collision_safe(path, content)

    if path.exists():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(existing, dict):
                merged_obs = existing.get("observations") or {}
                new_obs = evidence.get("observations") or {}
                if isinstance(merged_obs, dict) and isinstance(new_obs, dict):
                    updated_obs = dict(merged_obs)
                    updated_obs.update(new_obs)
                    evidence["observations"] = updated_obs
                if "created_at" in existing:
                    evidence["created_at"] = existing["created_at"]
                elif "timestamp" in existing:
                    evidence["created_at"] = existing["timestamp"]
        except Exception:
            pass

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
