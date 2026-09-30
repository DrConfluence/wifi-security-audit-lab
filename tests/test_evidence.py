import json

from assessment.evidence import create_evidence, write_evidence


def test_create_evidence():
    session = {
        "assessment_id": "WA-TEST001",
        "ssid": "LAB-NET",
        "bssid": "02:00:00:00:00:01",
        "authorization_ref": "LAB-001",
        "scope_status": "AUTHORIZED",
    }

    evidence = create_evidence(
        session,
        {"connectivity": {"status": "PASS"}},
    )

    assert evidence["assessment_id"] == "WA-TEST001"
    assert evidence["authorization_ref"] == "LAB-001"
    assert evidence["scope_status"] == "AUTHORIZED"
    assert evidence["observations"]["connectivity"]["status"] == "PASS"


def test_write_evidence(tmp_path, monkeypatch):
    import assessment.evidence as module

    monkeypatch.setattr(module, "EVIDENCE_DIR", tmp_path)

    evidence = {
        "assessment_id": "WA-TEST002",
        "timestamp": "2026-01-01T00:00:00+00:00",
        "observations": {"gateway": {"status": "PASS"}},
    }

    path = write_evidence(evidence)

    assert path.exists()

    loaded = json.loads(path.read_text())
    assert loaded["assessment_id"] == "WA-TEST002"


def test_write_evidence_preserves_prior_observations(tmp_path, monkeypatch):
    import assessment.evidence as module
    from assessment.evidence import record_observation

    monkeypatch.setattr(module, "EVIDENCE_DIR", tmp_path)

    session = {
        "assessment_id": "WA-PRESERVE01",
        "ssid": "LAB-NET",
        "bssid": "02:00:00:00:00:01",
        "authorization_ref": "LAB-001",
        "scope_status": "AUTHORIZED",
    }

    # First observation recorded
    record_observation(session, "connectivity", "PASS", {"latency_ms": 15})
    path = tmp_path / "WA-PRESERVE01.json"
    assert path.exists()

    loaded1 = json.loads(path.read_text(encoding="utf-8"))
    assert "connectivity" in loaded1["observations"]
    assert loaded1["observations"]["connectivity"]["status"] == "PASS"

    # Subsequent observation recorded under same assessment ID
    record_observation(session, "services", "PASS", {"open_ports": [80, 443]})

    loaded2 = json.loads(path.read_text(encoding="utf-8"))
    # Verify prior observation is preserved and not overwritten
    assert "connectivity" in loaded2["observations"]
    assert loaded2["observations"]["connectivity"]["status"] == "PASS"
    assert loaded2["observations"]["connectivity"]["details"]["latency_ms"] == 15
    assert "services" in loaded2["observations"]
    assert loaded2["observations"]["services"]["status"] == "PASS"
