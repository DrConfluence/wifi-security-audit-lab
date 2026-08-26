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
