import pytest

from assessment.engine import start_assessment


def test_authorized_assessment_session():
    session = start_assessment(
        ssid="LAB-NET",
        bssid="02:00:00:00:00:01",
        authorization_ref="LAB-001",
    )

    assert session["scope_status"] == "AUTHORIZED"
    assert session["ssid"] == "LAB-NET"


def test_missing_authorization_is_rejected():
    with pytest.raises(PermissionError):
        start_assessment(
            ssid="LAB-NET",
            bssid="02:00:00:00:00:01",
            authorization_ref=None,
        )
