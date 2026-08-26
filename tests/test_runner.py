from assessment.runner import run_end_to_end


def test_runner_without_phase2(monkeypatch):
    def fake_run_assessment(**kwargs):
        return {
            "session": {
                "assessment_id": "WA-TEST",
                "ssid": kwargs["ssid"],
                "authorization_ref": kwargs["authorization_ref"],
            },
            "connectivity": {
                "connection_state": "NOT_CONNECTED",
                "gateway": None,
                "gateway_test": {
                    "status": "NOT_AVAILABLE",
                },
            },
            "services": [],
        }

    monkeypatch.setattr(
        "assessment.runner.run_assessment",
        fake_run_assessment,
    )

    result = run_end_to_end(
        ssid="LAB-NET",
        authorization_ref="LAB-001",
    )

    assert result["assessment_id"] == "WA-TEST"
    assert result["connection_state"] == "NOT_CONNECTED"
    assert result["services_tested"] == 0
