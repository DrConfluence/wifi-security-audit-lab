from assessment.executive import build_executive_summary


def test_blocked_summary():
    report = {
        "phase_1": {
            "connection_state": "NOT_CONNECTED",
            "gateway_status": "NOT_AVAILABLE",
        },
        "phase_2": {
            "services_tested": 0,
            "services_reachable": 0,
        },
        "findings": [
            {
                "status": "BLOCKED",
            }
        ],
    }

    result = build_executive_summary(report)

    assert result["overall_status"] == "BLOCKED"
    assert result["findings_blocked"] == 1


def test_verified_summary():
    report = {
        "phase_1": {
            "connection_state": "DHCP_ACQUIRED",
            "gateway_status": "PASS",
        },
        "phase_2": {
            "services_tested": 2,
            "services_reachable": 1,
        },
        "findings": [
            {
                "status": "VERIFIED",
            }
        ],
    }

    result = build_executive_summary(report)

    assert result["overall_status"] == "PARTIAL"
    assert result["services_reachable"] == 1
