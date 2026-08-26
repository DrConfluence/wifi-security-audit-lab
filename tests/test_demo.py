from assessment.executive import build_executive_summary


def test_demo_summary_is_partial():
    report = {
        "phase_1": {
            "connection_state": "DHCP_ACQUIRED",
            "gateway_status": "PASS",
        },
        "phase_2": {
            "services_tested": 3,
            "services_reachable": 2,
        },
        "findings": [
            {"status": "VERIFIED"},
            {"status": "VERIFIED"},
        ],
    }

    result = build_executive_summary(report)

    assert result["overall_status"] == "PARTIAL"
    assert result["services_tested"] == 3
    assert result["services_reachable"] == 2
