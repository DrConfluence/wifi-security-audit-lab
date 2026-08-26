from assessment.findings import generate_findings


def test_not_connected_finding():
    findings = generate_findings(
        {
            "connection_state": "NOT_CONNECTED",
            "gateway_test": {
                "status": "NOT_AVAILABLE",
            },
        },
        [],
    )

    assert findings[0]["id"] == "CONN-001"
    assert findings[0]["status"] == "BLOCKED"


def test_gateway_verified():
    findings = generate_findings(
        {
            "connection_state": "DHCP_ACQUIRED",
            "gateway_test": {
                "status": "PASS",
            },
        },
        [],
    )

    assert any(
        item["id"] == "NET-001"
        for item in findings
    )


def test_service_verified():
    findings = generate_findings(
        {
            "connection_state": "DHCP_ACQUIRED",
            "gateway_test": {
                "status": "PASS",
            },
        },
        [
            {
                "service": "HTTP",
                "port": 80,
                "status": "PASS",
            }
        ],
    )

    assert any(
        item["id"] == "SVC-80"
        for item in findings
    )
