from assessment.live_assessment import (
    classify_band,
    classify_security,
    validate_target,
    verify_association,
)


def test_security_classification():
    assert classify_security(
        "[WPA2-PSK-CCMP-128][RSN-PSK-CCMP-128][ESS]"
    ) == "WPA2"


def test_wpa3_classification():
    assert classify_security(
        "[WPA2-PSK-CCMP-128][RSN-PSK+SAE-CCMP-128][ESS]"
    ) == "WPA2/WPA3"


def test_band():
    assert classify_band(2462) == "2.4 GHz"
    assert classify_band(5300) == "5 GHz"


def test_target_validation():
    scan = {
        "networks": [
            {
                "ssid": "LAB",
                "bssid": "00:11:22:33:44:55",
            }
        ]
    }

    result = validate_target(scan, "LAB")

    assert result["found"] is True
    assert result["count"] == 1


def test_association_requires_ip():
    connection = {
        "available": True,
        "data": {
            "ssid": "LAB",
            "bssid": "00:11:22:33:44:55",
            "ip": "0.0.0.0",
        },
    }

    result = verify_association(
        connection,
        "LAB",
    )

    assert result["associated"] is False


def test_real_association_state():
    connection = {
        "available": True,
        "data": {
            "ssid": "LAB",
            "bssid": "00:11:22:33:44:55",
            "ip": "192.168.1.20",
            "supplicant_state": "COMPLETED",
        },
    }

    result = verify_association(
        connection,
        "LAB",
    )

    assert result["associated"] is True
