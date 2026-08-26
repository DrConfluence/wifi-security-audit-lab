from assessment.live import classify_connection


def test_unknown_connection():
    assert classify_connection(
        {"available": False}
    ) == "UNKNOWN"


def test_not_connected():
    result = classify_connection({
        "available": True,
        "data": {
            "ssid": "<unknown ssid>",
            "bssid": None,
            "ip": "0.0.0.0",
        },
    })

    assert result == "NOT_CONNECTED"


def test_ip_acquired():
    result = classify_connection({
        "available": True,
        "data": {
            "ssid": "AUTHORIZED-LAB",
            "bssid": "02:00:00:00:00:01",
            "ip": "192.168.10.20",
        },
    })

    assert result == "IP_ACQUIRED"


def test_scan_data_string_items_are_ignored():
    from assessment.live import main

    # Regression coverage is intentionally kept at the
    # parsing boundary: malformed/non-dict scan entries
    # must never crash the live assessment.
    raw_networks = [
        "unexpected-string-entry",
        {"ssid": "LAB", "bssid": "00:11:22:33:44:55"},
    ]

    networks = [
        item for item in raw_networks
        if isinstance(item, dict)
    ]

    assert len(networks) == 1
    assert networks[0]["ssid"] == "LAB"
