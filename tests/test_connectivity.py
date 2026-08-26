from assessment.connectivity import (
    connection_state,
    gateway_from_connection_info,
    gateway_from_routes,
)


def test_gateway_from_routes():
    routes = """default via 192.168.1.1 dev wlan0
192.168.1.0/24 dev wlan0 proto kernel scope link src 192.168.1.10"""

    assert gateway_from_routes(routes) == "192.168.1.1"


def test_gateway_missing():
    routes = """192.168.1.0/24 dev wlan0 proto kernel"""

    assert gateway_from_routes(routes) is None


def test_gateway_ipv4():
    routes = """default via 10.0.0.1 dev wlan0"""

    assert gateway_from_routes(routes) == "10.0.0.1"


def test_gateway_does_not_guess_from_termux():
    connection = {
        "available": True,
        "data": {
            "ssid": "LAB-NET",
            "bssid": "02:00:00:00:00:01",
            "ip": "192.168.10.20",
        },
    }

    assert gateway_from_connection_info(connection) is None


def test_connection_not_connected_unknown_ssid():
    connection = {
        "available": True,
        "data": {
            "ssid": "<unknown ssid>",
            "bssid": None,
            "ip": "0.0.0.0",
        },
    }

    assert connection_state(connection) == "NOT_CONNECTED"


def test_connection_not_connected_zero_ip():
    connection = {
        "available": True,
        "data": {
            "ssid": "LAB-NET",
            "bssid": "02:00:00:00:00:01",
            "ip": "0.0.0.0",
        },
    }

    assert connection_state(connection) == "NOT_CONNECTED"


def test_connection_dhcp_acquired():
    connection = {
        "available": True,
        "data": {
            "ssid": "LAB-NET",
            "bssid": "02:00:00:00:00:01",
            "ip": "192.168.10.20",
        },
    }

    assert connection_state(connection) == "DHCP_ACQUIRED"


def test_connection_api_unavailable():
    connection = {
        "available": False,
        "reason": "API unavailable",
    }

    assert connection_state(connection) == "UNKNOWN"


def test_routes_permission_denied_is_unavailable():
    from assessment.connectivity import get_routes

    routes = get_routes()

    # Android/Termux may deny netlink access.
    # The function must report this rather than crash.
    assert "available" in routes
    assert isinstance(routes["available"], bool)


def test_connection_state_does_not_treat_ssid_visibility_as_access():
    connection = {
        "available": True,
        "data": {
            "ssid": "VISIBLE-NETWORK",
            "bssid": "02:00:00:00:00:01",
            "ip": "0.0.0.0",
        },
    }

    assert connection_state(connection) == "NOT_CONNECTED"
