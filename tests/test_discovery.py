from assessment.discovery import (
    band_from_frequency,
    normalize_network,
    security_class,
)


def test_band_24():
    assert band_from_frequency(2462) == "2.4 GHz"


def test_band_5():
    assert band_from_frequency(5300) == "5 GHz"


def test_wpa2_wpa3():
    caps = "[WPA2-PSK-CCMP-128][RSN-PSK+SAE-CCMP-128][ESS]"
    assert security_class(caps) == "WPA2/WPA3"


def test_wps_detection():
    network = normalize_network({
        "ssid": "LAB",
        "bssid": "00:11:22:33:44:55",
        "frequency_mhz": 2462,
        "rssi": -50,
        "capabilities": "[WPA2-PSK-CCMP-128][WPS][ESS]",
    })

    assert network["security"] == "WPA2"
    assert network["wps_advertised"] is True
    assert network["band"] == "2.4 GHz"


def test_open_unspecified():
    assert security_class("[ESS]") == "OPEN/UNSPECIFIED"
