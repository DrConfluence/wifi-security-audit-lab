import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from wifi_scan import (
    classify_security,
    frequency_to_band,
    frequency_to_channel,
)


def test_wpa2_classification():
    capabilities = "[WPA2-PSK-CCMP-128][RSN-PSK-CCMP-128][ESS]"
    assert classify_security(capabilities) == "WPA2"


def test_wpa3_classification():
    capabilities = "[WPA3-SAE-CCMP-128][ESS]"
    assert classify_security(capabilities) == "WPA3"


def test_wep_classification():
    capabilities = "[WEP][ESS]"
    assert classify_security(capabilities) == "WEP"


def test_open_network_classification():
    assert classify_security("[ESS]") == "OPEN"


def test_unknown_security():
    assert classify_security("") == "UNKNOWN"


def test_24ghz_band():
    assert frequency_to_band(2412) == "2.4GHz"


def test_5ghz_band():
    assert frequency_to_band(5180) == "5GHz"


def test_channel_1():
    assert frequency_to_channel(2412) == 1


def test_channel_6():
    assert frequency_to_channel(2437) == 6


def test_channel_11():
    assert frequency_to_channel(2462) == 11


def test_channel_36():
    assert frequency_to_channel(5180) == 36


def test_channel_149():
    assert frequency_to_channel(5745) == 149
