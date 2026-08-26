from assessment.services import (
    check_tcp,
    validate_url_target,
)


def test_valid_http_target():
    result = validate_url_target("http://192.168.1.1")

    assert result["valid"]
    assert result["hostname"] == "192.168.1.1"
    assert result["port"] == 80


def test_valid_https_target():
    result = validate_url_target("https://192.168.1.1")

    assert result["valid"]
    assert result["port"] == 443


def test_invalid_scheme():
    result = validate_url_target("ftp://192.168.1.1")

    assert not result["valid"]


def test_invalid_target():
    result = validate_url_target("not-a-url")

    assert not result["valid"]


def test_unreachable_tcp_target():
    result = check_tcp("127.0.0.1", 1, timeout=0.2)

    assert result["status"] in ("PASS", "FAIL")
    assert "reachable" in result
