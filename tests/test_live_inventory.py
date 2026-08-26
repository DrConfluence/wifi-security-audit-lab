from assessment.live_inventory import (
    gateway_from_routes,
    subnet_from_ip,
)


def test_gateway_from_ip_route():
    text = "default via 192.168.10.1 dev wlan0"
    assert gateway_from_routes(
        {
            "stdout": text,
            "available": True,
        }
    ) == "192.168.10.1"


def test_gateway_from_proc_route():
    text = (
        "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU "
        "Window IRTT\n"
        "wlan0 00000000 010AA8C0 0003 0 0 0 00000000 0 0 0\n"
    )

    assert gateway_from_routes(
        {
            "stdout": text,
            "available": True,
        }
    ) == "192.168.10.1"


def test_subnet():
    assert str(subnet_from_ip("192.168.10.25")) == "192.168.10.0/24"
