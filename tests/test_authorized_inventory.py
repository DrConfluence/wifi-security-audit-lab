from assessment.authorized_inventory import network_from_ip

def test_network_from_ip():
    assert str(network_from_ip("172.22.25.69")) == "172.22.25.0/24"

def test_invalid_ip():
    assert network_from_ip("0.0.0.0") is None
