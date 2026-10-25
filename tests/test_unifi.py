from scanner.unifi import parse_client, parse_device


def test_parse_unifi_device_uses_name_or_model():
    d = parse_device({"mac": "D8:B3:70:00:00:01", "ip": "192.168.1.110", "model": "USMINI",
                      "model_name": "USW Flex Mini", "state": 1})
    assert (d.mac, d.ip, d.name, d.vendor) == ("d8:b3:70:00:00:01", "192.168.1.110", "USW Flex Mini", "Ubiquiti")
    named = parse_device({"mac": "d8:b3:70:00:00:02", "name": "Switch zolder", "model": "USMINI"})
    assert named.name == "Switch zolder"


def test_parse_client_falls_back_to_last_ip():
    c = parse_client({"mac": "AA:BB:CC:DD:EE:FF", "last_ip": "192.168.1.5", "hostname": "tv", "oui": "Samsung"})
    assert (c.mac, c.ip, c.hostname, c.vendor) == ("aa:bb:cc:dd:ee:ff", "192.168.1.5", "tv", "Samsung")
