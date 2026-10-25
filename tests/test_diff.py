from scanner.diff import diff_identity, diff_ports, is_random_mac


def test_diff_ports_detects_open_close_and_service_change():
    previous = {(22, "tcp"): {"service": "ssh", "version": "OpenSSH 9.5"}, (80, "tcp"): {"service": "http"}}
    current = {(22, "tcp"): {"service": "ssh", "version": "OpenSSH 9.6"}, (443, "tcp"): {"service": "https"}}
    changes = {(c.type, c.detail["port"]) for c in diff_ports(previous, current)}
    assert changes == {("port_opened", 443), ("port_closed", 80), ("service_changed", 22)}


def test_diff_ports_unchanged_is_empty():
    ports = {(22, "tcp"): {"service": "ssh", "version": None}}
    assert diff_ports(ports, dict(ports)) == []


def test_missing_new_value_is_not_a_change():
    assert diff_identity("192.168.1.5", "tv", None, None) == []
    assert [c.type for c in diff_identity("192.168.1.5", "tv", "192.168.1.6", "tv")] == ["ip_changed"]


def test_random_mac():
    assert is_random_mac("da:a1:19:00:00:01")
    assert not is_random_mac("00:11:32:aa:bb:cc")
