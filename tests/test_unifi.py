import http.server
import ssl
import subprocess
import threading

import pytest
import requests

from scanner.config import Config
from scanner.unifi import Pins, UniFiClient, UniFiError, parse_client, parse_device, server_fingerprint


def test_parse_unifi_device_uses_name_or_model():
    d = parse_device({"mac": "D8:B3:70:00:00:01", "ip": "192.168.1.110", "model": "USMINI",
                      "model_name": "USW Flex Mini", "state": 1})
    assert (d.mac, d.ip, d.name, d.vendor) == ("d8:b3:70:00:00:01", "192.168.1.110", "USW Flex Mini", "Ubiquiti")
    named = parse_device({"mac": "d8:b3:70:00:00:02", "name": "Switch zolder", "model": "USMINI"})
    assert named.name == "Switch zolder"


def test_parse_client_falls_back_to_last_ip():
    c = parse_client({"mac": "AA:BB:CC:DD:EE:FF", "last_ip": "192.168.1.5", "hostname": "tv", "oui": "Samsung"})
    assert (c.mac, c.ip, c.hostname, c.vendor) == ("aa:bb:cc:dd:ee:ff", "192.168.1.5", "tv", "Samsung")


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def test_failed_login_backs_off_instead_of_retrying_every_minute(tmp_path):
    clock = Clock()
    client = UniFiClient(Config(unifi_host="h", unifi_username="u", unifi_password="fout", unifi_verify_ssl=True),
                         clock=clock)
    calls = []

    class Resp:
        status_code = 401
        headers = {}

    client.session.post = lambda url, **kw: calls.append(url) or Resp()
    with pytest.raises(UniFiError, match="opnieuw over 60 s"):
        client._login()
    assert len(calls) == 2  # UniFi OS en de oude controller
    with pytest.raises(UniFiError, match="volgende poging over 60 s"):
        client._login()
    assert len(calls) == 2  # niet opnieuw geprobeerd
    clock.now += 61
    with pytest.raises(UniFiError, match="opnieuw over 120 s"):
        client._login()
    clock.now += 121
    with pytest.raises(UniFiError, match="opnieuw over 300 s"):
        client._login()


@pytest.fixture(scope="module")
def https_server(tmp_path_factory):
    """Een HTTPS-server met een zelfondertekend certificaat, zoals een Cloud Key."""
    d = tmp_path_factory.mktemp("tls")
    key, cert = d / "key.pem", d / "cert.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=unifi",
                    "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True)

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1]
    server.shutdown()


def pinned_client(port, pins_path, fingerprint=""):
    client = UniFiClient(Config(unifi_host="127.0.0.1", unifi_username="u", unifi_password="p",
                                unifi_fingerprint=fingerprint), pins=Pins(pins_path))
    base = f"https://127.0.0.1:{port}"
    client._pin(base, "127.0.0.1", port)
    return client, base


def test_certificate_is_pinned_on_first_use_and_then_enforced(https_server, tmp_path):
    pins = tmp_path / "pins.json"
    client, base = pinned_client(https_server, pins)
    assert client.session.post(base + "/api/login", json={}, timeout=5).status_code == 200
    assert server_fingerprint("127.0.0.1", https_server) in pins.read_text()

    # Een andere controller (of iemand die zich ervoor uitgeeft) met hetzelfde adres: geweigerd.
    pins.write_text('{"127.0.0.1:%d": "%s"}' % (https_server, "00" * 32))
    client, base = pinned_client(https_server, pins)
    with pytest.raises(requests.exceptions.SSLError, match="(?i)fingerprint"):
        client.session.post(base + "/api/login", json={}, timeout=5)
    assert "is veranderd (nu " in client._mismatch("127.0.0.1", https_server)


def test_fingerprint_option_overrides_stored_pin(https_server, tmp_path):
    pins = tmp_path / "pins.json"
    pins.write_text('{"127.0.0.1:%d": "%s"}' % (https_server, "00" * 32))
    real = server_fingerprint("127.0.0.1", https_server)
    colons = ":".join(real[i:i + 2] for i in range(0, 64, 2)).upper()
    client, base = pinned_client(https_server, pins, fingerprint=colons)
    assert client.session.post(base + "/api/login", json={}, timeout=5).status_code == 200
