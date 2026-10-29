from datetime import datetime, timedelta, timezone

from scanner.config import Config
from scanner.db import Database
from scanner.engine import Engine, Sighting
from scanner.networks import (configured_networks, is_private, parse_network, unifi_networks, unknown_network,
                              wan_networks)
from scanner.overview import publish
from scanner.report import build_report

T0 = datetime(2026, 10, 29, 12, 0, tzinfo=timezone.utc)

NETWORKCONF = [
    {"name": "Default", "purpose": "corporate", "ip_subnet": "192.168.1.1/24"},
    {"name": "IoT", "purpose": "corporate", "ip_subnet": "192.168.30.1/24"},
    {"name": "Internet 1", "purpose": "wan"},
]
GATEWAY = {"name": "Gateway Max", "wan1": {"ip": "192.168.178.2", "netmask": "255.255.255.0"}}


class FakeHA:
    def __init__(self):
        self.pushes = []
        self.sensors = {}

    def notify(self, services, title, message, url=None):
        self.pushes.append((title, message))
        return True

    def persistent_notification(self, notification_id, title, message):
        return True

    def set_sensor(self, entity_id, state, attributes):
        self.sensors[entity_id] = (state, attributes)

    def set_select_options(self, entity_id, options):
        return True


def known(extra=()):
    return unifi_networks(NETWORKCONF) + wan_networks([GATEWAY]) + configured_networks([], list(extra))


def test_known_networks_from_unifi_wan_and_options():
    names = {str(k.network): k.name for k in known(["10.8.0.0/24"])}
    assert names == {"192.168.1.0/24": "Default (UniFi)", "192.168.30.0/24": "IoT (UniFi)",
                     "192.168.178.0/24": "internetkant van Gateway Max (wan1)", "10.8.0.0/24": "zelf goedgekeurd"}
    assert parse_network("geen netwerk") is None and parse_network("fe80::/64") is None


def test_only_private_addresses_outside_known_networks_count():
    k = known()
    assert str(unknown_network("192.168.4.7", k)) == "192.168.4.0/24"
    assert unknown_network("192.168.1.50", k) is None
    assert unknown_network("192.168.178.245", k) is None  # Delta-modem voor de gateway
    assert unknown_network("8.8.8.8", k) is None and unknown_network("169.254.1.2", k) is None
    assert is_private("100.64.1.1") and not is_private("fe80::1")


def test_unknown_network_is_pushed_once_and_clears_when_approved(tmp_path):
    db = Database(tmp_path / "t.db")
    ha = FakeHA()
    e = Engine(db, Config(notify_services=["notify.test"]), ha)
    e.handle_sightings([Sighting("00:11:32:00:00:01", "192.168.1.10", name="NAS")], "unifi", T0)
    e.handle_sightings([Sighting("aa:bb:cc:00:00:01", "192.168.4.2", name="Extender")], "unifi", T0)
    assert e.check_networks(known(), T0) == 1
    assert e.check_networks(known(), T0 + timedelta(minutes=5)) == 0
    titles = [p[0] for p in ha.pushes]
    assert titles.count("Onbekend netwerk 192.168.4.0/24") == 1
    assert "Extender (192.168.4.2, aa:bb:cc:00:00:01)" in ha.pushes[-1][1]

    publish(db, ha)
    state, attrs = ha.sensors["sensor.netwerkscanner_onbekende_netwerken"]
    assert state == 1 and attrs["netwerken"][0]["netwerk"] == "192.168.4.0/24"
    text, _ = build_report(db, "2000", "3000")
    assert "Onbekende netwerken (1)\n- 192.168.4.0/24, gezien bij Extender" in text

    # Zelf goedgekeurd via known_subnets: telt niet meer als onbekend, en geen nieuwe melding.
    e.check_networks(known(["192.168.4.0/24"]), T0 + timedelta(minutes=10))
    publish(db, ha)
    assert ha.sensors["sensor.netwerkscanner_onbekende_netwerken"][0] == 0
    assert db.network("192.168.4.0/24")["known_as"] == "zelf goedgekeurd"


def test_private_address_in_ips_alert_counts(tmp_path):
    db = Database(tmp_path / "t.db")
    e = Engine(db, Config(), FakeHA())
    db.add_event("2026-10-29T11:00:00+00:00", "intrusion", None,
                 {"src": "10.0.0.5:4444", "dst": "192.168.1.10:445", "signature": "x", "blocked": True})
    assert e.check_networks(known(), T0) == 1
    assert db.network("10.0.0.0/24")["example"] == "10.0.0.5 in een IPS-melding"


def test_without_known_networks_nothing_is_flagged(tmp_path):
    db = Database(tmp_path / "t.db")
    e = Engine(db, Config(), FakeHA())
    e.handle_sightings([Sighting("aa:bb:cc:00:00:01", "192.168.4.2")], "unifi", T0)
    assert e.check_networks([], T0) == 0
