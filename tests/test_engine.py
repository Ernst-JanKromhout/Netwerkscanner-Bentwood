from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from scanner import vendor

from scanner.config import Config
from scanner.db import Database
from scanner.engine import Engine, Sighting
from scanner.nmap import Host
from scanner.report import build_report

T0 = datetime(2026, 10, 25, 12, 0, tzinfo=timezone.utc)


class FakeHA:
    def __init__(self):
        self.pushes = []

    def notify(self, services, title, message, url=None):
        self.pushes.append((title, message, url))
        return True

    def persistent_notification(self, notification_id, title, message):
        self.notifications = getattr(self, "notifications", []) + [(notification_id, message)]
        return True


@pytest.fixture(autouse=True)
def prefixes(monkeypatch):
    monkeypatch.setattr(vendor, "_default", vendor.PrefixTable(Path(__file__).parent / "fixtures" / "mac-prefixes"))


@pytest.fixture
def setup(tmp_path):
    db = Database(tmp_path / "test.db")
    cfg = Config(notify_services=["notify.test"], trusted_macs={"00:11:32:00:00:99"})
    ha = FakeHA()
    scans = []
    engine = Engine(db, cfg, ha, lambda mac, ip, kind: scans.append((mac, ip, kind)))
    # Beginsituatie: twee bekende apparaten, zonder meldingen.
    engine.handle_sightings([
        Sighting("00:11:32:00:00:01", "192.168.1.10", "nas", vendor="Synology"),
        Sighting("00:11:32:00:00:99", "192.168.1.20", "pc"),
    ], "unifi", T0)
    return db, engine, ha, scans


def test_bootstrap_records_without_pushing(setup):
    db, _, ha, scans = setup
    assert db.device_count() == 2
    assert ha.pushes == []
    assert len(scans) == 2
    assert [e["type"] for e in db.events_between("2000", "3000")] == ["baseline"]
    assert db.device("00:11:32:00:00:99")["trusted"] == 1


def test_new_device_pushes_and_requests_scan(setup):
    db, engine, ha, scans = setup
    engine.handle_sightings([Sighting("da:a1:19:00:00:05", "192.168.30.40", "unknown")], "unifi", T0)
    assert ha.pushes[0][0] == "Nieuw apparaat op je netwerk"
    assert "privé" in ha.pushes[0][1]
    assert scans[-1] == ("da:a1:19:00:00:05", "192.168.30.40", "top")
    event = db.events_between("2000", "3000")[-1]
    assert event["type"] == "new_device" and event["notified"] == 1


def test_port_opened_pushes_only_for_untrusted(setup):
    db, engine, ha, _ = setup
    for mac, ip in (("00:11:32:00:00:01", "192.168.1.10"), ("00:11:32:00:00:99", "192.168.1.20")):
        engine.handle_scan(mac, ip, "top", Host(ip, True, ports={(22, "tcp"): {"service": "ssh"}}), 5, T0)
        engine.handle_scan(mac, ip, "top", Host(ip, True, ports={(22, "tcp"): {"service": "ssh"},
                                                                 (23, "tcp"): {"service": "telnet"}}), 5, T0)
    types = [e["type"] for e in db.events_between("2000", "3000")]
    assert types.count("first_scan") == 2
    assert types.count("port_opened") == 2
    assert len(ha.pushes) == 1
    assert "23/tcp" in ha.pushes[0][1] and "nas" in ha.pushes[0][1]


def test_unreachable_host_does_not_close_ports(setup):
    db, engine, _, _ = setup
    mac, ip = "00:11:32:00:00:01", "192.168.1.10"
    engine.handle_scan(mac, ip, "top", Host(ip, True, ports={(22, "tcp"): {"service": "ssh"}}), 5, T0)
    engine.handle_scan(mac, ip, "top", Host(ip, False), 5, T0)
    engine.handle_scan(mac, ip, "top", Host(ip, True, ports={(22, "tcp"): {"service": "ssh"}}), 5, T0)
    assert "port_closed" not in [e["type"] for e in db.events_between("2000", "3000")]


def test_full_scan_compares_only_with_full_scan(setup):
    db, engine, _, _ = setup
    mac, ip = "00:11:32:00:00:01", "192.168.1.10"
    engine.handle_scan(mac, ip, "top", Host(ip, True, ports={(22, "tcp"): {}}), 5, T0)
    engine.handle_scan(mac, ip, "full", Host(ip, True, ports={(22, "tcp"): {}, (40000, "tcp"): {}}), 5, T0)
    engine.handle_scan(mac, ip, "top", Host(ip, True, ports={(22, "tcp"): {}}), 5, T0)
    assert "port_opened" not in [e["type"] for e in db.events_between("2000", "3000")]


def test_gone_back_and_ip_change(setup):
    db, engine, _, _ = setup
    mac = "00:11:32:00:00:01"
    engine.check_absent(T0 + timedelta(hours=25))
    assert db.device(mac)["present"] == 0
    engine.handle_sightings([Sighting(mac, "192.168.1.11")], "ping", T0 + timedelta(hours=26))
    types = [e["type"] for e in db.events_between("2000", "3000")]
    assert {"device_gone", "device_back", "ip_changed"} <= set(types)
    assert db.device(mac)["present"] == 1


def test_report_groups_events(setup):
    db, engine, _, _ = setup
    engine.handle_sightings([Sighting("da:a1:19:00:00:05", "192.168.30.40", "camera")], "unifi", T0)
    text, count = build_report(db, "2000", "3000")
    assert count == 2
    assert "Nieuwe apparaten (1)" in text and "camera" in text
    assert "Start van de scanner (1)" in text


def test_empty_report(tmp_path):
    text, count = build_report(Database(tmp_path / "leeg.db"), "2000", "3000")
    assert (text, count) == ("Geen wijzigingen.", 0)


def test_dns_name_does_not_flap_against_unifi(setup):
    db, engine, _, _ = setup
    nas = "00:11:32:00:00:01"
    engine.handle_sightings([Sighting(nas, "192.168.1.10", "Cloud-Key-Gen2")], "ping", T0)
    engine.handle_sightings([Sighting(nas, "192.168.1.10", "nas")], "unifi", T0)
    assert db.device(nas)["hostname"] == "nas"
    assert not [e for e in db.recent_events(50) if e["type"] == "hostname_changed"]


FERRARI = "24:fd:fa:10:d2:db"


def test_new_device_with_hidden_vendor_is_flagged(setup):
    db, engine, ha, _ = setup
    engine.handle_sightings([Sighting(FERRARI, "192.168.1.22", "imx8mm-ferrari", network="Default")], "unifi", T0)
    title, message, _ = ha.pushes[-1]
    assert title == "Nieuw apparaat op je netwerk"
    assert "Fabrikant verborgen: prefix 24:FD:FA" in message
    assert "NXP i.MX" in message
    assert "tweede melding" in message
    assert db.device(FERRARI)["vendor"] is None
    detail = db.events_between("2000", "3000")[-1]["detail"]
    assert '"vendor_status": "verborgen"' in detail


def test_known_vendor_is_stored_and_shown(setup):
    db, engine, ha, _ = setup
    engine.handle_sightings([Sighting("b8:27:eb:00:00:01", "192.168.1.30", "kastje")], "unifi", T0)
    assert "Fabrikant: Raspberry Pi Foundation" in ha.pushes[-1][1]
    assert db.device("b8:27:eb:00:00:01")["vendor"] == "Raspberry Pi Foundation"


def test_unifi_private_vendor_is_not_stored(setup):
    db, engine, _, _ = setup
    engine.handle_sightings([Sighting(FERRARI, "192.168.1.22", vendor="Private")], "unifi", T0)
    assert db.device(FERRARI)["vendor"] is None


def test_existing_device_gets_vendor_backfilled(setup):
    db, engine, _, _ = setup
    engine.handle_sightings([Sighting("00:11:32:00:00:99", "192.168.1.20", "pc")], "unifi", T0)
    assert db.device("00:11:32:00:00:99")["vendor"] == "Synology Incorporated"


def test_first_scan_of_new_device_sends_ports(setup):
    _, engine, ha, _ = setup
    engine.handle_sightings([Sighting(FERRARI, "192.168.1.22", "imx8mm-ferrari")], "unifi", T0)
    ports = {(80, "tcp"): {"service": "http"}, (502, "tcp"): {"service": "mbap"}, (23, "tcp"): {"service": "telnet"}}
    engine.handle_scan(FERRARI, "192.168.1.22", "top", Host("192.168.1.22", True, ports=ports), 30, T0)
    title, message, _ = ha.pushes[-1]
    assert title == "Poortscan klaar: imx8mm-ferrari"
    assert "3 open poort(en)" in message
    assert message.index("23/tcp") < message.index("80/tcp")  # hoog risico bovenaan
    assert "hoog risico" in message
    assert "Fabrikant verborgen" in message
    # Een tweede eerste-scan (bijvoorbeeld de volledige) geeft geen extra melding.
    count = len(ha.pushes)
    engine.handle_scan(FERRARI, "192.168.1.22", "top", Host("192.168.1.22", True, ports=ports), 30, T0)
    assert len(ha.pushes) == count


def test_first_scan_unreachable_then_result(setup):
    _, engine, ha, _ = setup
    engine.handle_sightings([Sighting(FERRARI, "192.168.1.22", "imx8mm-ferrari")], "unifi", T0)
    engine.handle_scan(FERRARI, "192.168.1.22", "top", Host("192.168.1.22", False), 30, T0)
    assert ha.pushes[-1][0] == "Poortscan: imx8mm-ferrari reageerde niet"
    engine.handle_scan(FERRARI, "192.168.1.22", "top", Host("192.168.1.22", False), 30, T0)
    assert sum("reageerde niet" in p[0] for p in ha.pushes) == 1
    engine.handle_scan(FERRARI, "192.168.1.22", "top", Host("192.168.1.22", True, ports={}), 30,
                       T0 + timedelta(hours=8))
    assert ha.pushes[-1][0] == "Poortscan klaar: imx8mm-ferrari"
    assert "Geen open poorten" in ha.pushes[-1][1]


def test_first_scan_of_known_or_trusted_device_stays_quiet(setup):
    _, engine, ha, _ = setup
    for mac, ip in (("00:11:32:00:00:01", "192.168.1.10"), ("00:11:32:00:00:99", "192.168.1.20")):
        engine.handle_scan(mac, ip, "top", Host(ip, True, ports={(22, "tcp"): {"service": "ssh"}}), 5, T0)
    assert ha.pushes == []
