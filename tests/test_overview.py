from datetime import datetime, timezone

from scanner.config import Config
from scanner.db import Database
from scanner.engine import Engine, Sighting
from scanner.nmap import Host
from scanner.overview import devices, recent_changes

T0 = datetime(2026, 10, 25, 12, 0, tzinfo=timezone.utc)


class FakeHA:
    def notify(self, services, title, message, url=None):
        return True

    def persistent_notification(self, notification_id, title, message):
        return True


def test_devices_with_latest_ports_online_first(tmp_path):
    db = Database(tmp_path / "t.db")
    engine = Engine(db, Config(), FakeHA())
    engine.handle_sightings([
        Sighting("00:11:32:00:00:01", "192.168.1.10", "nas", vendor="Synology"),
        Sighting("00:11:32:00:00:02", "192.168.1.9", "printer"),
    ], "unifi", T0)
    engine.handle_scan("00:11:32:00:00:01", "192.168.1.10", "top",
                       Host("192.168.1.10", True, ports={(22, "tcp"): {"service": "ssh"}}), 5, T0)
    engine.handle_scan("00:11:32:00:00:01", "192.168.1.10", "top",
                       Host("192.168.1.10", True, ports={(443, "tcp"): {"service": "https"}}), 5, T0)
    db.set_present("00:11:32:00:00:02", False)

    rows = devices(db)
    assert [r["naam"] for r in rows] == ["nas", "printer"]
    assert rows[0]["poorten"] == ["443/tcp https"]
    assert rows[0]["gescand"] and not rows[1]["gescand"]
    assert rows[1]["online"] is False


def test_recent_changes_newest_first(tmp_path):
    db = Database(tmp_path / "t.db")
    engine = Engine(db, Config(), FakeHA())
    engine.handle_sightings([Sighting("00:11:32:00:00:01", "192.168.1.10", "nas")], "unifi", T0)
    engine.handle_sightings([Sighting("00:11:32:00:00:05", "192.168.1.40", "camera")], "unifi", T0)
    changes = recent_changes(db)
    assert changes[0]["type"] == "new_device" and "camera" in changes[0]["tekst"]
    assert changes[0]["soort"] == "Nieuwe apparaten"
    assert changes[-1]["type"] == "baseline"
