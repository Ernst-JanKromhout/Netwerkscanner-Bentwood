from datetime import datetime, timedelta, timezone

from scanner.config import Config
from scanner.db import Database
from scanner.engine import Engine, Sighting
from scanner.health import Health
from scanner.report import build_report

T0 = datetime(2026, 10, 29, 12, 0, tzinfo=timezone.utc)


class FakeHA:
    def __init__(self, up=True):
        self.up = up
        self.pushes = []
        self.notes = []

    def notify(self, services, title, message, url=None):
        if self.up:
            self.pushes.append((title, message))
        return self.up

    def persistent_notification(self, notification_id, title, message):
        if self.up:
            self.notes.append((notification_id, title))
        return self.up


def engine(tmp_path, ha):
    return Engine(Database(tmp_path / "t.db"), Config(notify_services=["notify.test"]), ha)


def test_fault_alerts_once_after_30_minutes_and_recovery_once():
    h = Health()
    h.ok("unifi", T0)
    h.fail("unifi", "HTTP 401", T0 + timedelta(minutes=1))
    assert h.check(T0 + timedelta(minutes=20)) == []
    assert h.summary()[0] == "werkt"  # korte hapering is nog geen storing
    [t] = h.check(T0 + timedelta(minutes=31))
    assert (t.source, t.ok, t.error) == ("unifi", False, "HTTP 401")
    h.fail("unifi", "HTTP 401", T0 + timedelta(minutes=40))
    assert h.check(T0 + timedelta(minutes=45)) == []
    state, rows = h.summary()
    assert state == "storing" and rows[0]["fout"] == "HTTP 401" and not rows[0]["werkt"]
    h.ok("unifi", T0 + timedelta(minutes=50))
    [back] = h.check(T0 + timedelta(minutes=51))
    assert back.ok and h.summary()[0] == "werkt"
    assert h.check(T0 + timedelta(minutes=52)) == []


def test_ips_that_never_worked_does_not_alert():
    h = Health()
    h.fail("threats", "geen enkele manier werkt", T0)
    assert h.check(T0 + timedelta(hours=2)) == []
    h.fail("unifi", "weg", T0)
    assert [t.source for t in h.check(T0 + timedelta(hours=2))] == ["unifi"]


def test_health_transitions_push_and_land_in_report(tmp_path):
    ha = FakeHA()
    e = engine(tmp_path, ha)
    h = Health()
    h.fail("unifi", "inloggen mislukt", T0)
    e.handle_health(h.check(T0 + timedelta(minutes=31)), T0 + timedelta(minutes=31))
    h.ok("unifi", T0 + timedelta(hours=1))
    e.handle_health(h.check(T0 + timedelta(hours=1)), T0 + timedelta(hours=1))
    assert [p[0] for p in ha.pushes] == ["Netwerkscanner: storing bij UniFi-controller",
                                         "Netwerkscanner: UniFi-controller werkt weer"]
    assert "Beoordeel" not in ha.pushes[0][1]
    text, _ = build_report(e.db, "2000", "3000")
    assert "Storingen van de scanner (1)\n- UniFi-controller: inloggen mislukt" in text


def test_failed_push_is_retried_when_ha_is_back(tmp_path):
    ha = FakeHA(up=False)
    e = engine(tmp_path, ha)
    e.handle_sightings([Sighting("00:11:32:00:00:01", "192.168.1.10")], "unifi", T0)  # beginsituatie
    e.handle_sightings([Sighting("00:11:32:00:00:02", "192.168.1.11")], "unifi", T0)
    assert ha.pushes == [] and len(e.db.outbox()) == 1
    assert e.retry_pushes(T0 + timedelta(minutes=1)) == 0  # nog steeds weg
    ha.up = True
    assert e.retry_pushes(T0 + timedelta(minutes=2)) == 1
    assert [p[0] for p in ha.pushes] == ["Nieuw apparaat op je netwerk"] and len(ha.notes) == 1
    assert e.db.outbox() == []
    assert e.db.conn.execute("SELECT notified FROM events WHERE type = 'new_device'").fetchone()[0] == 1


def test_old_failed_pushes_expire_after_a_day(tmp_path):
    ha = FakeHA(up=False)
    e = engine(tmp_path, ha)
    e.db.queue_push("2026-10-27T12:00:00+00:00", None, "oud", "tekst", None)
    assert e.retry_pushes(T0) == 0 and e.db.outbox() == []


def test_rejected_device_coming_back_is_pushed(tmp_path):
    ha = FakeHA()
    e = engine(tmp_path, ha)
    mac = "00:11:32:00:00:01"
    e.handle_sightings([Sighting(mac, "192.168.1.10", name="Vreemde laptop")], "unifi", T0)
    e.review("reject", mac, T0)
    e.check_absent(T0 + timedelta(hours=25))
    e.handle_sightings([Sighting(mac, "192.168.1.44")], "unifi", T0 + timedelta(hours=26))
    [(title, message)] = ha.pushes
    assert title == "Afgekeurd apparaat weer online"
    assert "Vreemde laptop (192.168.1.44" in message and "Beoordeel" not in message
