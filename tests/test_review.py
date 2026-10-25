from datetime import datetime, timezone

from scanner.config import Config
from scanner.db import Database
from scanner.engine import Engine, Sighting
from scanner.overview import devices, publish
from scanner.report import build_report
from scanner.review import NOTHING_PENDING, SELECT_ENTITY, parse

T0 = datetime(2026, 10, 25, 12, 0, tzinfo=timezone.utc)
NAS, CAM = "00:11:32:00:00:01", "da:a1:19:00:00:05"


class FakeHA:
    def __init__(self):
        self.pushes, self.sensors, self.selects = [], {}, {}

    def notify(self, services, title, message, url=None):
        self.pushes.append((title, message, url))
        return True

    def persistent_notification(self, notification_id, title, message):
        self.notifications = getattr(self, "notifications", []) + [(notification_id, message)]
        return True

    def set_sensor(self, entity_id, state, attributes):
        self.sensors[entity_id] = (state, attributes)

    def set_select_options(self, entity_id, options):
        self.selects[entity_id] = options
        return True


def setup(tmp_path, trusted=()):
    db = Database(tmp_path / "t.db")
    ha = FakeHA()
    engine = Engine(db, Config(notify_services=["notify.mobile_app_telefoon"], trusted_macs=set(trusted)), ha)
    engine.handle_sightings([Sighting(NAS, "192.168.1.10", "nas")], "unifi", T0)
    engine.handle_sightings([Sighting(CAM, "192.168.1.40", "camera")], "unifi", T0)
    return db, engine, ha


def test_parse_push_and_dashboard_events():
    assert parse("mobile_app_notification_action", {"action": f"NWS_APPROVE_{CAM}"}) is None
    assert parse("netwerkscanner_review", {"action": "reject", "device": f"camera (192.168.1.40) {CAM}"}) == ("reject", CAM)
    assert parse("netwerkscanner_review", {"action": "approve", "device": NOTHING_PENDING}) is None
    assert parse("netwerkscanner_review", {"action": "approve_all"}) == ("approve_all", None)


def test_push_links_to_dashboard(tmp_path):
    _, _, ha = setup(tmp_path)
    title, message, url = ha.pushes[0]
    assert url == "/beveiliging/netwerk"
    assert "dashboard Beveiliging" in message
    notification_id, text = ha.notifications[0]
    assert notification_id.startswith("netwerkscanner_")
    assert "(/beveiliging/netwerk)" in text


def test_approve_and_reject(tmp_path):
    db, engine, _ = setup(tmp_path)
    assert engine.review("approve", CAM, T0) == 1
    assert db.device(CAM)["trusted"] == 1
    assert engine.review("reject", CAM, T0) == 1
    assert db.device(CAM)["trusted"] == 0
    assert [d["mac"] for d in db.pending_devices()] == [NAS]
    statuses = {d["mac"]: d["status"] for d in devices(db)}
    assert statuses == {NAS: "te beoordelen", CAM: "afgekeurd"}


def test_approve_all_and_unknown_mac(tmp_path):
    db, engine, _ = setup(tmp_path)
    assert engine.review("approve", "ff:ff:ff:ff:ff:ff", T0) == 0
    assert engine.review("approve_all", None, T0) == 2
    assert db.pending_devices() == []


def test_rejected_beats_trusted_macs_on_restart(tmp_path):
    db, engine, _ = setup(tmp_path, trusted={CAM})
    engine.review("reject", CAM, T0)
    db.set_trusted({CAM})
    assert db.device(CAM)["trusted"] == 0


def test_report_warns_about_rejected_device_online(tmp_path):
    db, engine, _ = setup(tmp_path)
    engine.review("reject", CAM, T0)
    text, _ = build_report(db, "2000", "3000")
    assert text.startswith("Let op: afgekeurde apparaten nog online (1)")
    assert "Afgekeurd (1)" in text


def test_publish_fills_select_with_pending(tmp_path):
    db, engine, ha = setup(tmp_path)
    publish(db, ha)
    assert len(ha.selects[SELECT_ENTITY]) == 2
    assert ha.sensors["sensor.netwerkscanner_te_beoordelen"][0] == 2
    engine.review("approve_all", None, T0)
    publish(db, ha)
    assert ha.selects[SELECT_ENTITY] == [NOTHING_PENDING]
