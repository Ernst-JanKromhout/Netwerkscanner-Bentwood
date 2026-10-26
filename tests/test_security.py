from datetime import datetime, timedelta, timezone

import requests

from scanner.config import Config
from scanner.db import Database
from scanner.engine import Engine, Sighting
from scanner.report import build_report
from scanner.security import login_notifications, parse_login, parse_threat
from scanner.unifi import UniFiClient

T0 = datetime(2026, 10, 26, 12, 0, tzinfo=timezone.utc)
IPS_EVENT = {
    "_id": "abc", "timestamp": 1761480000000, "src_ip": "45.1.2.3", "src_port": 51234,
    "dest_ip": "192.168.1.250", "dest_port": 5001, "inner_alert_signature": "ET SCAN Nmap Scripting Engine",
    "inner_alert_category": "Attempted Information Leak", "inner_alert_action": "blocked",
}


class FakeHA:
    def __init__(self):
        self.pushes = []

    def notify(self, services, title, message, url=None):
        self.pushes.append((title, message))
        return True

    def persistent_notification(self, notification_id, title, message):
        return True


def test_parse_threat_from_ips_event_and_alarm():
    t = parse_threat(IPS_EVENT)
    assert (t.key, t.src, t.dst, t.blocked) == ("abc", "45.1.2.3:51234", "192.168.1.250:5001", True)
    alarm = parse_threat({"time": 1761480000, "key": "EVT_IPS_IpsAlert", "msg": "Port scan", "src_ip": "1.2.3.4"})
    assert alarm.ts_ms == 1761480000000 and alarm.signature == "Port scan" and not alarm.blocked
    assert parse_threat({"msg": "zonder tijd"}) is None


def test_parse_login_and_only_new_notifications():
    msg = "Login attempt or request with invalid authentication from evil.example (203.0.113.9). Requested URL: '/'."
    assert parse_login(msg) == ("evil.example", "203.0.113.9")
    assert parse_login("iets anders") is None
    added = {"type": "added", "notifications": {"http-login": {"message": msg}, "other": {"message": "x"}}}
    assert login_notifications(added) == [msg]
    assert login_notifications({**added, "type": "current"}) == []


def test_threats_are_stored_once_with_one_push(tmp_path):
    db = Database(tmp_path / "t.db")
    ha = FakeHA()
    engine = Engine(db, Config(), ha)
    engine.handle_sightings([Sighting("00:11:32:00:00:01", "192.168.1.250", "nas")], "unifi", T0)
    second = {**IPS_EVENT, "_id": "def", "timestamp": IPS_EVENT["timestamp"] + 1000, "inner_alert_action": "alert"}
    threats = [parse_threat(IPS_EVENT), parse_threat(second)]

    assert engine.handle_threats(threats, T0) == 2
    assert engine.handle_threats(threats, T0) == 0
    assert len(ha.pushes) == 1
    title, message = ha.pushes[0]
    assert title == "2 aanvallen op je netwerk" and "1 van 2 geblokkeerd" in message
    assert "nas (192.168.1.250:5001)" in message
    report, count = build_report(db, "2000", "2100")
    assert "Aanvallen (IPS van de gateway) (2)" in report


def test_failed_login_push_at_most_hourly_per_ip(tmp_path):
    db = Database(tmp_path / "t.db")
    ha = FakeHA()
    engine = Engine(db, Config(), ha)
    engine.handle_failed_login("evil", "203.0.113.9", T0)
    engine.handle_failed_login("evil", "203.0.113.9", T0 + timedelta(minutes=10))
    engine.handle_failed_login("other", "203.0.113.10", T0 + timedelta(minutes=10))
    engine.handle_failed_login("evil", "203.0.113.9", T0 + timedelta(minutes=61))
    assert len(ha.pushes) == 3
    report, count = build_report(db, "2000", "2100")
    assert count == 4 and "Mislukte inlogpogingen op Home Assistant (4)" in report


class FakeResponse:
    def __init__(self, status, data=None):
        self.status_code = status
        self._data = data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(str(self.status_code))

    def json(self):
        return {"data": self._data}


def test_threat_records_falls_back_to_alarms():
    client = UniFiClient(Config(unifi_host="h", unifi_username="u", unifi_password="p"))
    client.base = "https://h"
    client.session.post = lambda url, **kw: FakeResponse(404)
    client.session.get = lambda url, **kw: FakeResponse(200, [
        {"key": "EVT_IPS_IpsAlert", "time": 1}, {"key": "EVT_AP_Lost_Contact", "time": 2}])
    assert [r["key"] for r in client.threat_records(0, 10)] == ["EVT_IPS_IpsAlert"]
