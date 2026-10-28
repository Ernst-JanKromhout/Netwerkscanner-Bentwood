from datetime import datetime, timedelta, timezone

import requests

from scanner.config import Config
from scanner.db import Database
from scanner.engine import Engine, Sighting
from scanner.report import build_report
from scanner.security import login_notifications, parse_login, parse_threat
from scanner.unifi import UniFiClient, UniFiError, system_log_rows

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


# Een IPS-regel zoals system-log/all van UniFi Network 8.x en later hem geeft.
SYSTEM_LOG_THREAT = {
    "id": "evt-9", "timestamp": 1761480000000, "category": "SECURITY",
    "subcategory": "SECURITY_INTRUSION_PREVENTION", "key": "THREAT_BLOCKED_V3", "event": "THREAT_BLOCKED",
    "title_raw": "Threat Blocked",
    "message_raw": "{SIGNATURE} from {SRC_IP} to {DST_CLIENT} was blocked.",
    "parameters": {
        "SRC_IP": {"id": "45.1.2.3", "name": "45.1.2.3"},
        "SRC_PORT": {"id": "51234", "name": "51234"},
        "DST_CLIENT": {"id": "00:11:32:00:00:01", "ip": "192.168.1.250", "name": "nas"},
        "DST_PORT": {"id": "5001", "name": "5001"},
        "SIGNATURE": {"id": "2009582", "name": "ET SCAN Nmap Scripting Engine"},
        "CATEGORY": {"id": "scan", "name": "Attempted Information Leak"},
    },
}
FIREWALL_BLOCK = {**SYSTEM_LOG_THREAT, "id": "evt-10", "subcategory": "SECURITY_FIREWALL",
                  "key": "TRAFFIC_BLOCKED_KNOWN_SOURCE_CLIENT"}


class FakeResponse:
    def __init__(self, status, data=None, body=None, text=""):
        self.status_code = status
        self._data = data
        self._body = body
        self.text = text

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(str(self.status_code))

    def json(self):
        return self._body if self._body is not None else {"data": self._data}


def unifi_client():
    client = UniFiClient(Config(unifi_host="h", unifi_username="u", unifi_password="p"))
    client.base = "https://h"
    client.api_prefix = "/proxy/network"
    return client


def test_parse_threat_from_system_log():
    t = parse_threat(SYSTEM_LOG_THREAT)
    assert (t.key, t.ts_ms, t.src, t.dst) == ("evt-9", 1761480000000, "45.1.2.3:51234", "192.168.1.250:5001")
    assert t.signature == "ET SCAN Nmap Scripting Engine" and t.category == "Attempted Information Leak"
    assert t.blocked
    bare = parse_threat({"id": "x", "timestamp": 1761480000, "subcategory": "SECURITY_INTRUSION_PREVENTION",
                         "key": "THREAT_DETECTED", "message_raw": "Scan from {SRC_IP}",
                         "parameters": {"SRC_IP": {"name": "1.2.3.4"}}})
    assert bare.ts_ms == 1761480000000 and bare.signature == "Scan from 1.2.3.4" and not bare.blocked


def test_threat_records_reads_system_log_and_skips_firewall_blocks():
    client = unifi_client()
    calls = []

    def post(url, json=None, **kw):
        calls.append((url, json))
        return FakeResponse(200, body={"data": [SYSTEM_LOG_THREAT, FIREWALL_BLOCK], "total_element_count": 2})

    client.session.post = post
    records = client.threat_records(1000, 2000)
    assert [r["id"] for r in records] == ["evt-9"]
    url, body = calls[0]
    assert url == "https://h/proxy/network/v2/api/site/default/system-log/all"
    assert body["timestampFrom"] == 1000 and body["timestampTo"] == 2000
    assert body["categories"] == ["SECURITY"] and body["subcategories"] == ["SECURITY_INTRUSION_PREVENTION"]


def test_threat_records_error_names_every_endpoint():
    client = unifi_client()
    client.session.post = lambda url, **kw: FakeResponse(404, text="Not Found")
    client.session.get = lambda url, **kw: FakeResponse(400, text='{"meta":{"rc":"error","msg":"api.err.Invalid"}}')
    try:
        client.threat_records(0, 10)
    except UniFiError as exc:
        message = str(exc)
    else:
        raise AssertionError("verwachtte een UniFiError")
    assert "system-log: HTTP 404" in message and "stat/ips/event: HTTP 404" in message
    assert "list/alarm: HTTP 400" in message and "api.err.Invalid" in message


def test_system_log_rows_accepts_the_known_shapes():
    assert system_log_rows({"data": [{"id": 1}]}) == [{"id": 1}]
    assert system_log_rows([{"logs": [{"id": 2}]}]) == [{"id": 2}]
    assert system_log_rows([{"id": 3}]) == [{"id": 3}]
    assert system_log_rows({"total_element_count": 0}) == []
    for bad in ({"meta": {"rc": "error"}}, "tekst", {"data": "x"}):
        try:
            system_log_rows(bad)
        except UniFiError:
            continue
        raise AssertionError(f"{bad!r} had een fout moeten geven")


def test_threat_records_falls_back_to_alarms():
    client = UniFiClient(Config(unifi_host="h", unifi_username="u", unifi_password="p"))
    client.base = "https://h"
    client.session.post = lambda url, **kw: FakeResponse(404)
    client.session.get = lambda url, **kw: FakeResponse(200, [
        {"key": "EVT_IPS_IpsAlert", "time": 1}, {"key": "EVT_AP_Lost_Contact", "time": 2}])
    assert [r["key"] for r in client.threat_records(0, 10)] == ["EVT_IPS_IpsAlert"]
