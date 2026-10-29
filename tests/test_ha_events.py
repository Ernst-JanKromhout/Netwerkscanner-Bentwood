import json

import pytest

from scanner import ha_events
from scanner.ha_events import EventListener


class Timeout(Exception):
    pass


class FakeWS:
    """Geeft de berichten uit `script` terug; None betekent: niets binnen de tijd."""

    def __init__(self, script):
        self.script = list(script)
        self.sent = []
        self.closed = False

    def recv(self):
        if not self.script:
            raise ConnectionError("dicht")
        item = self.script.pop(0)
        if item is None:
            raise Timeout()
        return json.dumps(item)

    def send(self, text):
        self.sent.append(json.loads(text))

    def settimeout(self, seconds):
        self.timeout = seconds

    def close(self):
        self.closed = True


@pytest.fixture(autouse=True)
def token(monkeypatch):
    monkeypatch.setattr(ha_events, "supervisor_token", lambda: "x")


def listener(ws, events, statuses):
    return EventListener(lambda t, d: events.append((t, d)), on_status=lambda ok, e: statuses.append(ok),
                         connect=lambda url: (ws, (Timeout,)), ping_seconds=30)


def test_ping_when_quiet_and_reconnect_without_pong():
    ws = FakeWS([{"type": "auth_required"}, {"type": "auth_ok"}, None, {"id": 1001, "type": "pong"},
                 {"id": 1, "type": "event", "event": {"event_type": "netwerkscanner_review",
                                                      "data": {"action": "approve_all"}}},
                 None, None])
    events, statuses = [], []
    with pytest.raises(RuntimeError, match="geen antwoord van HA"):
        listener(ws, events, statuses)._listen()
    pings = [m for m in ws.sent if m.get("type") == "ping"]
    assert [p["id"] for p in pings] == [1001, 1002]
    assert events == [("netwerkscanner_review", {"action": "approve_all"})]
    assert statuses == [True, True] and ws.closed


def test_failed_connection_reports_fault(monkeypatch):
    statuses = []
    lst = EventListener(lambda t, d: None, on_status=lambda ok, e: statuses.append((ok, e)),
                        connect=lambda url: (_ for _ in ()).throw(OSError("geweigerd")))

    def stop(seconds):
        raise KeyboardInterrupt

    monkeypatch.setattr(ha_events.time, "sleep", stop)
    with pytest.raises(KeyboardInterrupt):
        lst.run()
    assert statuses == [(False, "websocket: geweigerd")]
