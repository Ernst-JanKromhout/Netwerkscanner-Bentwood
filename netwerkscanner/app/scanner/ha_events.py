"""Luistert via de websocket van Home Assistant naar de knoppen en naar meldingen over mislukte logins."""

from __future__ import annotations

import json
import logging
import threading
import time
from typing import Callable

from .homeassistant import supervisor_token
from .review import EVENT_TYPES

log = logging.getLogger(__name__)

WS_URL = "ws://supervisor/core/websocket"
NOTIFICATIONS = "persistent_notification"  # event_type waaronder we meldingen doorgeven
_NOTIFICATIONS_ID = 100


# Zo vaak een ping als er niets binnenkomt. Blijft het antwoord uit, dan is de verbinding stuk.
PING_SECONDS = 30
_PING_ID_START = 1000


def _connect(url: str):
    import websocket  # alleen in de add-on nodig

    return websocket.create_connection(url, timeout=30), (websocket.WebSocketTimeoutException, TimeoutError)


class EventListener(threading.Thread):
    """Zonder ping zou een half weggevallen verbinding eeuwig blijven wachten, en reageren de knoppen
    stilletjes niet meer. Daarom elke PING_SECONDS een ping, en opnieuw verbinden als er geen pong komt."""

    def __init__(self, on_event: Callable[[str, dict], None], url: str = WS_URL,
                 on_status: Callable[[bool, str | None], None] | None = None, connect=_connect,
                 ping_seconds: float = PING_SECONDS):
        super().__init__(daemon=True, name="ha-events")
        self.on_event = on_event
        self.url = url
        self.on_status = on_status or (lambda ok, error: None)
        self.connect = connect
        self.ping_seconds = ping_seconds
        self.authenticated = False

    def run(self) -> None:
        delay = 5
        while True:
            self.authenticated = False
            try:
                self._listen()
            except Exception as exc:  # verbinding weg of HA herstart: opnieuw proberen
                if self.authenticated:
                    delay = 5
                log.warning("Websocket naar HA verbroken: %s (opnieuw over %d s)", exc, delay)
                self.on_status(False, f"websocket: {exc}")
            time.sleep(delay)
            delay = min(delay * 2, 300)

    def _listen(self) -> None:
        ws, timeouts = self.connect(self.url)
        try:
            ws.recv()  # auth_required
            ws.send(json.dumps({"type": "auth", "access_token": supervisor_token()}))
            reply = json.loads(ws.recv())
            if reply.get("type") != "auth_ok":
                raise RuntimeError(f"websocket-authenticatie mislukt: {reply.get('type')}")
            for i, event_type in enumerate(EVENT_TYPES, start=1):
                ws.send(json.dumps({"id": i, "type": "subscribe_events", "event_type": event_type}))
            ws.send(json.dumps({"id": _NOTIFICATIONS_ID, "type": "persistent_notification/subscribe"}))
            self.authenticated = True
            self.on_status(True, None)
            log.info("Luistert naar knoppen en naar mislukte logins")
            ws.settimeout(self.ping_seconds)
            ping_id = _PING_ID_START
            waiting_for_pong = False
            while True:
                try:
                    message = json.loads(ws.recv())
                except timeouts:
                    if waiting_for_pong:
                        raise RuntimeError(f"geen antwoord van HA binnen {self.ping_seconds:.0f} s") from None
                    ping_id += 1
                    ws.send(json.dumps({"id": ping_id, "type": "ping"}))
                    waiting_for_pong = True
                    continue
                waiting_for_pong = False  # elk bericht bewijst dat de verbinding leeft
                if message.get("type") == "pong":
                    self.on_status(True, None)
                    continue
                if message.get("type") != "event":
                    continue
                event = message.get("event", {})
                try:
                    if message.get("id") == _NOTIFICATIONS_ID:
                        self.on_event(NOTIFICATIONS, event)
                    else:
                        self.on_event(event.get("event_type", ""), event.get("data", {}))
                except Exception:
                    log.exception("Verwerken van HA-event mislukt")
        finally:
            ws.close()
