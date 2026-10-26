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


class EventListener(threading.Thread):
    def __init__(self, on_event: Callable[[str, dict], None], url: str = WS_URL):
        super().__init__(daemon=True, name="ha-events")
        self.on_event = on_event
        self.url = url

    def run(self) -> None:
        delay = 5
        while True:
            try:
                self._listen()
                delay = 5
            except Exception as exc:  # verbinding weg of HA herstart: opnieuw proberen
                log.warning("Websocket naar HA verbroken: %s (opnieuw over %d s)", exc, delay)
            time.sleep(delay)
            delay = min(delay * 2, 300)

    def _listen(self) -> None:
        import websocket  # alleen in de add-on nodig

        ws = websocket.create_connection(self.url, timeout=30)
        try:
            ws.recv()  # auth_required
            ws.send(json.dumps({"type": "auth", "access_token": supervisor_token()}))
            reply = json.loads(ws.recv())
            if reply.get("type") != "auth_ok":
                raise RuntimeError(f"websocket-authenticatie mislukt: {reply.get('type')}")
            for i, event_type in enumerate(EVENT_TYPES, start=1):
                ws.send(json.dumps({"id": i, "type": "subscribe_events", "event_type": event_type}))
            ws.send(json.dumps({"id": _NOTIFICATIONS_ID, "type": "persistent_notification/subscribe"}))
            log.info("Luistert naar knoppen en naar mislukte logins")
            ws.settimeout(None)
            while True:
                message = json.loads(ws.recv())
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
