"""Praat met Home Assistant via de Supervisor-proxy: meldingen, rapport en sensoren."""

from __future__ import annotations

import logging
import os

import requests

log = logging.getLogger(__name__)


class HomeAssistant:
    def __init__(self, base_url: str = "http://supervisor/core/api", token: str | None = None):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers["Authorization"] = f"Bearer {token or os.environ.get('SUPERVISOR_TOKEN', '')}"

    def call_service(self, service: str, data: dict) -> bool:
        domain, _, name = service.partition(".")
        try:
            resp = self.session.post(f"{self.base_url}/services/{domain}/{name}", json=data, timeout=15)
            resp.raise_for_status()
            return True
        except requests.RequestException as exc:
            log.warning("Service %s mislukt: %s", service, exc)
            return False

    def notify(self, services: list[str], title: str, message: str) -> bool:
        """Stuurt naar elke dienst; geslaagd als er minstens één aankwam."""
        delivered = False
        for service in services:
            data = {"title": title, "message": message}
            if service.startswith("telegram_bot."):
                data["parse_mode"] = "plain_text"
            delivered = self.call_service(service, data) or delivered
        return delivered

    def persistent_notification(self, notification_id: str, title: str, message: str) -> bool:
        return self.call_service(
            "persistent_notification.create",
            {"notification_id": notification_id, "title": title, "message": message},
        )

    def set_sensor(self, entity_id: str, state, attributes: dict) -> None:
        try:
            resp = self.session.post(
                f"{self.base_url}/states/{entity_id}",
                json={"state": state, "attributes": attributes},
                timeout=15,
            )
            resp.raise_for_status()
        except requests.RequestException as exc:
            log.warning("Sensor %s bijwerken mislukt: %s", entity_id, exc)
