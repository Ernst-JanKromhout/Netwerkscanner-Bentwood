"""Praat met Home Assistant via de Supervisor-proxy: meldingen, rapport en sensoren."""

from __future__ import annotations

import logging
import os
from pathlib import Path

import requests

log = logging.getLogger(__name__)

# s6-overlay start CMD met een schone omgeving; de echte variabelen staan hier.
S6_ENV_DIR = Path("/run/s6/container_environment")


def supervisor_token(env_dir: Path = S6_ENV_DIR) -> str:
    token = os.environ.get("SUPERVISOR_TOKEN")
    if token:
        return token
    try:
        return (env_dir / "SUPERVISOR_TOKEN").read_text().strip()
    except OSError:
        log.error("Geen SUPERVISOR_TOKEN gevonden: meldingen en sensoren werken niet")
        return ""


class HomeAssistant:
    def __init__(self, base_url: str = "http://supervisor/core/api", token: str | None = None):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers["Authorization"] = f"Bearer {token or supervisor_token()}"

    def call_service(self, service: str, data: dict) -> bool:
        domain, _, name = service.partition(".")
        try:
            resp = self.session.post(f"{self.base_url}/services/{domain}/{name}", json=data, timeout=15)
            resp.raise_for_status()
            return True
        except requests.RequestException as exc:
            log.warning("Service %s mislukt: %s", service, exc)
            return False

    def notify(self, services: list[str], title: str, message: str, actions: list[dict] | None = None) -> bool:
        """Stuurt naar elke dienst; geslaagd als er minstens één aankwam.

        Knoppen (`actions`) gaan alleen mee naar de HA-app (notify.mobile_app_*).
        """
        delivered = False
        for service in services:
            data = {"title": title, "message": message}
            if service.startswith("telegram_bot."):
                data["parse_mode"] = "plain_text"
            if actions and service.startswith("notify.mobile_app_"):
                data["data"] = {"actions": actions}
            delivered = self.call_service(service, data) or delivered
        return delivered

    def persistent_notification(self, notification_id: str, title: str, message: str) -> bool:
        return self.call_service(
            "persistent_notification.create",
            {"notification_id": notification_id, "title": title, "message": message},
        )

    def set_select_options(self, entity_id: str, options: list[str]) -> bool:
        return self.call_service("input_select.set_options", {"entity_id": entity_id, "options": options})

    def time_zone(self) -> str | None:
        """Tijdzone uit de HA-configuratie, bijvoorbeeld 'Europe/Amsterdam'."""
        try:
            resp = self.session.get(f"{self.base_url}/config", timeout=15)
            resp.raise_for_status()
            return resp.json().get("time_zone")
        except (requests.RequestException, ValueError) as exc:
            log.warning("Tijdzone ophalen mislukt: %s", exc)
            return None

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
