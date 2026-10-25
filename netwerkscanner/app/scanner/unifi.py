"""Leest actieve clients uit de UniFi Network-controller (UniFi OS of losse controller)."""

from __future__ import annotations

import logging
from dataclasses import dataclass

import requests
import urllib3

from .config import Config, normalize_mac

log = logging.getLogger(__name__)


@dataclass
class Client:
    mac: str
    ip: str | None
    hostname: str | None
    name: str | None
    vendor: str | None
    network: str | None


class UniFiClient:
    """Werkt met UniFi OS (/api/auth/login) en met de oudere controller op poort 8443."""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.session = requests.Session()
        self.session.verify = cfg.unifi_verify_ssl
        if not cfg.unifi_verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.base: str | None = None
        self.api_prefix = ""

    def _login(self) -> None:
        creds = {"username": self.cfg.unifi_username, "password": self.cfg.unifi_password}
        host = self.cfg.unifi_host
        attempts = [
            (f"https://{host}", "/api/auth/login", "/proxy/network"),
            (f"https://{host}:8443", "/api/login", ""),
        ]
        last_error: Exception | None = None
        for base, login_path, prefix in attempts:
            try:
                resp = self.session.post(base + login_path, json=creds, timeout=15)
                if resp.status_code == 200:
                    csrf = resp.headers.get("X-CSRF-Token")
                    if csrf:
                        self.session.headers["X-CSRF-Token"] = csrf
                    self.base, self.api_prefix = base, prefix
                    log.info("Ingelogd op UniFi via %s%s", base, login_path)
                    return
                last_error = RuntimeError(f"{base}{login_path} gaf HTTP {resp.status_code}")
            except requests.RequestException as exc:
                last_error = exc
        raise RuntimeError(f"Inloggen op UniFi mislukt: {last_error}")

    def _get(self, path: str) -> list[dict]:
        if self.base is None:
            self._login()
        resp = self.session.get(f"{self.base}{self.api_prefix}/api/s/{self.cfg.unifi_site}/{path}", timeout=15)
        if resp.status_code == 401:
            self.base = None
            self._login()
            resp = self.session.get(f"{self.base}{self.api_prefix}/api/s/{self.cfg.unifi_site}/{path}", timeout=15)
        resp.raise_for_status()
        return resp.json().get("data", [])

    def active_clients(self) -> list[Client]:
        """Clients plus de UniFi-apparaten zelf (switches, access points), die niet in stat/sta staan."""
        clients = [parse_client(raw) for raw in self._get("stat/sta") if raw.get("mac")]
        devices = [parse_device(raw) for raw in self._get("stat/device") if raw.get("mac") and raw.get("state") == 1]
        return clients + devices


def parse_device(raw: dict) -> Client:
    """Een UniFi-apparaat; de naam is wat je in UniFi ziet, anders het model (bijv. 'USW Flex Mini')."""
    model = raw.get("model_name") or raw.get("model")
    return Client(
        mac=normalize_mac(raw["mac"]),
        ip=raw.get("ip"),
        hostname=None,
        name=raw.get("name") or model,
        vendor="Ubiquiti",
        network="UniFi-apparaat",
    )


def parse_client(raw: dict) -> Client:
    return Client(
        mac=normalize_mac(raw["mac"]),
        ip=raw.get("ip") or raw.get("last_ip"),
        hostname=raw.get("hostname"),
        name=raw.get("name"),
        vendor=raw.get("oui"),
        network=raw.get("network") or raw.get("essid"),
    )
