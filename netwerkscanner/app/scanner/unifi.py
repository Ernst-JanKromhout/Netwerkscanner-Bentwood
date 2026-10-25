"""Leest actieve clients uit de UniFi Network-controller (Cloud Key Gen2)."""

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

    def active_clients(self) -> list[Client]:
        if self.base is None:
            self._login()
        url = f"{self.base}{self.api_prefix}/api/s/{self.cfg.unifi_site}/stat/sta"
        resp = self.session.get(url, timeout=15)
        if resp.status_code == 401:
            self.base = None
            self._login()
            resp = self.session.get(f"{self.base}{self.api_prefix}/api/s/{self.cfg.unifi_site}/stat/sta", timeout=15)
        resp.raise_for_status()
        return [parse_client(raw) for raw in resp.json().get("data", []) if raw.get("mac")]


def parse_client(raw: dict) -> Client:
    return Client(
        mac=normalize_mac(raw["mac"]),
        ip=raw.get("ip") or raw.get("last_ip"),
        hostname=raw.get("hostname"),
        name=raw.get("name"),
        vendor=raw.get("oui"),
        network=raw.get("network") or raw.get("essid"),
    )
