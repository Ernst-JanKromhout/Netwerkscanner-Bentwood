"""Leest actieve clients uit de UniFi Network-controller (UniFi OS of losse controller)."""

from __future__ import annotations

import logging
from dataclasses import dataclass

import requests
import urllib3

from .config import Config, normalize_mac
from .security import IPS_SUBCATEGORY, is_ips_alarm

log = logging.getLogger(__name__)

# Nieuwere UniFi Network-versies (8.x en later) zetten IPS-meldingen in het systeemlog van de v2-API.
SYSTEM_LOG_PAGE_SIZE = 100
SYSTEM_LOG_MAX_PAGES = 5


class UniFiError(Exception):
    """UniFi antwoordde, maar niet bruikbaar. Bij de volgende ronde gewoon opnieuw."""


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

    def _get(self, path: str, body: dict | None = None) -> list[dict]:
        """GET, of POST met `body` (sommige stat-endpoints willen een tijdvak in de body)."""
        if self.base is None:
            self._login()

        def call():
            url = f"{self.base}{self.api_prefix}/api/s/{self.cfg.unifi_site}/{path}"
            if body is None:
                return self.session.get(url, timeout=15)
            return self.session.post(url, json=body, timeout=15)

        resp = self._send(call, path)
        try:
            return resp.json().get("data", [])
        except ValueError as exc:
            raise UniFiError(f"onvolledig antwoord op {path}: {exc}") from exc

    def _post_v2(self, path: str, body: dict):
        """POST naar de v2-API (/v2/api/site/<site>/...) en geeft de JSON terug."""
        if self.base is None:
            self._login()

        def call():
            url = f"{self.base}{self.api_prefix}/v2/api/site/{self.cfg.unifi_site}/{path}"
            return self.session.post(url, json=body, timeout=15)

        resp = self._send(call, path)
        try:
            return resp.json()
        except ValueError as exc:
            raise UniFiError(f"onvolledig antwoord op {path}: {exc}") from exc

    def _send(self, call, path: str):
        """Voert de aanvraag uit, logt na een verlopen sessie opnieuw in en geeft bij een fout de reden van UniFi mee."""
        resp = call()
        if resp.status_code == 401:
            self.base = None
            self._login()
            resp = call()
        if resp.status_code >= 400:
            reason = (getattr(resp, "text", "") or "").strip().replace("\n", " ")[:200]
            raise requests.HTTPError(f"HTTP {resp.status_code} op {path}" + (f": {reason}" if reason else ""),
                                     response=resp)
        return resp

    def active_clients(self) -> list[Client]:
        """Clients plus de UniFi-apparaten zelf (switches, access points), die niet in stat/sta staan."""
        clients = [parse_client(raw) for raw in self._get("stat/sta") if raw.get("mac")]
        devices = [parse_device(raw) for raw in self._get("stat/device") if raw.get("mac") and raw.get("state") == 1]
        return clients + devices


    def threat_records(self, since_ms: int, now_ms: int) -> list[dict]:
        """IPS-meldingen sinds `since_ms`.

        Eerst het systeemlog van de v2-API (UniFi Network 8.x en later), dan de oude endpoints
        stat/ips/event en list/alarm. Lukt geen enkele, dan een fout met de reden van elk.
        """
        errors = []
        try:
            return self._system_log_threats(since_ms, now_ms)
        except (requests.HTTPError, UniFiError) as exc:
            errors.append(f"system-log: {exc}")
        try:
            return self._get("stat/ips/event", {"start": since_ms, "end": now_ms, "_limit": 500})
        except (requests.HTTPError, UniFiError) as exc:
            errors.append(f"stat/ips/event: {exc}")
        try:
            return [r for r in self._get("list/alarm") if is_ips_alarm(r)]
        except (requests.HTTPError, UniFiError) as exc:
            errors.append(f"list/alarm: {exc}")
        raise UniFiError("geen enkele manier om IPS-meldingen te lezen werkt (" + "; ".join(errors) + ")")

    def _system_log_threats(self, since_ms: int, now_ms: int) -> list[dict]:
        """IPS-regels uit het systeemlog. De categorie SECURITY bevat ook gewone firewallblokkades,
        daarom filteren we zelf nog eens op de subcategorie."""
        found: dict = {}
        for page in range(SYSTEM_LOG_MAX_PAGES):
            answer = self._post_v2("system-log/all", {
                "timestampFrom": since_ms,
                "timestampTo": now_ms,
                "categories": ["SECURITY"],
                "subcategories": [IPS_SUBCATEGORY],
                "pageNumber": page,
                "pageSize": SYSTEM_LOG_PAGE_SIZE,
            })
            rows = system_log_rows(answer)
            for row in rows:
                if row.get("subcategory") == IPS_SUBCATEGORY:
                    found.setdefault(row.get("id") or id(row), row)
            if len(rows) < SYSTEM_LOG_PAGE_SIZE:
                break
        else:
            log.warning("Meer dan %d IPS-meldingen sinds de vorige ronde, alleen de eerste gelezen",
                        SYSTEM_LOG_PAGE_SIZE * SYSTEM_LOG_MAX_PAGES)
        return list(found.values())


def system_log_rows(answer) -> list[dict]:
    """De regels uit een systeemlog-antwoord: een object met 'data' of 'logs', zo'n object in een lijst,
    of een kale lijst met regels."""
    if isinstance(answer, list) and len(answer) == 1 and isinstance(answer[0], dict) \
            and ({"data", "logs"} & answer[0].keys()):
        answer = answer[0]
    if isinstance(answer, dict):
        if "data" not in answer and "logs" not in answer:
            # Een lege uitslag heeft soms alleen tellers; alleen een teller van 0 betekent 'niets'.
            counts = [answer.get(k) for k in ("total_element_count", "totalElementCount")]
            if 0 in counts:
                return []
        answer = answer.get("data", answer.get("logs"))
    if not isinstance(answer, list) or not all(isinstance(r, dict) for r in answer):
        raise UniFiError("onverwacht antwoord van system-log/all")
    return answer


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
