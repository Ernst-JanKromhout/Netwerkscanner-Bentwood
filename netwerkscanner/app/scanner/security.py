"""Aanvallen uit de IPS van de UniFi-gateway en mislukte inlogpogingen op Home Assistant."""

from __future__ import annotations

import re
from dataclasses import dataclass

# HA zet bij een mislukte login een melding met dit id en een tekst als
# "Login attempt or request with invalid authentication from host (1.2.3.4). Requested URL: ..."
HA_LOGIN_NOTIFICATION = "http-login"
_LOGIN_FROM = re.compile(r"from (?P<host>\S+) \((?P<ip>[0-9a-fA-F:.]+)\)")

# Subcategorie van IPS-regels in het systeemlog van de v2-API (UniFi Network 8.x en later).
IPS_SUBCATEGORY = "SECURITY_INTRUSION_PREVENTION"
_PLACEHOLDER = re.compile(r"\{(\w+)\}")


@dataclass
class Threat:
    key: str  # uniek per melding, om dubbele te voorkomen
    ts_ms: int
    src: str
    dst: str
    signature: str
    category: str
    blocked: bool

    def detail(self) -> dict:
        return {"src": self.src, "dst": self.dst, "signature": self.signature,
                "category": self.category, "blocked": self.blocked}


def _addr(ip: str | None, port) -> str:
    if not ip:
        return "onbekend"
    return f"{ip}:{port}" if port else ip


def parse_threat(raw: dict) -> Threat | None:
    """Een IPS-melding uit het systeemlog (v2), stat/ips/event of list/alarm van de UniFi-controller."""
    if "parameters" in raw or raw.get("subcategory") == IPS_SUBCATEGORY:
        return _parse_system_log(raw)
    ts = raw.get("timestamp") or raw.get("time")
    if not ts:
        return None
    ts = int(ts)
    if ts < 10**12:  # seconden in plaats van milliseconden
        ts *= 1000
    signature = raw.get("inner_alert_signature") or raw.get("signature") or raw.get("msg") or "onbekende aanval"
    category = raw.get("inner_alert_category") or raw.get("catname") or raw.get("category") or ""
    action = str(raw.get("inner_alert_action") or raw.get("action") or "").lower()
    src = _addr(raw.get("src_ip"), raw.get("src_port"))
    dst = _addr(raw.get("dest_ip") or raw.get("dst_ip"), raw.get("dest_port") or raw.get("dst_port"))
    key = str(raw.get("_id") or f"{ts}-{src}-{dst}-{signature}")
    return Threat(key, ts, src, dst, signature, category, blocked=action in ("blocked", "drop", "dropped", "block"))


def _param(params: dict, *names: str) -> dict:
    for name in names:
        value = params.get(name)
        if isinstance(value, dict):
            return value
    return {}


def _param_addr(params: dict, names: tuple[str, ...], port_names: tuple[str, ...]) -> str:
    p = _param(params, *names)
    ip = p.get("ip") or p.get("id") or p.get("name")
    port_param = _param(params, *port_names)
    port = port_param.get("name") or port_param.get("id")
    return _addr(ip, port)


def _render(template: str | None, params: dict) -> str:
    """Vult {SRC_CLIENT} en dergelijke in met de naam uit `parameters`."""
    def fill(match: re.Match) -> str:
        p = params.get(match.group(1))
        if isinstance(p, dict):
            return str(p.get("name") or p.get("ip") or p.get("id") or match.group(0))
        return match.group(0)
    return _PLACEHOLDER.sub(fill, template or "")


def _parse_system_log(raw: dict) -> Threat | None:
    """Een IPS-regel uit system-log/all. Bron, doel en handtekening staan in `parameters`."""
    ts = raw.get("timestamp")
    if not ts:
        return None
    ts = int(ts)
    if ts < 10**12:
        ts *= 1000
    params = raw.get("parameters") or {}
    src = _param_addr(params, ("SRC_IP", "SRC_CLIENT", "SRC", "SOURCE"), ("SRC_PORT",))
    dst = _param_addr(params, ("DST_IP", "DST_CLIENT", "DST", "DESTINATION"), ("DST_PORT",))
    named = _param(params, "SIGNATURE", "THREAT", "IPS_SIGNATURE", "RULE")
    signature = (named.get("name") or _render(raw.get("message_raw") or raw.get("message"), params)
                 or raw.get("title_raw") or "onbekende aanval")
    category = _param(params, "CATEGORY", "THREAT_CATEGORY").get("name") or raw.get("title_raw") or ""
    action = " ".join(str(raw.get(k) or "") for k in ("key", "event", "title_raw")).upper()
    key = str(raw.get("id") or f"{ts}-{src}-{dst}-{signature}")
    return Threat(key, ts, src, dst, signature, category, blocked="BLOCK" in action)


def is_ips_alarm(raw: dict) -> bool:
    key = str(raw.get("key", ""))
    return "IPS" in key or "Threat" in key or bool(raw.get("inner_alert_signature"))


def parse_login(message: str) -> tuple[str, str] | None:
    """(host, ip) uit de HA-melding over een mislukte login, of None."""
    match = _LOGIN_FROM.search(message or "")
    if not match:
        return None
    return match.group("host"), match.group("ip")


def login_notifications(event: dict) -> list[str]:
    """Teksten van nieuwe of bijgewerkte 'http-login'-meldingen uit een persistent_notification-event.

    Bij het aanmelden stuurt HA 'current' met wat er al stond; dat is oud nieuws en slaan we over.
    """
    if event.get("type") not in ("added", "updated"):
        return []
    notifications = event.get("notifications") or {}
    return [n.get("message", "") for nid, n in notifications.items() if nid == HA_LOGIN_NOTIFICATION]
