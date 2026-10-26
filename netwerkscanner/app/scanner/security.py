"""Aanvallen uit de IPS van de UniFi-gateway en mislukte inlogpogingen op Home Assistant."""

from __future__ import annotations

import re
from dataclasses import dataclass

# HA zet bij een mislukte login een melding met dit id en een tekst als
# "Login attempt or request with invalid authentication from host (1.2.3.4). Requested URL: ..."
HA_LOGIN_NOTIFICATION = "http-login"
_LOGIN_FROM = re.compile(r"from (?P<host>\S+) \((?P<ip>[0-9a-fA-F:.]+)\)")


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
    """Een IPS-melding uit stat/ips/event of list/alarm van de UniFi-controller."""
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
