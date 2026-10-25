"""Bouwt het dagrapport uit de gebeurtenissen van de afgelopen periode."""

from __future__ import annotations

import json

from .db import Database

SECTIONS = [
    ("new_device", "Nieuwe apparaten"),
    ("port_opened", "Poorten geopend"),
    ("service_changed", "Dienst of versie gewijzigd"),
    ("port_closed", "Poorten gesloten"),
    ("first_scan", "Eerste poortscan"),
    ("device_gone", "Verdwenen"),
    ("device_back", "Weer terug"),
    ("ip_changed", "IP-wissels"),
    ("hostname_changed", "Naamwissels"),
    ("baseline", "Start van de scanner"),
]


def _label(db: Database, mac: str | None) -> str:
    if mac is None:
        return ""
    device = db.device(mac)
    if device is None:
        return mac
    return device["name"] or device["hostname"] or device["vendor"] or mac


def _port(d: dict) -> str:
    service = " ".join(v for v in (d.get("service"), d.get("version")) if v)
    return f"{d['port']}/{d['proto']}" + (f" ({service})" if service else "")


def _line(db: Database, type_: str, mac: str | None, d: dict) -> str:
    who = _label(db, mac)
    if type_ == "new_device":
        extra = ", willekeurig MAC" if d.get("random_mac") else ""
        return f"{who}: {d.get('ip') or 'geen IP'}, {mac}{extra}"
    if type_ in ("port_opened", "port_closed"):
        return f"{who} ({d.get('ip')}): {_port(d)}"
    if type_ == "service_changed":
        old = " ".join(v for v in (d.get("old_service"), d.get("old_version")) if v) or "onbekend"
        return f"{who} ({d.get('ip')}): poort {d['port']}/{d['proto']} van {old} naar {_port(d)}"
    if type_ == "first_scan":
        ports = ", ".join(_port(p) for p in d.get("ports", [])) or "geen open poorten"
        return f"{who} ({d.get('ip')}): {ports}"
    if type_ == "device_gone":
        return f"{who} ({d.get('ip')}), laatst gezien {d.get('last_seen')}"
    if type_ == "device_back":
        return f"{who} ({d.get('ip')}), weg sinds {d.get('away_since')}"
    if type_ in ("ip_changed", "hostname_changed"):
        return f"{who}: {d.get('old')} naar {d.get('new')}"
    if type_ == "baseline":
        return f"{d.get('devices')} apparaten vastgelegd als beginsituatie"
    return f"{who}: {json.dumps(d, ensure_ascii=False)}"


def build_report(db: Database, start: str, end: str) -> tuple[str, int]:
    """Geeft (tekst, aantal gebeurtenissen). Een lege periode is één regel."""
    events = db.events_between(start, end)
    if not events:
        return "Geen wijzigingen.", 0
    by_type: dict[str, list[str]] = {}
    for e in events:
        by_type.setdefault(e["type"], []).append(_line(db, e["type"], e["mac"], json.loads(e["detail"])))
    parts: list[str] = []
    for type_, title in SECTIONS:
        lines = by_type.pop(type_, None)
        if lines:
            parts.append(f"{title} ({len(lines)})\n" + "\n".join(f"- {l}" for l in lines))
    for type_, lines in by_type.items():
        parts.append(f"{type_} ({len(lines)})\n" + "\n".join(f"- {l}" for l in lines))
    return "\n\n".join(parts), len(events)


def build_summary(db: Database, start: str, end: str) -> str:
    """Korte versie voor de telefoon: alleen aantallen per soort."""
    events = db.events_between(start, end)
    if not events:
        return "Geen wijzigingen in het netwerk."
    counts: dict[str, int] = {}
    for e in events:
        counts[e["type"]] = counts.get(e["type"], 0) + 1
    titles = dict(SECTIONS)
    lines = [f"{titles.get(t, t)}: {n}" for t, n in counts.items()]
    return "\n".join(lines) + "\n\nVolledig rapport staat in Home Assistant."
