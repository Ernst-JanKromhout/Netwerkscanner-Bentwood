"""Overzichten voor het HA-dashboard: apparaten met hun poorten en de laatste wijzigingen."""

from __future__ import annotations

import json
from datetime import datetime, timedelta

from .db import Database, iso, label, utcnow
from .homeassistant import HomeAssistant
from .report import SECTIONS, _line
from .review import NAME_SELECT, NOTHING_PENDING, SELECT_ENTITY, option_label

TYPE_LABELS = dict(SECTIONS)


def _port_label(p: dict) -> str:
    return f"{p['port']}/{p['proto']}" + (f" {p['service']}" if p.get("service") else "")


def devices(db: Database) -> list[dict]:
    """Eén regel per apparaat: online eerst, daarna op IP."""
    ports = db.latest_ports()
    scanned = db.scanned_macs()
    rows = db.conn.execute("SELECT * FROM devices").fetchall()
    result = []
    for d in rows:
        open_ports = ports.get(d["mac"], [])
        result.append({
            "naam": label(d),
            "ip": d["ip"] or "",
            "mac": d["mac"],
            "fabrikant": d["vendor"] or "",
            "online": bool(d["present"]),
            "vertrouwd": bool(d["trusted"]),
            "status": _status(d),
            "gescand": d["mac"] in scanned,
            "poorten": [_port_label(p) for p in open_ports],
            "eerst_gezien": _local(d["first_seen"]),
            "laatst_gezien": _local(d["last_seen"]),
        })
    result.sort(key=lambda r: (not r["online"], _ip_key(r["ip"])))
    return result


def _status(device) -> str:
    if device["review"] == "rejected":
        return "afgekeurd"
    if device["trusted"]:
        return "goedgekeurd"
    return "te beoordelen"


def recent_changes(db: Database, limit: int = 25) -> list[dict]:
    result = []
    for e in db.recent_events(limit):
        result.append({
            "tijd": _local(e["ts"]),
            "soort": TYPE_LABELS.get(e["type"], e["type"]),
            "type": e["type"],
            "tekst": _line(db, e["type"], e["mac"], json.loads(e["detail"])),
        })
    return result


def _local(ts: str | None) -> str:
    if not ts:
        return ""
    return datetime.fromisoformat(ts).astimezone().strftime("%d-%m %H:%M")


def _ip_key(ip: str) -> tuple:
    try:
        return tuple(int(part) for part in ip.split("."))
    except ValueError:
        return (999,)


def publish(db: Database, ha: HomeAssistant) -> None:
    """Zet alle sensoren en de keuzelijst met te beoordelen apparaten in HA."""
    midnight = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    today = db.events_between(iso(midnight.astimezone()), iso(utcnow() + timedelta(seconds=1)))
    online = db.conn.execute("SELECT COUNT(*) FROM devices WHERE present = 1").fetchone()[0]
    known = db.device_count()
    pending = db.pending_devices()
    ha.set_sensor("sensor.netwerkscanner_apparaten_online", online,
                  {"friendly_name": "Netwerk: apparaten online", "unit_of_measurement": "apparaten",
                   "icon": "mdi:lan", "bekend_totaal": known})
    ha.set_sensor("sensor.netwerkscanner_gebeurtenissen_vandaag", len(today),
                  {"friendly_name": "Netwerk: wijzigingen vandaag", "unit_of_measurement": "wijzigingen",
                   "icon": "mdi:lan-pending"})
    ha.set_sensor("sensor.netwerkscanner_apparaten", known,
                  {"friendly_name": "Netwerk: apparaten", "unit_of_measurement": "apparaten",
                   "icon": "mdi:devices", "apparaten": devices(db)})
    ha.set_sensor("sensor.netwerkscanner_te_beoordelen", len(pending),
                  {"friendly_name": "Netwerk: te beoordelen", "unit_of_measurement": "apparaten",
                   "icon": "mdi:shield-search"})
    changes = recent_changes(db)
    ha.set_sensor("sensor.netwerkscanner_laatste_wijzigingen", changes[0]["tijd"] if changes else "geen",
                  {"friendly_name": "Netwerk: laatste wijzigingen", "icon": "mdi:history",
                   "wijzigingen": changes})
    ha.set_select_options(SELECT_ENTITY, [option_label(d) for d in pending] or [NOTHING_PENDING])
    ha.set_select_options(NAME_SELECT, [option_label(d) for d in db.all_devices()] or [NOTHING_PENDING])
