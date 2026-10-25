"""Overzichten voor het HA-dashboard: apparaten met hun poorten en de laatste wijzigingen."""

from __future__ import annotations

import json
from datetime import datetime

from .db import Database
from .report import SECTIONS, _line

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
            "naam": d["name"] or d["hostname"] or d["vendor"] or "Onbekend",
            "ip": d["ip"] or "",
            "mac": d["mac"],
            "fabrikant": d["vendor"] or "",
            "online": bool(d["present"]),
            "vertrouwd": bool(d["trusted"]),
            "gescand": d["mac"] in scanned,
            "poorten": [_port_label(p) for p in open_ports],
            "eerst_gezien": _local(d["first_seen"]),
            "laatst_gezien": _local(d["last_seen"]),
        })
    result.sort(key=lambda r: (not r["online"], _ip_key(r["ip"])))
    return result


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
