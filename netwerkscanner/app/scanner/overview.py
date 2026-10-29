"""Overzichten voor het HA-dashboard: apparaten met hun poorten en de laatste wijzigingen."""

from __future__ import annotations

import json
from datetime import datetime, timedelta

from .db import Database, iso, label, utcnow
from .health import Health
from .homeassistant import HomeAssistant
from .ports import explain, risk
from .report import SECTIONS, _line
from .review import NAME_SELECT, NOTHING_PENDING, SELECT_ENTITY, option_label

TYPE_LABELS = dict(SECTIONS)

# Alle sensoren die publish() zet; bij de overstap naar MQTT halen we deze REST-toestanden weg.
SENSOR_IDS = (
    "sensor.netwerkscanner_apparaten_online",
    "sensor.netwerkscanner_gebeurtenissen_vandaag",
    "sensor.netwerkscanner_apparaten",
    "sensor.netwerkscanner_apparaten_1",
    "sensor.netwerkscanner_apparaten_2",
    "sensor.netwerkscanner_apparaten_3",
    "sensor.netwerkscanner_poorten",
    "sensor.netwerkscanner_te_beoordelen",
    "sensor.netwerkscanner_aanvallen_vandaag",
    "sensor.netwerkscanner_laatste_wijzigingen",
    "sensor.netwerkscanner_status",
    "sensor.netwerkscanner_onbekende_netwerken",
)


# HA bewaart attributen boven 16 KB niet in de database en waarschuwt daar steeds over in het logboek.
# Daarom gaat de apparatenlijst in delen over meerdere sensoren en blijft elke lijst ruim onder die grens.
MAX_ATTR_BYTES = 14000
DEVICE_PARTS = 3


def fit(items: list, limit: int = MAX_ATTR_BYTES) -> list:
    """Kort een lijst van achteren in tot hij als JSON onder `limit` bytes blijft."""
    items = list(items)
    while items and len(json.dumps(items, ensure_ascii=False).encode()) > limit:
        items.pop()
    return items


def split(items: list, parts: int) -> list[list]:
    """Verdeelt in `parts` stukken die zo even groot mogelijk zijn, de eerste het grootst."""
    n = -(-len(items) // parts) if items else 0
    return [items[i * n:(i + 1) * n] for i in range(parts)]


def dashboard_rows(device_rows: list[dict]) -> list[dict]:
    """Alleen wat de tabel op het dashboard toont, met poorten als nummers."""
    return [{
        "naam": d["naam"],
        "ip": d["ip"],
        "status": d["status"],
        "online": d["online"],
        "gescand": d["gescand"],
        "poorten": sorted({int(p.split("/")[0]) for p in d["poorten"]}),
    } for d in device_rows]


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


def port_overview(device_rows: list[dict], db: Database) -> list[dict]:
    """Elke open poort die ergens voorkomt, met uitleg en op welke apparaten."""
    names = {d["mac"]: d["naam"] for d in device_rows}
    found: dict[tuple, dict] = {}
    for mac, open_ports in db.latest_ports().items():
        for p in open_ports:
            row = found.setdefault((p["port"], p["proto"]), {
                "poort": f"{p['port']}/{p['proto']}",
                "uitleg": explain(p["port"], p.get("service")),
                "risico": risk(p["port"]),
                "apparaten": [],
            })
            if mac in names and names[mac] not in row["apparaten"]:
                row["apparaten"].append(names[mac])
    order = {"hoog": 0, "let op": 1, "normaal": 2}
    return sorted(found.values(), key=lambda r: (order[r["risico"]], int(r["poort"].split("/")[0])))


def dashboard_ports(open_ports: list[dict]) -> list[dict]:
    """Zonder de volledige lijst apparaten per poort: één naam, of hoeveel apparaten het zijn."""
    return [{
        "poort": p["poort"],
        "uitleg": p["uitleg"],
        "risico": p["risico"],
        "op": p["apparaten"][0] if len(p["apparaten"]) == 1 else f"{len(p['apparaten'])} apparaten",
    } for p in open_ports]


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


SECURITY_TYPES = ("intrusion", "login_failed")


def security_events(db: Database, limit: int = 10) -> list[dict]:
    """Laatste aanvallen en mislukte logins, nieuwste eerst."""
    marks = ",".join("?" * len(SECURITY_TYPES))
    rows = db.conn.execute(
        f"SELECT * FROM events WHERE type IN ({marks}) ORDER BY id DESC LIMIT ?", (*SECURITY_TYPES, limit)
    ).fetchall()
    result = []
    for e in rows:
        d = json.loads(e["detail"])
        result.append({
            "tijd": _local(e["ts"]),
            "soort": "Aanval" if e["type"] == "intrusion" else "Mislukte login",
            "geblokkeerd": bool(d.get("blocked")) if e["type"] == "intrusion" else None,
            "tekst": _line(db, e["type"], e["mac"], d),
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


def publish(db: Database, ha: HomeAssistant, health: Health | None = None) -> None:
    """Zet alle sensoren en de keuzelijst met te beoordelen apparaten in HA."""
    if health is not None:
        state, sources = health.summary()
        ha.set_sensor("sensor.netwerkscanner_status", state,
                      {"friendly_name": "Netwerk: scanner", "icon": "mdi:heart-pulse" if state == "werkt"
                       else "mdi:heart-broken", "bronnen": sources})
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
    device_rows = devices(db)
    ha.set_sensor("sensor.netwerkscanner_apparaten", known,
                  {"friendly_name": "Netwerk: apparaten", "unit_of_measurement": "apparaten",
                   "icon": "mdi:devices"})
    for i, part in enumerate(split(dashboard_rows(device_rows), DEVICE_PARTS), start=1):
        ha.set_sensor(f"sensor.netwerkscanner_apparaten_{i}", len(part),
                      {"friendly_name": f"Netwerk: apparaten deel {i}", "unit_of_measurement": "apparaten",
                       "icon": "mdi:devices", "apparaten": fit(part)})
    open_ports = port_overview(device_rows, db)
    ha.set_sensor("sensor.netwerkscanner_poorten", len(open_ports),
                  {"friendly_name": "Netwerk: soorten open poorten", "unit_of_measurement": "poorten",
                   "icon": "mdi:door-open", "poorten": fit(dashboard_ports(open_ports))})
    ha.set_sensor("sensor.netwerkscanner_te_beoordelen", len(pending),
                  {"friendly_name": "Netwerk: te beoordelen", "unit_of_measurement": "apparaten",
                   "icon": "mdi:shield-search"})
    security_today = [e for e in today if e["type"] in SECURITY_TYPES]
    ha.set_sensor("sensor.netwerkscanner_aanvallen_vandaag", len(security_today),
                  {"friendly_name": "Netwerk: aanvallen en mislukte logins vandaag", "unit_of_measurement": "meldingen",
                   "icon": "mdi:shield-alert", "meldingen": fit(security_events(db))})
    nets = [{"netwerk": n["cidr"], "onbekend": n["known_as"] is None, "nu_bekend_als": n["known_as"] or "",
             "gezien_bij": n["example"] or "", "eerst_gezien": _local(n["first_seen"]),
             "laatst_gezien": _local(n["last_seen"])}
            for n in db.networks() if n["last_seen"] >= iso(utcnow() - timedelta(days=30))]
    ha.set_sensor("sensor.netwerkscanner_onbekende_netwerken", sum(n["onbekend"] for n in nets),
                  {"friendly_name": "Netwerk: onbekende netwerken", "unit_of_measurement": "netwerken",
                   "icon": "mdi:lan-disconnect", "netwerken": fit(nets)})
    changes = fit(recent_changes(db, 10))
    ha.set_sensor("sensor.netwerkscanner_laatste_wijzigingen", changes[0]["tijd"] if changes else "geen",
                  {"friendly_name": "Netwerk: laatste wijzigingen", "icon": "mdi:history",
                   "wijzigingen": changes})
    ha.set_select_options(SELECT_ENTITY, [option_label(d) for d in pending] or [NOTHING_PENDING])
    ha.set_select_options(NAME_SELECT, [option_label(d) for d in db.all_devices()] or [NOTHING_PENDING])
