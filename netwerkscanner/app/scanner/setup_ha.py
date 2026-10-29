"""Zet bij de start het dashboard, de keuzelijst en de knoppen in HA als ze nog ontbreken.

Bestaat iets al, dan blijft het zoals het is: aanpassingen van de gebruiker worden nooit overschreven.
Alleen een dashboard dat wij maakten en dat niet is aangepast, krijgt de indeling van de nieuwe versie.
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path

from .homeassistant import HomeAssistant, supervisor_token
from .review import NAME_SELECT, NAME_TEXT, NOTHING_PENDING, SELECT_ENTITY

log = logging.getLogger(__name__)

WS_URL = "ws://supervisor/core/websocket"
# (entiteit, websocket-commando, gegevens); de naam bepaalt de entity_id.
HELPERS = [
    (SELECT_ENTITY, "input_select/create",
     {"name": "Netwerkscanner te beoordelen", "options": [NOTHING_PENDING], "icon": "mdi:shield-search"}),
    (NAME_SELECT, "input_select/create",
     {"name": "Netwerkscanner apparaat", "options": [NOTHING_PENDING], "icon": "mdi:devices"}),
    (NAME_TEXT, "input_text/create",
     {"name": "Netwerkscanner naam", "max": 100, "icon": "mdi:rename"}),
]

SCRIPTS = {
    "netwerkscanner_goedkeuren": {
        "alias": "Netwerkscanner: apparaat goedkeuren",
        "icon": "mdi:check-circle",
        "mode": "single",
        "sequence": [
            {
                "event": "netwerkscanner_review",
                "event_data": {
                    "action": "approve",
                    "device": "{{ states('input_select.netwerkscanner_te_beoordelen') }}"
                }
            }
        ]
    },
    "netwerkscanner_afkeuren": {
        "alias": "Netwerkscanner: apparaat afkeuren",
        "icon": "mdi:close-circle",
        "mode": "single",
        "sequence": [
            {
                "event": "netwerkscanner_review",
                "event_data": {
                    "action": "reject",
                    "device": "{{ states('input_select.netwerkscanner_te_beoordelen') }}"
                }
            }
        ]
    },
    "netwerkscanner_naam_geven": {
        "alias": "Netwerkscanner: naam geven",
        "icon": "mdi:rename",
        "mode": "single",
        "sequence": [
            {
                "event": "netwerkscanner_review",
                "event_data": {
                    "action": "rename",
                    "device": "{{ states('input_select.netwerkscanner_apparaat') }}",
                    "name": "{{ states('input_text.netwerkscanner_naam') }}"
                }
            },
            {
                "action": "input_text.set_value",
                "target": {"entity_id": "input_text.netwerkscanner_naam"},
                "data": {"value": ""}
            }
        ]
    },
    "netwerkscanner_scannen": {
        "alias": "Netwerkscanner: apparaat nu scannen",
        "icon": "mdi:radar",
        "mode": "single",
        "sequence": [
            {
                "event": "netwerkscanner_review",
                "event_data": {
                    "action": "scan",
                    "device": "{{ states('input_select.netwerkscanner_apparaat') }}"
                }
            }
        ]
    },
    "netwerkscanner_alles_goedkeuren": {
        "alias": "Netwerkscanner: alle openstaande goedkeuren",
        "icon": "mdi:check-all",
        "mode": "single",
        "sequence": [
            {
                "event": "netwerkscanner_review",
                "event_data": {
                    "action": "approve_all"
                }
            }
        ]
    }
}

def devices_table(part: int) -> str:
    """Eén deel van de apparatenlijst (elk deel is een eigen sensor), zodat de tabellen naast elkaar passen."""
    return (
        f"{{% set ds = state_attr('sensor.netwerkscanner_apparaten_{part + 1}', 'apparaten') or [] %}}"
        "{% if ds %}| | Naam | IP | Poorten |\n|:-:|---|---|---|\n"
        "{% for d in ds %}{% set p = d.poorten %}"
        "| {{ '❌' if d.status == 'afgekeurd' else ('✅' if d.status == 'goedgekeurd' else '⚠️') }}"
        "{{ '' if d.online else '💤' }} | {{ d.naam }} | {{ d.ip }} | "
        "{{ (p[:3] | join(', ') ~ (' +' ~ (p | length - 3) if p | length > 3 else '')) if p "
        "else ('–' if d.gescand else '…') }} |\n"
        "{% endfor %}"
        + ("{% else %}*Nog geen gegevens.*" if part == 0 else "")
        + "{% endif %}"
    )


def ports_table(part: int, parts: int = 3) -> str:
    """Uitleg per open poort, verdeeld over `parts` kaarten naast elkaar."""
    return (
        "{% set all = state_attr('sensor.netwerkscanner_poorten', 'poorten') or [] %}"
        f"{{% set n = (all | length / {parts}) | round(0, 'ceil') | int %}}"
        f"{{% set ps = all[{part} * n:{part + 1} * n] %}}"
        "{% if ps %}| Poort | Waarvoor | Op |\n|---|---|---|\n"
        "{% for p in ps %}| {{ {'hoog': '🔴', 'let op': '🟠'}.get(p.risico, '🟢') }} **{{ p.poort.split('/')[0] }}** | {{ p.uitleg }} | "
        "{{ p.op }} |\n"
        "{% endfor %}"
        + ("{% else %}*Nog geen open poorten gevonden.*" if part == 0 else "")
        + "{% endif %}"
    )


PORT_LEGEND = ("🔴 hoog: liever dicht, of alleen als je het zelf gebruikt · "
               "🟠 let op: beheer of onversleuteld, check of je het kent · 🟢 normaal")

LEGEND = "✅ goedgekeurd · ⚠️ te beoordelen · ❌ afgekeurd · 💤 offline · … nog niet gescand · – geen open poorten"

CHANGES_LIST = (
    "{% set ws = (state_attr('sensor.netwerkscanner_laatste_wijzigingen', 'wijzigingen') or [])[:5] %}"
    "{% for w in ws %}**{{ w.tijd[6:] }}** {{ w.soort }}: {{ w.tekst }}\n\n"
    "{% else %}*Nog geen wijzigingen.*{% endfor %}"
)

SECURITY_LIST = (
    "{% set ms = (state_attr('sensor.netwerkscanner_aanvallen_vandaag', 'meldingen') or [])[:5] %}"
    "{% for m in ms %}{{ '🛡️' if m.geblokkeerd else '🚨' }} **{{ m.tijd[6:] }}** {{ m.soort }}: {{ m.tekst }}\n\n"
    "{% else %}🛡️ *Geen aanvallen of mislukte logins gezien.*{% endfor %}"
)

HEALTH_ALERT = (
    "{% for b in state_attr('sensor.netwerkscanner_status', 'bronnen') or [] %}{% if not b.werkt %}"
    "🚨 **{{ b.bron }}** werkt niet sinds {{ b.storing_sinds }}: {{ b.fout }}\n\n{% endif %}{% endfor %}"
)

PENDING = {"condition": "numeric_state", "entity": "sensor.netwerkscanner_te_beoordelen", "above": 0}


def _button(name: str, icon: str, script: str, columns: int = 6, confirm: str | None = None) -> dict:
    action = {"action": "perform-action", "perform_action": f"script.{script}"}
    if confirm:
        action["confirmation"] = {"text": confirm}
    return {"type": "button", "name": name, "icon": icon, "show_state": False, "tap_action": action,
            "grid_options": {"columns": columns, "rows": 1}}


OVERVIEW_SECTIONS = [
    {"type": "grid", "cards": [
        {"type": "heading", "heading": "Nu", "icon": "mdi:lan"},
        {"type": "tile", "entity": "sensor.netwerkscanner_apparaten_online", "name": "Online", "color": "green",
         "features": [{"type": "trend-graph", "hours_to_show": 24}], "grid_options": {"columns": 12}},
        {"type": "markdown", "visibility": [{"condition": "state", "entity": "sensor.netwerkscanner_status",
                                             "state": "storing"}],
         "content": HEALTH_ALERT, "grid_options": {"columns": "full"}},
        {"type": "tile", "entity": "sensor.netwerkscanner_te_beoordelen", "name": "Te beoordelen",
         "color": "orange", "vertical": True, "grid_options": {"columns": 4, "rows": 2}},
        {"type": "tile", "entity": "sensor.netwerkscanner_aanvallen_vandaag", "name": "Aanvallen vandaag",
         "color": "red", "vertical": True, "grid_options": {"columns": 4, "rows": 2}},
        {"type": "tile", "entity": "sensor.netwerkscanner_gebeurtenissen_vandaag", "name": "Wijzigingen vandaag",
         "color": "blue", "vertical": True, "grid_options": {"columns": 4, "rows": 2}},
    ]},
    {"type": "grid", "visibility": [PENDING], "cards": [
        {"type": "heading", "heading": "Te beoordelen", "icon": "mdi:shield-alert"},
        {"type": "entities", "entities": [{"entity": "input_select.netwerkscanner_te_beoordelen",
                                           "name": "Apparaat"}], "grid_options": {"columns": 12}},
        _button("Goedkeuren", "mdi:check-circle", "netwerkscanner_goedkeuren"),
        _button("Afkeuren", "mdi:close-circle", "netwerkscanner_afkeuren"),
        _button("Alle openstaande goedkeuren", "mdi:check-all", "netwerkscanner_alles_goedkeuren", 12,
                "Alle openstaande apparaten goedkeuren?"),
    ]},
    {"type": "grid", "cards": [
        {"type": "heading", "heading": "Beveiliging", "heading_style": "subtitle", "icon": "mdi:shield-alert"},
        {"type": "markdown", "content": SECURITY_LIST, "grid_options": {"columns": "full"}},
    ]},
    {"type": "grid", "cards": [
        {"type": "heading", "heading": "Laatste 5 wijzigingen", "heading_style": "subtitle", "icon": "mdi:history"},
        {"type": "markdown", "content": CHANGES_LIST, "grid_options": {"columns": "full"}},
    ]},
    {"type": "grid", "column_span": 3, "cards": [
        {"type": "heading", "heading": "Apparaten", "icon": "mdi:devices"},
        *[{"type": "markdown", "content": devices_table(i), "grid_options": {"columns": 12}} for i in range(3)],
        {"type": "markdown", "text_only": True, "content": LEGEND, "grid_options": {"columns": "full"}},
    ]},
    {"type": "grid", "cards": [
        {"type": "heading", "heading": "Apparaat", "icon": "mdi:rename"},
        {"type": "entities", "entities": [
            {"entity": "input_select.netwerkscanner_apparaat", "name": "Apparaat"},
            {"entity": "input_text.netwerkscanner_naam", "name": "Nieuwe naam"},
        ], "grid_options": {"columns": 12}},
        _button("Naam opslaan", "mdi:content-save", "netwerkscanner_naam_geven"),
        _button("Nu scannen", "mdi:radar", "netwerkscanner_scannen"),
        {"type": "markdown", "text_only": True,
         "content": ("Kies het apparaat. Typ een naam en druk op **Naam opslaan** (leeg zet de oude naam terug), "
                     "of druk op **Nu scannen** voor een poortscan. De uitslag komt als melding in HA."),
         "grid_options": {"columns": "full"}},
    ]},
    {"type": "grid", "column_span": 2, "cards": [
        {"type": "heading", "heading": "Wat betekenen de poorten", "icon": "mdi:door-open"},
        *[{"type": "markdown", "content": ports_table(i, 2), "grid_options": {"columns": 12}} for i in range(2)],
        {"type": "markdown", "text_only": True, "content": PORT_LEGEND, "grid_options": {"columns": "full"}},
    ]},
]

def split_path(dashboard_path: str) -> tuple[str, str]:
    """'/dashboard-netwerk/overzicht' -> ('dashboard-netwerk', 'overzicht')."""
    parts = [p for p in dashboard_path.strip("/").split("/") if p]
    url_path = parts[0] if parts else "dashboard-netwerk"
    view = parts[1] if len(parts) > 1 else "overzicht"
    return url_path, view


def dashboard_config(view_path: str) -> dict:
    return {"views": [
        {"title": "Overzicht", "path": view_path, "icon": "mdi:lan", "type": "sections", "max_columns": 3,
         "sections": OVERVIEW_SECTIONS},
    ]}


class WebSocket:
    """Kleine websocket-client voor losse commando's aan HA."""

    def __init__(self, url: str = WS_URL):
        import websocket  # alleen in de add-on nodig

        self.ws = websocket.create_connection(url, timeout=30)
        self.next_id = 1
        self.ws.recv()  # auth_required
        self.ws.send(json.dumps({"type": "auth", "access_token": supervisor_token()}))
        reply = json.loads(self.ws.recv())
        if reply.get("type") != "auth_ok":
            raise RuntimeError(f"websocket-authenticatie mislukt: {reply.get('type')}")

    def call(self, type_: str, **data):
        msg_id = self.next_id
        self.next_id += 1
        self.ws.send(json.dumps({"id": msg_id, "type": type_, **data}))
        while True:
            reply = json.loads(self.ws.recv())
            if reply.get("id") == msg_id and reply.get("type") == "result":
                break
        if not reply.get("success"):
            raise RuntimeError(f"{type_}: {reply.get('error', {}).get('message', reply.get('error'))}")
        return reply.get("result")

    def close(self) -> None:
        self.ws.close()


DASHBOARD_HASH = Path("/data/dashboard.sha256")


def _hash(config: dict) -> str:
    return hashlib.sha256(json.dumps(config, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def _ours_unchanged(current: dict, view_path: str, hash_path: Path) -> bool:
    """Is dit dashboard door ons gemaakt en sindsdien niet met de hand aangepast?

    Zonder opgeslagen hash (installaties van voor 0.1.10) herkennen we het aan de eerste view.
    """
    if hash_path.exists():
        return hash_path.read_text().strip() == _hash(current)
    views = current.get("views") or []
    return bool(views) and views[0].get("path") == view_path and views[0].get("title") == "Overzicht"


def ensure(ha: HomeAssistant, dashboard_path: str, ws_factory=WebSocket,
           hash_path: Path = DASHBOARD_HASH) -> list[str]:
    """Maakt wat ontbreekt en geeft terug wat er is aangemaakt of bijgewerkt.

    Een dashboard dat wij maakten en dat niemand aanpaste, krijgt bij een nieuwe versie de nieuwe indeling.
    Heb je het zelf aangepast, dan blijft het zoals het is.
    """
    created = []
    for script_id, config in SCRIPTS.items():
        if ha.state(f"script.{script_id}") is None and ha.save_script(script_id, config):
            created.append(f"script.{script_id}")

    url_path, view_path = split_path(dashboard_path)
    ws = ws_factory()
    try:
        for entity_id, command, data in HELPERS:
            if ha.state(entity_id) is None:
                ws.call(command, **data)
                created.append(entity_id)
        if "-" not in url_path:
            log.warning("dashboard_path %s: het eerste deel moet een koppelteken hebben, dashboard niet aangemaakt",
                        dashboard_path)
        elif url_path not in {d.get("url_path") for d in ws.call("lovelace/dashboards/list")}:
            ws.call("lovelace/dashboards/create", url_path=url_path, title="Netwerk", icon="mdi:lan",
                    show_in_sidebar=True, require_admin=False, mode="storage")
            config = dashboard_config(view_path)
            ws.call("lovelace/config/save", url_path=url_path, config=config)
            hash_path.write_text(_hash(config))
            created.append(f"dashboard /{url_path}/{view_path}")
        else:
            config = dashboard_config(view_path)
            try:
                current = ws.call("lovelace/config", url_path=url_path) or {}
            except RuntimeError:  # dashboard bestaat maar is nog leeg
                current = {}
            if current != config and _ours_unchanged(current, view_path, hash_path):
                ws.call("lovelace/config/save", url_path=url_path, config=config)
                hash_path.write_text(_hash(config))
                created.append(f"nieuwe indeling dashboard /{url_path}/{view_path}")
    finally:
        ws.close()
    return created
