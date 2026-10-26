"""Zet bij de start het dashboard, de keuzelijst en de knoppen in HA als ze nog ontbreken.

Bestaat iets al, dan blijft het zoals het is: aanpassingen van de gebruiker worden nooit overschreven.
"""

from __future__ import annotations

import json
import logging

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

def devices_table(part: int, parts: int = 3) -> str:
    """Eén deel van de apparatenlijst, zodat de tabellen op een breed scherm naast elkaar passen."""
    return (
        "{% set all = state_attr('sensor.netwerkscanner_apparaten', 'apparaten') or [] %}"
        f"{{% set n = (all | length / {parts}) | round(0, 'ceil') | int %}}"
        f"{{% set ds = all[{part} * n:{part + 1} * n] %}}"
        "{% if ds %}| | Naam | IP | Poorten |\n|:-:|---|---|---|\n"
        "{% for d in ds %}{% set p = d.poorten | map('regex_replace', '/.*', '') | list %}"
        "| {{ '❌' if d.status == 'afgekeurd' else ('✅' if d.status == 'goedgekeurd' else '⚠️') }}"
        "{{ '' if d.online else '💤' }} | {{ d.naam }} | {{ d.ip }} | "
        "{{ (p[:3] | join(', ') ~ (' +' ~ (p | length - 3) if p | length > 3 else '')) if p "
        "else ('–' if d.gescand else '…') }} |\n"
        "{% endfor %}"
        + ("{% else %}*Nog geen gegevens.*" if part == 0 else "")
        + "{% endif %}"
    )


LEGEND = "✅ goedgekeurd · ⚠️ te beoordelen · ❌ afgekeurd · 💤 offline · … nog niet gescand · – geen open poorten"

CHANGES_LIST = (
    "{% set ws = (state_attr('sensor.netwerkscanner_laatste_wijzigingen', 'wijzigingen') or [])[:5] %}"
    "{% for w in ws %}**{{ w.tijd[6:] }}** {{ w.soort }}: {{ w.tekst }}\n\n"
    "{% else %}*Nog geen wijzigingen.*{% endfor %}"
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
        {"type": "tile", "entity": "sensor.netwerkscanner_te_beoordelen", "name": "Te beoordelen",
         "color": "orange", "vertical": True, "grid_options": {"columns": 6, "rows": 2}},
        {"type": "tile", "entity": "sensor.netwerkscanner_gebeurtenissen_vandaag", "name": "Wijzigingen vandaag",
         "color": "blue", "vertical": True, "grid_options": {"columns": 6, "rows": 2}},
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
        {"type": "heading", "heading": "Laatste 5 wijzigingen", "heading_style": "subtitle", "icon": "mdi:history"},
        {"type": "markdown", "content": CHANGES_LIST, "grid_options": {"columns": "full"}},
    ]},
    {"type": "grid", "column_span": 3, "cards": [
        {"type": "heading", "heading": "Apparaten", "icon": "mdi:devices"},
        *[{"type": "markdown", "content": devices_table(i), "grid_options": {"columns": 12}} for i in range(3)],
        {"type": "markdown", "text_only": True, "content": LEGEND, "grid_options": {"columns": "full"}},
    ]},
]

NAMES_SECTIONS = [
    {"type": "grid", "cards": [
        {"type": "heading", "heading": "Naam geven", "icon": "mdi:rename"},
        {"type": "markdown", "text_only": True,
         "content": "Kies een apparaat, typ een naam en druk op **Naam opslaan**. Leeg opslaan zet de oude naam terug."},
        {"type": "entities", "entities": [
            {"entity": "input_select.netwerkscanner_apparaat", "name": "Apparaat"},
            {"entity": "input_text.netwerkscanner_naam", "name": "Nieuwe naam"},
        ], "grid_options": {"columns": 12}},
        _button("Naam opslaan", "mdi:content-save", "netwerkscanner_naam_geven", 12),
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
        {"title": "Namen", "path": "namen", "icon": "mdi:rename", "type": "sections", "max_columns": 2,
         "sections": NAMES_SECTIONS},
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


def ensure(ha: HomeAssistant, dashboard_path: str, ws_factory=WebSocket) -> list[str]:
    """Maakt wat ontbreekt en geeft terug wat er is aangemaakt."""
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
            ws.call("lovelace/config/save", url_path=url_path, config=dashboard_config(view_path))
            created.append(f"dashboard /{url_path}/{view_path}")
    finally:
        ws.close()
    return created
