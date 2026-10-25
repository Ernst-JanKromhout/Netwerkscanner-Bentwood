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

SECTIONS = [
    {
        "type": "grid",
        "cards": [
            {
                "type": "heading",
                "heading": "Te beoordelen",
                "icon": "mdi:shield-search"
            },
            {
                "type": "tile",
                "entity": "sensor.netwerkscanner_te_beoordelen",
                "name": "Openstaand",
                "grid_options": {
                    "columns": 12
                }
            },
            {
                "type": "entities",
                "entities": [
                    {
                        "entity": "input_select.netwerkscanner_te_beoordelen",
                        "name": "Apparaat"
                    }
                ],
                "grid_options": {
                    "columns": 12
                }
            },
            {
                "type": "button",
                "name": "Goedkeuren",
                "icon": "mdi:check-circle",
                "show_state": False,
                "tap_action": {
                    "action": "perform-action",
                    "perform_action": "script.netwerkscanner_goedkeuren"
                },
                "grid_options": {
                    "columns": 6,
                    "rows": 2
                }
            },
            {
                "type": "button",
                "name": "Afkeuren",
                "icon": "mdi:close-circle",
                "show_state": False,
                "tap_action": {
                    "action": "perform-action",
                    "perform_action": "script.netwerkscanner_afkeuren"
                },
                "grid_options": {
                    "columns": 6,
                    "rows": 2
                }
            },
            {
                "type": "button",
                "name": "Alle openstaande goedkeuren",
                "icon": "mdi:check-all",
                "show_state": False,
                "tap_action": {
                    "action": "perform-action",
                    "perform_action": "script.netwerkscanner_alles_goedkeuren",
                    "confirmation": {
                        "text": "Alle openstaande apparaten goedkeuren?"
                    }
                },
                "grid_options": {
                    "columns": 12,
                    "rows": 1
                }
            },
            {"type": "heading", "heading": "Naam geven", "icon": "mdi:rename"},
            {
                "type": "entities",
                "entities": [
                    {"entity": "input_select.netwerkscanner_apparaat", "name": "Apparaat"},
                    {"entity": "input_text.netwerkscanner_naam", "name": "Nieuwe naam"}
                ],
                "grid_options": {"columns": 12}
            },
            {
                "type": "button",
                "name": "Naam opslaan",
                "icon": "mdi:content-save",
                "show_state": False,
                "tap_action": {"action": "perform-action", "perform_action": "script.netwerkscanner_naam_geven"},
                "grid_options": {"columns": 12, "rows": 1}
            },
            {
                "type": "heading",
                "heading": "Nu",
                "icon": "mdi:lan"
            },
            {
                "type": "tile",
                "entity": "sensor.netwerkscanner_apparaten_online",
                "name": "Online",
                "grid_options": {
                    "columns": 6
                }
            },
            {
                "type": "tile",
                "entity": "sensor.netwerkscanner_gebeurtenissen_vandaag",
                "name": "Wijzigingen vandaag",
                "grid_options": {
                    "columns": 6
                }
            },
            {
                "type": "history-graph",
                "title": "Apparaten online, laatste 24 uur",
                "hours_to_show": 24,
                "entities": [
                    {
                        "entity": "sensor.netwerkscanner_apparaten_online",
                        "name": "Online"
                    }
                ],
                "grid_options": {
                    "columns": 12
                }
            }
        ]
    },
    {
        "type": "grid",
        "column_span": 2,
        "cards": [
            {
                "type": "heading",
                "heading": "Apparaten",
                "icon": "mdi:devices"
            },
            {
                "type": "markdown",
                "grid_options": {
                    "columns": "full"
                },
                "content": "✅ goedgekeurd · ⚠️ te beoordelen · ❌ afgekeurd · 💤 offline\n\n{% set ds = state_attr('sensor.netwerkscanner_apparaten', 'apparaten') or [] %}{% if ds %}| | Naam | IP | Open poorten | Laatst gezien |\n|---|---|---|---|---|\n{% for d in ds %}| {{ '❌' if d.status == 'afgekeurd' else ('✅' if d.status == 'goedgekeurd' else '⚠️') }}{{ '' if d.online else ' 💤' }} | {{ d.naam }} | {{ d.ip }} | {{ d.poorten | join(', ') if d.poorten else ('geen' if d.gescand else 'nog niet gescand') }} | {{ d.laatst_gezien }} |\n{% endfor %}{% else %}*Nog geen gegevens.*{% endif %}\n"
            },
            {
                "type": "heading",
                "heading": "Laatste wijzigingen",
                "icon": "mdi:history"
            },
            {
                "type": "markdown",
                "grid_options": {
                    "columns": "full"
                },
                "content": "{% set ws = state_attr('sensor.netwerkscanner_laatste_wijzigingen', 'wijzigingen') or [] %}{% if ws %}| Tijd | Soort | Wat |\n|---|---|---|\n{% for w in ws %}| {{ w.tijd }} | {{ w.soort }} | {{ w.tekst }} |\n{% endfor %}{% else %}*Nog geen wijzigingen.*{% endif %}\n"
            }
        ]
    }
]


def split_path(dashboard_path: str) -> tuple[str, str]:
    """'/dashboard-netwerk/overzicht' -> ('dashboard-netwerk', 'overzicht')."""
    parts = [p for p in dashboard_path.strip("/").split("/") if p]
    url_path = parts[0] if parts else "dashboard-netwerk"
    view = parts[1] if len(parts) > 1 else "overzicht"
    return url_path, view


def dashboard_config(view_path: str) -> dict:
    return {"views": [{"title": "Overzicht", "path": view_path, "icon": "mdi:lan", "type": "sections",
                       "max_columns": 3, "sections": SECTIONS}]}


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
