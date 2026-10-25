"""Vertaalt knoppen op het HA-dashboard naar een beoordeling."""

from __future__ import annotations

import re

from .config import normalize_mac
from .db import label

EVENT_TYPES = ("netwerkscanner_review",)
SELECT_ENTITY = "input_select.netwerkscanner_te_beoordelen"
NAME_SELECT = "input_select.netwerkscanner_apparaat"
NAME_TEXT = "input_text.netwerkscanner_naam"
NOTHING_PENDING = "Niets te beoordelen"

_MAC = re.compile(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})")


def parse(event_type: str, data: dict) -> tuple[str, str | None, str | None] | None:
    """Geeft (actie, mac, naam) of None als het event niet voor ons is.

    Event 'netwerkscanner_review' met action (approve, reject, approve_all, rename)
    en 'device': de gekozen optie uit de keuzelijst, waarin de MAC staat.
    Bij rename staat de nieuwe naam in 'name'; leeg zet de naam terug.
    """
    if event_type == "netwerkscanner_review":
        action = data.get("action")
        if action == "approve_all":
            return action, None, None
        if action not in ("approve", "reject", "rename"):
            return None
        match = _MAC.search(str(data.get("mac") or data.get("device") or ""))
        if not match:
            return None
        name = str(data.get("name") or "").strip()[:100] if action == "rename" else None
        return action, normalize_mac(match.group(1)), name
    return None


def option_label(device) -> str:
    return f"{label(device)} ({device['ip'] or 'geen IP'}) {device['mac']}"
