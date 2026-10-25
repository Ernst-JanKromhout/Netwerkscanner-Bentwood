"""Vertaalt knoppen op het HA-dashboard naar een beoordeling."""

from __future__ import annotations

import re

from .config import normalize_mac

EVENT_TYPES = ("netwerkscanner_review",)
SELECT_ENTITY = "input_select.netwerkscanner_te_beoordelen"
NOTHING_PENDING = "Niets te beoordelen"

_MAC = re.compile(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})")


def parse(event_type: str, data: dict) -> tuple[str, str | None] | None:
    """Geeft (actie, mac) of None als het event niet voor ons is.

    Event 'netwerkscanner_review' met action (approve, reject, approve_all)
    en 'device': de gekozen optie uit de keuzelijst, waarin de MAC staat.
    """
    if event_type == "netwerkscanner_review":
        action = data.get("action")
        if action == "approve_all":
            return action, None
        if action not in ("approve", "reject"):
            return None
        match = _MAC.search(str(data.get("mac") or data.get("device") or ""))
        return (action, normalize_mac(match.group(1))) if match else None
    return None


def option_label(device) -> str:
    name = device["name"] or device["hostname"] or device["vendor"] or "Onbekend"
    return f"{name} ({device['ip'] or 'geen IP'}) {device['mac']}"
