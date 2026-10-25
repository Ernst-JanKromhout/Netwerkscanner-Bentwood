"""Vertaalt knoppen uit HA (pushmelding of dashboard) naar een beoordeling."""

from __future__ import annotations

import re

from .config import normalize_mac

EVENT_TYPES = ("mobile_app_notification_action", "netwerkscanner_review")
SELECT_ENTITY = "input_select.netwerkscanner_te_beoordelen"
NOTHING_PENDING = "Niets te beoordelen"

_MAC = re.compile(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})")
_PUSH = re.compile(r"^NWS_(APPROVE|REJECT)_(.+)$")


def parse(event_type: str, data: dict) -> tuple[str, str | None] | None:
    """Geeft (actie, mac) of None als het event niet voor ons is.

    - Pushmelding: data.action = 'NWS_APPROVE_<mac>' of 'NWS_REJECT_<mac>'.
    - Dashboard: event 'netwerkscanner_review' met action (approve, reject, approve_all)
      en 'device': de gekozen optie uit de keuzelijst, waarin de MAC staat.
    """
    if event_type == "mobile_app_notification_action":
        match = _PUSH.match(str(data.get("action", "")))
        if not match:
            return None
        return ("approve" if match.group(1) == "APPROVE" else "reject"), normalize_mac(match.group(2))
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
