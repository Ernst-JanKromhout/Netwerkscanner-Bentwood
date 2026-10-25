"""Verwerkt waarnemingen en scans tot gebeurtenissen, en meldt wat urgent is."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Callable

from .config import Config
from .db import Database, iso, utcnow
from .diff import Change, diff_identity, diff_ports, is_random_mac
from .homeassistant import HomeAssistant
from .nmap import Host

log = logging.getLogger(__name__)

ScanRequest = Callable[[str, str, str], None]  # (mac, ip, kind)


@dataclass
class Sighting:
    mac: str
    ip: str | None
    hostname: str | None = None
    name: str | None = None
    vendor: str | None = None
    network: str | None = None


def describe(device) -> str:
    """Leesbare naam van een apparaat: naam, hostnaam of fabrikant, met IP en MAC."""
    label = device["name"] or device["hostname"] or device["vendor"] or "Onbekend apparaat"
    return f"{label} ({device['ip'] or 'geen IP'}, {device['mac']})"


class Engine:
    def __init__(self, db: Database, cfg: Config, ha: HomeAssistant, request_scan: ScanRequest | None = None):
        self.db = db
        self.cfg = cfg
        self.ha = ha
        self.request_scan = request_scan or (lambda mac, ip, kind: None)

    # waarnemingen

    def handle_sightings(self, sightings: list[Sighting], source: str, now: datetime | None = None) -> None:
        ts = iso(now or utcnow())
        bootstrap = self.db.get_meta("bootstrapped_at") is None
        new_count = 0
        for s in sightings:
            if self._handle_sighting(s, source, ts, bootstrap):
                new_count += 1
        if bootstrap and sightings:
            self.db.set_meta("bootstrapped_at", ts)
            self.db.set_trusted(self.cfg.trusted_macs)
            self.db.add_event(ts, "baseline", None, {"devices": new_count})
            log.info("Eerste inventaris: %d apparaten vastgelegd zonder meldingen", new_count)

    def _handle_sighting(self, s: Sighting, source: str, ts: str, bootstrap: bool) -> bool:
        fields = {k: v for k, v in (("ip", s.ip), ("hostname", s.hostname), ("name", s.name),
                                    ("vendor", s.vendor), ("network", s.network)) if v}
        existing = self.db.device(s.mac)

        if existing is None:
            trusted = s.mac in self.cfg.trusted_macs
            self.db.upsert_device(s.mac, ts, trusted=int(trusted), **fields)
            self.db.add_observation(ts, s.mac, s.ip, s.hostname, source)
            if s.ip:
                self.request_scan(s.mac, s.ip, "top")
            if bootstrap:
                return True
            device = self.db.device(s.mac)
            detail = {"ip": s.ip, "hostname": s.hostname, "name": s.name, "vendor": s.vendor,
                      "network": s.network, "random_mac": is_random_mac(s.mac)}
            event_id = self.db.add_event(ts, "new_device", s.mac, detail)
            if not trusted:
                lines = [describe(device)]
                if s.network:
                    lines.append(f"Netwerk: {s.network}")
                if detail["random_mac"]:
                    lines.append("Willekeurig (privé) MAC-adres: mogelijk een bekende telefoon met een nieuw adres.")
                lines.append("Poortscan is gestart.")
                self._push(event_id, "Nieuw apparaat op je netwerk", "\n".join(lines), s.mac)
            return True

        changes: list[Change] = diff_identity(existing["ip"], existing["hostname"], s.ip, s.hostname)
        came_back = not existing["present"]
        for change in changes:
            self.db.add_event(ts, change.type, s.mac, change.detail)
        if came_back:
            self.db.add_event(ts, "device_back", s.mac, {"ip": s.ip, "away_since": existing["last_seen"]})
            self.db.set_present(s.mac, True)
        if changes or came_back:
            self.db.add_observation(ts, s.mac, s.ip, s.hostname, source)
        self.db.upsert_device(s.mac, ts, **fields)
        return False

    def mark_seen_by_ip(self, ip: str, source: str, now: datetime | None = None) -> bool:
        """Voor hosts zonder MAC (ander subnet): koppel via het laatst bekende IP."""
        device = self.db.device_by_ip(ip)
        if device is None:
            return False
        self.handle_sightings([Sighting(mac=device["mac"], ip=ip)], source, now)
        return True

    def check_absent(self, now: datetime | None = None) -> None:
        now = now or utcnow()
        cutoff = iso(now - timedelta(hours=self.cfg.absent_hours))
        for device in self.db.stale_devices(cutoff):
            self.db.add_event(iso(now), "device_gone", device["mac"],
                              {"ip": device["ip"], "last_seen": device["last_seen"]})
            self.db.set_present(device["mac"], False)

    # scans

    def handle_scan(self, mac: str, ip: str, kind: str, host: Host | None, duration_s: float,
                    now: datetime | None = None) -> None:
        ts = iso(now or utcnow())
        if host is None or not host.up:
            self.db.add_scan(ts, mac, ip, kind, duration_s, False, {})
            log.info("Scan %s van %s: apparaat reageerde niet", kind, ip)
            return
        previous = self.db.last_scan_ports(mac, kind)
        self.db.add_scan(ts, mac, ip, kind, duration_s, True, host.ports)
        device = self.db.device(mac)

        if previous is None:
            if kind == "top":
                ports = [{"port": p, "proto": proto, **info} for (p, proto), info in sorted(host.ports.items())]
                self.db.add_event(ts, "first_scan", mac, {"ip": ip, "ports": ports})
            return

        for change in diff_ports(previous, host.ports):
            event_id = self.db.add_event(ts, change.type, mac, {"ip": ip, **change.detail})
            if change.type == "port_opened" and device is not None and not device["trusted"]:
                d = change.detail
                service = " ".join(v for v in (d["service"], d["version"]) if v) or "onbekende dienst"
                self._push(event_id, "Nieuwe open poort", mac=mac, message=
                           f"{describe(device)}\nPoort {d['port']}/{d['proto']}: {service}")

    def _push(self, event_id: int, title: str, message: str, mac: str) -> None:
        actions = [
            {"action": f"NWS_APPROVE_{mac}", "title": "Goedkeuren"},
            {"action": f"NWS_REJECT_{mac}", "title": "Afkeuren"},
        ]
        if self.ha.notify(self.cfg.notify_services, title, message, actions):
            self.db.mark_notified(event_id)

    # beoordelen

    def review(self, action: str, mac: str | None, now: datetime | None = None) -> int:
        """Keurt een apparaat (of met 'approve_all' alle openstaande) goed of af. Geeft het aantal terug."""
        ts = iso(now or utcnow())
        if action == "approve_all":
            macs = [d["mac"] for d in self.db.pending_devices()]
            review = "approved"
        elif action in ("approve", "reject") and mac:
            macs = [mac]
            review = "approved" if action == "approve" else "rejected"
        else:
            return 0
        done = 0
        for m in macs:
            if self.db.set_review(m, review):
                self.db.add_event(ts, review, m, {"ip": self.db.device(m)["ip"]})
                done += 1
        return done
