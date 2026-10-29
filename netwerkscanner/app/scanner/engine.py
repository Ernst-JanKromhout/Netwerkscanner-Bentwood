"""Verwerkt waarnemingen en scans tot gebeurtenissen, en meldt wat urgent is."""

from __future__ import annotations

import ipaddress
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Callable

from .config import Config
from .db import Database, iso, label, utcnow
from .diff import Change, diff_identity, diff_ports, is_random_mac
from .health import SOURCES, Transition
from .networks import KnownNetwork, find_known, strip_port, unknown_network
from .homeassistant import HomeAssistant
from .nmap import Host
from .ports import RISK_LABELS, explain, risk
from .security import Threat

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
    return f"{label(device, 'Onbekend apparaat')} ({device['ip'] or 'geen IP'}, {device['mac']})"


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
                self._push(event_id, "Nieuw apparaat op je netwerk", "\n".join(lines))
            return True

        hostname = s.hostname
        if source != "unifi" and existing["hostname"]:
            # DNS geeft soms een andere of ingekorte naam dan UniFi; zonder dit wisselt de naam elke scan.
            hostname = existing["hostname"]
            fields.pop("hostname", None)
        changes: list[Change] = diff_identity(existing["ip"], existing["hostname"], s.ip, hostname)
        came_back = not existing["present"]
        for change in changes:
            self.db.add_event(ts, change.type, s.mac, change.detail)
        if came_back:
            event_id = self.db.add_event(ts, "device_back", s.mac, {"ip": s.ip, "away_since": existing["last_seen"]})
            self.db.set_present(s.mac, True)
        if changes or came_back:
            self.db.add_observation(ts, s.mac, s.ip, s.hostname, source)
        self.db.upsert_device(s.mac, ts, **fields)
        if came_back and existing["review"] == "rejected":
            self._push(event_id, "Afgekeurd apparaat weer online",
                       f"{describe(self.db.device(s.mac))}\nJe had dit apparaat afgekeurd. Blokkeer het in UniFi "
                       "als het niet op je netwerk hoort.", review_hint=False)
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
                self._push(event_id, "Nieuwe open poort",
                           f"{describe(device)}\nPoort {d['port']}/{d['proto']}: {service}\n{RISK_LABELS[risk(d['port'])]} {explain(d['port'], d['service'])}")

    def _push(self, event_id: int, title: str, message: str, review_hint: bool = True) -> None:
        """Melding in HA en op de telefoon. Lukt een van beide niet (HA even weg), dan later opnieuw."""
        url = self.cfg.dashboard_path
        note_id = f"netwerkscanner_{event_id}"
        note_text = f"{message}\n\n[Open het dashboard Netwerk]({url})"
        noted = self.ha.persistent_notification(note_id, title, note_text)
        if review_hint:
            message += "\nBeoordeel het in het dashboard Netwerk."
        delivered = self.ha.notify(self.cfg.notify_services, title, message, url)
        if delivered:
            self.db.mark_notified(event_id)
        pushed = delivered or not self.cfg.notify_services  # zonder diensten valt er niets te herhalen
        if not (pushed and noted):
            self.db.queue_push(iso(utcnow()), event_id, title, None if pushed else message, url,
                               None if noted else note_id, note_text)
            log.info("Melding '%s' kwam niet aan, wordt later opnieuw geprobeerd", title)

    def retry_pushes(self, now: datetime | None = None) -> int:
        """Probeert meldingen die niet aankwamen opnieuw; na een dag vervallen ze (het dagrapport heeft ze)."""
        now = now or utcnow()
        dropped = self.db.drop_outbox_before(iso(now - timedelta(days=1)))
        if dropped:
            log.warning("%d melding(en) na een dag nog steeds niet aangekomen, vervallen", dropped)
        sent = 0
        for row in self.db.outbox():
            push_done = not row["message"] or self.ha.notify(self.cfg.notify_services, row["title"],
                                                              row["message"], row["url"])
            note_done = not row["note_id"] or self.ha.persistent_notification(row["note_id"], row["title"],
                                                                               row["note_text"])
            if push_done and row["message"] and row["event_id"]:
                self.db.mark_notified(row["event_id"])
            self.db.update_outbox(row["id"], push_done, note_done)
            sent += push_done and note_done
        return sent

    # netwerken

    def check_networks(self, known: list[KnownNetwork], now: datetime | None = None) -> int:
        """Zoekt IP's buiten je eigen netwerken en meldt elk onbekend netwerk één keer. Geeft het aantal nieuwe.

        Bronnen: apparaten van de laatste week en adressen uit IPS-meldingen en mislukte logins.
        Zonder bekende netwerken (geen UniFi en geen subnets) valt er niets te vergelijken.
        """
        if not known:
            return 0
        now = now or utcnow()
        ts = iso(now)
        since = iso(now - timedelta(days=7))
        found: dict[str, tuple[str, str | None]] = {}  # cidr -> (waar gezien, mac)
        for device in self.db.recent_devices(since):
            net = unknown_network(device["ip"], known)
            if net is not None:
                found.setdefault(str(net), (describe(device), device["mac"]))
        for e in self.db.events_of_types(("intrusion", "login_failed"), since):
            d = json.loads(e["detail"])
            what = "een IPS-melding" if e["type"] == "intrusion" else "een mislukte login op HA"
            for address in (d.get("src"), d.get("dst"), d.get("ip")):
                if not address:
                    continue
                ip = strip_port(address)
                net = unknown_network(ip, known)
                if net is not None:
                    found.setdefault(str(net), (f"{ip} in {what}", None))

        new = 0
        for cidr, (example, mac) in found.items():
            row = self.db.network(cidr)
            if row is None:
                self.db.add_network(cidr, ts, example, mac)
                event_id = self.db.add_event(ts, "unknown_network", mac, {"network": cidr, "voorbeeld": example})
                self._push(event_id, f"Onbekend netwerk {cidr}",
                           f"Gezien bij: {example}\n"
                           "Dit netwerk hoort niet bij je eigen netwerken. Vaak is het een extra router of extender, "
                           "een apparaat met een eigen hotspot, een VPN of een verkeerd ingesteld vast IP.\n"
                           "Hoort het erbij, zet het dan in de optie known_subnets.", review_hint=False)
                new += 1
            else:
                self.db.seen_network(cidr, ts, example, mac)
                if row["known_as"] is not None:
                    self.db.set_network_known(cidr, None)
        # Netwerken die je intussen goedkeurde of die UniFi nu kent, tellen niet meer als onbekend.
        for row in self.db.networks():
            if row["known_as"] is None and row["cidr"] not in found:
                match = find_known(str(ipaddress.ip_network(row["cidr"]).network_address + 1), known)
                if match is not None:
                    self.db.set_network_known(row["cidr"], match.name)
        return new

    # gezondheid van de scanner zelf

    def handle_health(self, transitions: list[Transition], now: datetime | None = None) -> None:
        ts = iso(now or utcnow())
        for t in transitions:
            name = SOURCES.get(t.source, t.source)
            if t.ok:
                event_id = self.db.add_event(ts, "scanner_ok", None, {"bron": name})
                self._push(event_id, f"Netwerkscanner: {name} werkt weer", "De scanner volgt je netwerk weer.",
                           review_hint=False)
            else:
                event_id = self.db.add_event(ts, "scanner_fault", None, {"bron": name, "fout": t.error})
                self._push(event_id, f"Netwerkscanner: storing bij {name}",
                           f"Werkt al sinds {t.since.astimezone():%H:%M} niet.\n{t.error or ''}".strip(),
                           review_hint=False)

    # beveiliging

    def handle_threats(self, threats: list[Threat], now: datetime | None = None) -> int:
        """Slaat nieuwe IPS-meldingen op en stuurt één push per ronde. Geeft het aantal nieuwe terug."""
        now = now or utcnow()
        last = int(self.db.get_meta("last_threat_ms") or 0)
        new = sorted((t for t in threats if t.ts_ms > last), key=lambda t: t.ts_ms)
        if not new:
            return 0
        event_id = 0
        for t in new:
            event_id = self.db.add_event(iso(now), "intrusion", None, t.detail())
        self.db.set_meta("last_threat_ms", str(new[-1].ts_ms))
        blocked = sum(t.blocked for t in new)
        latest = new[-1]
        title = "Aanval op je netwerk" if len(new) == 1 else f"{len(new)} aanvallen op je netwerk"
        status = "geblokkeerd" if blocked == len(new) else f"{blocked} van {len(new)} geblokkeerd"
        self._push(event_id, title,
                   f"{status}\nLaatste: {latest.signature}\nVan {self._who(latest.src)} naar {self._who(latest.dst)}")
        return len(new)

    def handle_failed_login(self, host: str, ip: str, now: datetime | None = None) -> None:
        """Mislukte login op HA. Push hooguit één keer per uur per IP, het rapport krijgt ze allemaal."""
        now = now or utcnow()
        event_id = self.db.add_event(iso(now), "login_failed", None, {"ip": ip, "host": host})
        key = f"login_push_{ip}"
        previous = self.db.get_meta(key)
        if previous and datetime.fromisoformat(previous) > now - timedelta(hours=1):
            return
        self.db.set_meta(key, iso(now))
        self._push(event_id, "Mislukte inlogpoging op Home Assistant", f"Van {self._who(ip)}")

    def _who(self, address: str) -> str:
        """IP (met poort) plus de naam als het een apparaat uit je eigen netwerk is."""
        device = self.db.device_by_ip(address.rsplit(":", 1)[0] if address.count(":") == 1 else address)
        return f"{label(device, address)} ({address})" if device else address

    # beoordelen

    def review(self, action: str, mac: str | None, now: datetime | None = None, name: str | None = None) -> int:
        """Keurt een apparaat (of met 'approve_all' alle openstaande) goed of af, of geeft het een naam.

        Geeft het aantal aangepaste apparaten terug.
        """
        ts = iso(now or utcnow())
        if action == "rename":
            device = self.db.device(mac) if mac else None
            if device is None:
                return 0
            old = label(device)
            self.db.set_alias(mac, (name or "").strip())
            self.db.add_event(ts, "renamed", mac, {"ip": device["ip"], "old": old, "new": label(self.db.device(mac))})
            return 1
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
