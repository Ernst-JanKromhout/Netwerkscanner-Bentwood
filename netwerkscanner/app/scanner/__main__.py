"""Hoofdlus: UniFi pollen, pingsweeps, nachtelijke scans, dagrapport en sensoren."""

from __future__ import annotations

import logging
import os
import queue
import threading
import time
from datetime import datetime, timedelta

from . import nmap, setup_ha
from .config import DB_PATH, Config
from .db import Database, iso, utcnow
from .engine import Engine, Sighting
from .ha_events import EventListener
from .homeassistant import HomeAssistant
from .overview import publish
from .report import build_report, build_summary
from .review import parse
from .schedule import next_daily, nightly_kind
from .unifi import UniFiClient

log = logging.getLogger("netwerkscanner")


class ScanWorker(threading.Thread):
    """Poortscans in een eigen thread, zodat een lange scan het pollen niet ophoudt."""

    def __init__(self, cfg: Config, ha: HomeAssistant):
        super().__init__(daemon=True, name="scan-worker")
        self.cfg = cfg
        self.ha = ha
        self.jobs: queue.Queue[tuple[str, str, str]] = queue.Queue()
        self.pending: set[str] = set()
        self.lock = threading.Lock()

    def request(self, mac: str, ip: str, kind: str) -> None:
        with self.lock:
            if mac in self.pending:
                return
            self.pending.add(mac)
        self.jobs.put((mac, ip, kind))

    def run(self) -> None:
        db = Database(DB_PATH)
        engine = Engine(db, self.cfg, self.ha)
        while True:
            mac, ip, kind = self.jobs.get()
            try:
                host, duration = nmap.port_scan(ip, kind, self.cfg.top_ports)
                engine.handle_scan(mac, ip, kind, host, duration)
                log.info("Scan %s van %s klaar in %.0f s", kind, ip, duration)
            except Exception:
                log.exception("Scan %s van %s mislukt", kind, ip)
            finally:
                with self.lock:
                    self.pending.discard(mac)


class Scanner:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.ha = HomeAssistant()
        self.db = Database(DB_PATH)
        self.worker = ScanWorker(cfg, self.ha)
        self.engine = Engine(self.db, cfg, self.ha, self.worker.request)
        self.unifi = UniFiClient(cfg) if cfg.unifi_enabled else None
        self._event_db: Database | None = None

    def poll_unifi(self) -> None:
        clients = self.unifi.active_clients()
        self.engine.handle_sightings(
            [Sighting(c.mac, c.ip, c.hostname, c.name, c.vendor, c.network) for c in clients], "unifi"
        )

    def ping_sweep(self) -> None:
        if not self.cfg.subnets:
            return
        hosts = nmap.ping_sweep(self.cfg.subnets)
        self.engine.handle_sightings(
            [Sighting(h.mac, h.ip, h.hostname, vendor=h.vendor) for h in hosts if h.mac], "ping"
        )
        for h in hosts:
            if not h.mac and not self.engine.mark_seen_by_ip(h.ip, "ping"):
                log.debug("Ping-antwoord van onbekend IP %s zonder MAC, overgeslagen", h.ip)

    def nightly(self, when: datetime) -> None:
        kind = nightly_kind(when, self.cfg.weekly_full_scan)
        devices = self.db.present_devices()
        log.info("Nachtelijke %s-scan van %d apparaten", kind, len(devices))
        for device in devices:
            self.worker.request(device["mac"], device["ip"], kind)
        self.db.prune(utcnow())

    def daily_report(self) -> None:
        end = iso(utcnow())
        start = self.db.get_meta("last_report_at") or iso(utcnow() - timedelta(days=1))
        text, count = build_report(self.db, start, end)
        title = f"Netwerkrapport {datetime.now():%d-%m-%Y}"
        self.ha.persistent_notification("netwerkscanner_dagrapport", title, text)
        if self.cfg.report_to_notify:
            self.ha.notify(self.cfg.notify_services, title, build_summary(self.db, start, end))
        self.db.set_meta("last_report_at", end)
        log.info("Dagrapport verstuurd met %d gebeurtenissen", count)

    def update_sensors(self) -> None:
        publish(self.db, self.ha)

    def on_ha_event(self, event_type: str, data: dict) -> None:
        """Draait in de websocket-thread, dus met een eigen databaseverbinding."""
        parsed = parse(event_type, data)
        if parsed is None:
            return
        action, mac, name = parsed
        if self._event_db is None:
            self._event_db = Database(DB_PATH)
        count = Engine(self._event_db, self.cfg, self.ha).review(action, mac, name=name)
        log.info("Beoordeling %s voor %s: %d apparaat/apparaten", action, mac or "alle openstaande", count)
        publish(self._event_db, self.ha)

    def run(self) -> None:
        self.db.set_trusted(self.cfg.trusted_macs)
        self.worker.start()
        EventListener(self.on_ha_event).start()
        now = datetime.now()
        due = {
            "unifi": now,
            "ping": now + timedelta(seconds=30),
            "absent": now + timedelta(minutes=5),
            "sensors": now + timedelta(minutes=1),
            "nightly": next_daily(now, self.cfg.nightly_scan_time),
            "report": next_daily(now, self.cfg.report_time),
        }
        if self.unifi is None:
            log.warning("Geen UniFi-gegevens ingevuld: alleen pingsweeps")
        while True:
            now = datetime.now()
            for task, when in list(due.items()):
                if now < when:
                    continue
                try:
                    self._run_task(task, when)
                except Exception:
                    log.exception("Taak %s mislukt", task)
                due[task] = self._next(task, now)
            time.sleep(5)

    def _run_task(self, task: str, when: datetime) -> None:
        if task == "unifi" and self.unifi is not None:
            self.poll_unifi()
        elif task == "ping":
            self.ping_sweep()
        elif task == "absent":
            self.engine.check_absent()
        elif task == "sensors":
            self.update_sensors()
        elif task == "nightly":
            self.nightly(when)
        elif task == "report":
            self.daily_report()

    def _next(self, task: str, now: datetime) -> datetime:
        if task == "unifi":
            return now + timedelta(seconds=self.cfg.unifi_interval_seconds)
        if task == "ping":
            return now + timedelta(minutes=self.cfg.ping_interval_minutes)
        if task in ("absent", "sensors"):
            return now + timedelta(minutes=5)
        if task == "nightly":
            return next_daily(now, self.cfg.nightly_scan_time)
        return next_daily(now, self.cfg.report_time)


def use_home_assistant_time_zone() -> None:
    """De container draait in UTC; neem de tijdzone van HA over voor rapport- en scantijden."""
    tz = HomeAssistant().time_zone()
    if tz:
        os.environ["TZ"] = tz
        time.tzset()


def set_up_dashboard(cfg: Config) -> None:
    """Fouten hier mogen de scanner niet tegenhouden: zonder dashboard werken meldingen gewoon."""
    try:
        created = setup_ha.ensure(HomeAssistant(), cfg.dashboard_path)
    except Exception as exc:
        log.warning("Dashboard en knoppen aanmaken mislukt: %s", exc)
        return
    if created:
        log.info("Aangemaakt in Home Assistant: %s", ", ".join(created))


def main() -> None:
    cfg = Config.load()
    logging.basicConfig(level=cfg.log_level.upper(), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    use_home_assistant_time_zone()
    log.info("Netwerkscanner start, tijdzone %s, subnetten: %s",
             os.environ.get("TZ", "UTC"), ", ".join(cfg.subnets) or "geen")
    if cfg.create_dashboard:
        set_up_dashboard(cfg)
    Scanner(cfg).run()


if __name__ == "__main__":
    main()
