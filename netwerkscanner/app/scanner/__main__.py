"""Hoofdlus: UniFi pollen, pingsweeps, nachtelijke scans, dagrapport en sensoren."""

from __future__ import annotations

import itertools
import logging
import os
import queue
import threading
import time
from datetime import datetime, timedelta

import requests

from . import __version__, nmap, setup_ha
from .config import DB_PATH, Config
from .db import Database, iso, label, utcnow
from .ports import RISK_LABELS, explain, risk
from .engine import Engine, Sighting
from .ha_events import NOTIFICATIONS, EventListener
from .health import Health
from .homeassistant import HomeAssistant
from .mqtt import MqttSensors, broker_settings
from .networks import configured_networks
from .overview import SENSOR_IDS, publish
from .report import build_report, build_summary
from .review import parse
from .security import login_notifications, parse_login, parse_threat
from .schedule import next_daily, nightly_kind
from .unifi import UniFiClient, UniFiError

log = logging.getLogger("netwerkscanner")


# Lager is eerder: met de hand gestart, dan nieuwe apparaten, dan de nachtelijke ronde.
PRIO_MANUAL, PRIO_NEW, PRIO_NIGHTLY = 0, 1, 2


class ScanWorker:
    """Poortscans in eigen threads, zodat een lange scan het pollen niet ophoudt.

    Eén wachtrij met voorrang: een nieuw apparaat of Nu scannen hoeft niet te wachten tot de
    zondagse volledige scans van het hele netwerk klaar zijn. Er lopen `cfg.scan_workers` scans tegelijk.
    """

    def __init__(self, cfg: Config, ha: HomeAssistant):
        self.cfg = cfg
        self.ha = ha
        self.jobs: queue.PriorityQueue[tuple[int, int, str, str, str]] = queue.PriorityQueue()
        self.queued: dict[tuple[str, str], tuple[int, int]] = {}  # (mac, kind) -> (voorrang, volgnummer)
        self.running: set[tuple[str, str]] = set()
        self.manual: set[str] = set()  # met de hand gestart: uitslag als melding in HA
        self.lock = threading.Lock()
        self._seq = itertools.count()

    def request(self, mac: str, ip: str, kind: str, priority: int = PRIO_NEW) -> bool:
        """Zet een scan in de rij. Staat hij er al met minder voorrang, dan schuift hij naar voren."""
        key = (mac, kind)
        with self.lock:
            if key in self.running:
                return False
            current = self.queued.get(key)
            if current is not None and current[0] <= priority:
                return False
            seq = next(self._seq)
            self.queued[key] = (priority, seq)
        self.jobs.put((priority, seq, mac, ip, kind))
        return True

    def start(self) -> None:
        for i in range(max(1, self.cfg.scan_workers)):
            threading.Thread(target=self._loop, daemon=True, name=f"scan-worker-{i + 1}").start()

    def next_job(self, block: bool = True) -> tuple[str, str, str] | None:
        """De volgende scan, of None als deze vervangen is door dezelfde scan met meer voorrang."""
        _, seq, mac, ip, kind = self.jobs.get(block)
        with self.lock:
            current = self.queued.get((mac, kind))
            if current is None or current[1] != seq:
                return None
            del self.queued[(mac, kind)]
            self.running.add((mac, kind))
        return mac, ip, kind

    def _loop(self) -> None:
        db = Database(DB_PATH)
        engine = Engine(db, self.cfg, self.ha)
        while True:
            job = self.next_job()
            if job is None:
                continue
            mac, ip, kind = job
            try:
                host, duration = nmap.port_scan(ip, kind, self.cfg.top_ports)
                engine.handle_scan(mac, ip, kind, host, duration)
                log.info("Scan %s van %s klaar in %.0f s", kind, ip, duration)
                if kind == "top" and mac in self.manual:
                    self._report_manual(db, mac, ip, host, duration)
            except Exception:
                log.exception("Scan %s van %s mislukt", kind, ip)
            finally:
                with self.lock:
                    self.running.discard((mac, kind))
                    if kind == "top":
                        self.manual.discard(mac)

    def scan_now(self, mac: str, ip: str) -> bool:
        """Scan op verzoek, vooraan in de rij; False als hij al loopt of al vooraan staat.

        Ook dan komt de uitslag als melding: de scan die al liep of wachtte telt als deze.
        """
        with self.lock:
            self.manual.add(mac)
        return self.request(mac, ip, "top", PRIO_MANUAL)

    def _report_manual(self, db: Database, mac: str, ip: str, host, duration: float) -> None:
        device = db.device(mac)
        name = label(device, ip) if device else ip
        if not host.up:
            text = f"{name} ({ip}) reageerde niet."
        elif not host.ports:
            text = f"{name} ({ip}): geen open poorten."
        else:
            lines = [f"- {RISK_LABELS[risk(p)]} **{p}/{proto}** {explain(p, info.get('service'))}"
                     for (p, proto), info in sorted(host.ports.items())]
            text = f"{name} ({ip}), {len(host.ports)} open poort(en):\n" + "\n".join(lines)
        self.ha.persistent_notification(f"netwerkscanner_scan_{mac.replace(':', '')}",
                                        f"Scan klaar in {duration:.0f} s", text)


class Scanner:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.ha = HomeAssistant()
        self.health = Health()
        self.db = Database(DB_PATH)
        self.worker = ScanWorker(cfg, self.ha)
        self.engine = Engine(self.db, cfg, self.ha, self.worker.request)
        self.unifi = UniFiClient(cfg) if cfg.unifi_enabled else None
        self._event_db: Database | None = None
        self._unifi_networks: list = []
        self._unifi_networks_at: float | None = None

    def poll_unifi(self) -> None:
        try:
            clients = self.unifi.active_clients()
        except (UniFiError, requests.RequestException) as exc:
            log.warning("UniFi uitlezen mislukt, volgende ronde opnieuw: %s", exc)
            self.health.fail("unifi", str(exc))
            return
        self.health.ok("unifi")
        self.engine.handle_sightings(
            [Sighting(c.mac, c.ip, c.hostname, c.name, c.vendor, c.network) for c in clients], "unifi"
        )

    def ping_sweep(self) -> None:
        if not self.cfg.subnets:
            return
        try:
            hosts = nmap.ping_sweep(self.cfg.subnets)
        except Exception as exc:
            self.health.fail("ping", str(exc))
            raise
        self.health.ok("ping")
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
            self.worker.request(device["mac"], device["ip"], kind, PRIO_NIGHTLY)
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

    def check_networks(self) -> None:
        """Eigen netwerken: subnets en known_subnets, plus wat UniFi kent (elk uur opnieuw opgehaald)."""
        if self.unifi is not None and (self._unifi_networks_at is None
                                       or time.monotonic() - self._unifi_networks_at > 3600):
            try:
                self._unifi_networks = self.unifi.networks()
                self._unifi_networks_at = time.monotonic()
            except (UniFiError, requests.RequestException) as exc:
                log.warning("Netwerken uit UniFi lezen mislukt, vorige lijst blijft gelden: %s", exc)
                if self._unifi_networks_at is None:
                    return  # zonder de UniFi-netwerken zou alles als onbekend tellen
        known = configured_networks(self.cfg.subnets, self.cfg.known_subnets) + self._unifi_networks
        new = self.engine.check_networks(known)
        if new:
            log.warning("%d onbekend(e) netwerk(en) gezien", new)
            self.update_sensors()

    def update_sensors(self) -> None:
        publish(self.db, self.ha, self.health)

    def check_health(self) -> None:
        """Storingen van de scanner zelf melden, en meldingen die niet aankwamen opnieuw proberen."""
        transitions = self.health.check()
        self.engine.handle_health(transitions)
        if transitions:
            self.update_sensors()
        if self.engine.retry_pushes():
            log.info("Eerder mislukte meldingen alsnog verstuurd")

    def poll_threats(self) -> None:
        now_ms = int(time.time() * 1000)
        since = int(self.db.get_meta("last_threat_ms") or now_ms - 3600 * 1000)
        try:
            records = self.unifi.threat_records(since, now_ms)
        except (UniFiError, requests.RequestException) as exc:
            log.warning("IPS-meldingen uit UniFi lezen mislukt: %s", exc)
            self.health.fail("threats", str(exc))
            return
        self.health.ok("threats")
        threats = [t for t in (parse_threat(r) for r in records) if t is not None]
        count = self.engine.handle_threats(threats)
        if count:
            log.info("%d nieuwe IPS-melding(en) uit UniFi", count)

    def on_ha_event(self, event_type: str, data: dict) -> None:
        """Draait in de websocket-thread, dus met een eigen databaseverbinding."""
        if self._event_db is None:
            self._event_db = Database(DB_PATH)
        if event_type == NOTIFICATIONS:
            for message in login_notifications(data):
                login = parse_login(message)
                if login:
                    log.warning("Mislukte inlogpoging op HA van %s (%s)", *login)
                    Engine(self._event_db, self.cfg, self.ha).handle_failed_login(*login)
                    publish(self._event_db, self.ha, self.health)
            return
        parsed = parse(event_type, data)
        if parsed is None:
            return
        action, mac, name = parsed
        if action == "scan":
            device = self._event_db.device(mac)
            if device is None or not device["ip"]:
                log.warning("Nu scannen: geen IP bekend voor %s", mac)
                return
            started = self.worker.scan_now(mac, device["ip"])
            log.info("Nu scannen van %s (%s): %s", device["ip"], mac, "gestart" if started else "loopt al")
            return
        count = Engine(self._event_db, self.cfg, self.ha).review(action, mac, name=name)
        log.info("Beoordeling %s voor %s: %d apparaat/apparaten", action, mac or "alle openstaande", count)
        publish(self._event_db, self.ha, self.health)

    def _ha_events_status(self, ok: bool, error: str | None) -> None:
        if ok:
            self.health.ok("ha_events")
        else:
            self.health.fail("ha_events", error or "verbinding verbroken")

    def use_mqtt(self) -> None:
        """Sensoren via MQTT als er een broker is, anders zoals voorheen via de REST-API."""
        settings = broker_settings()
        sensors = MqttSensors.connect(settings, __version__) if settings else None
        if sensors is None:
            log.info("Sensoren via de REST-API: na een herstart van HA zijn ze er pas weer na de volgende ronde")
            self.db.set_meta("sensor_transport", "rest")
            return
        migrate_to_mqtt(self.db, self.ha)
        self.ha.sensors = sensors
        self.update_sensors()  # meteen, zodat de entiteiten niet een minuut ontbreken

    def run(self) -> None:
        self.db.set_trusted(self.cfg.trusted_macs)
        self.use_mqtt()
        self.worker.start()
        EventListener(self.on_ha_event, on_status=self._ha_events_status).start()
        now = datetime.now()
        due = {
            "unifi": now,
            "ping": now + timedelta(seconds=30),
            "absent": now + timedelta(minutes=5),
            "sensors": now + timedelta(minutes=1),
            "threats": now + timedelta(seconds=45),
            "health": now + timedelta(minutes=1),
            "networks": now + timedelta(minutes=2),
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
        elif task == "threats" and self.unifi is not None:
            self.poll_threats()
        elif task == "ping":
            self.ping_sweep()
        elif task == "absent":
            self.engine.check_absent()
        elif task == "sensors":
            self.update_sensors()
        elif task == "health":
            self.check_health()
        elif task == "networks":
            self.check_networks()
        elif task == "nightly":
            self.nightly(when)
        elif task == "report":
            self.daily_report()

    def _next(self, task: str, now: datetime) -> datetime:
        if task == "unifi":
            return now + timedelta(seconds=self.cfg.unifi_interval_seconds)
        if task == "ping":
            return now + timedelta(minutes=self.cfg.ping_interval_minutes)
        if task == "health":
            return now + timedelta(minutes=1)
        if task in ("absent", "sensors", "threats", "networks"):
            return now + timedelta(minutes=5)
        if task == "nightly":
            return next_daily(now, self.cfg.nightly_scan_time)
        return next_daily(now, self.cfg.report_time)


def migrate_to_mqtt(db: Database, ha: HomeAssistant) -> None:
    """Haalt de oude REST-sensoren weg voordat MQTT dezelfde entity_id's opeist.

    Anders ziet HA de naam als bezet en maakt hij sensor.netwerkscanner_..._2 aan, en kloppen dashboards niet meer.
    Alleen bij de overstap: daarna zijn het MQTT-entiteiten en raken we ze niet meer via REST aan.
    """
    if db.get_meta("sensor_transport") == "mqtt":
        return
    for entity_id in SENSOR_IDS:
        ha.delete_state(entity_id)
    db.set_meta("sensor_transport", "mqtt")
    log.info("Oude REST-sensoren weggehaald, voortaan via MQTT")


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
        log.info("Aangemaakt of bijgewerkt in Home Assistant: %s", ", ".join(created))


def main() -> None:
    cfg = Config.load()
    logging.basicConfig(level=cfg.log_level.upper(), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    use_home_assistant_time_zone()
    log.info("Netwerkscanner %s start, tijdzone %s, subnetten: %s",
             __version__, os.environ.get("TZ", "UTC"), ", ".join(cfg.subnets) or "geen")
    if cfg.create_dashboard:
        set_up_dashboard(cfg)
    Scanner(cfg).run()


if __name__ == "__main__":
    main()
