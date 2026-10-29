"""Houdt bij of elke bron van de scanner nog werkt, zodat een stille storing toch opvalt."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime, timedelta

from .db import utcnow

# Zo lang mag een bron falen voordat er een pushmelding komt.
ALERT_AFTER = timedelta(minutes=30)

SOURCES = {
    "unifi": "UniFi-controller",
    "threats": "IPS-meldingen uit UniFi",
    "ping": "Pingsweep (nmap)",
    "ha_events": "Koppeling met Home Assistant (knoppen en logins)",
}


@dataclass
class SourceState:
    last_ok: datetime | None = None
    failing_since: datetime | None = None
    error: str | None = None
    alerted: bool = False


@dataclass(frozen=True)
class Transition:
    source: str
    ok: bool  # True: werkt weer, False: storing
    error: str | None
    since: datetime


class Health:
    """Thread-safe: de hoofdlus, de scanthreads en de websocket-thread melden hier allemaal."""

    def __init__(self, alert_after: timedelta = ALERT_AFTER):
        self.alert_after = alert_after
        self._lock = threading.Lock()
        self._sources: dict[str, SourceState] = {}

    def ok(self, source: str, now: datetime | None = None) -> None:
        with self._lock:
            s = self._sources.setdefault(source, SourceState())
            s.last_ok = now or utcnow()
            s.failing_since = None
            s.error = None

    def fail(self, source: str, error: str, now: datetime | None = None) -> None:
        with self._lock:
            s = self._sources.setdefault(source, SourceState())
            if s.failing_since is None:
                s.failing_since = now or utcnow()
            s.error = str(error)[:300]

    def check(self, now: datetime | None = None) -> list[Transition]:
        """Wat er sinds de vorige keer is omgeslagen: een storing die lang genoeg duurt, of herstel na een melding.

        Een bron die sinds de start nog nooit werkte, geeft wel een storing maar alleen als hij eerder werkte
        of het om UniFi of de HA-koppeling gaat: de IPS-uitlezing werkt op sommige UniFi-versies gewoon niet.
        """
        now = now or utcnow()
        result = []
        with self._lock:
            for source, s in self._sources.items():
                if s.failing_since is not None and not s.alerted:
                    if s.last_ok is None and source == "threats":
                        continue
                    if now - s.failing_since >= self.alert_after:
                        s.alerted = True
                        result.append(Transition(source, False, s.error, s.failing_since))
                elif s.failing_since is None and s.alerted:
                    s.alerted = False
                    result.append(Transition(source, True, None, s.last_ok or now))
        return result

    def summary(self) -> tuple[str, list[dict]]:
        """('werkt' of 'storing', een regel per bron) voor de statussensor."""
        with self._lock:
            rows = []
            for source, s in sorted(self._sources.items()):
                rows.append({
                    "bron": SOURCES.get(source, source),
                    "werkt": s.failing_since is None,
                    "laatst_gelukt": _local(s.last_ok),
                    "storing_sinds": _local(s.failing_since),
                    "fout": s.error or "",
                })
            broken = any(s.failing_since is not None and s.alerted for s in self._sources.values())
        return ("storing" if broken else "werkt"), rows


def _local(dt: datetime | None) -> str:
    return dt.astimezone().strftime("%d-%m %H:%M") if dt else ""
