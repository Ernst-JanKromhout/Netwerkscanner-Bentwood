"""SQLite-opslag van apparaten, waarnemingen, scans, poorten en gebeurtenissen."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    mac         TEXT PRIMARY KEY,
    ip          TEXT,
    hostname    TEXT,
    name        TEXT,
    vendor      TEXT,
    network     TEXT,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    present     INTEGER NOT NULL DEFAULT 1,
    trusted     INTEGER NOT NULL DEFAULT 0,
    review      TEXT, -- NULL = nog te beoordelen, 'approved' of 'rejected'
    alias       TEXT  -- naam die de gebruiker zelf gaf; gaat boven alle andere namen
);

-- Alleen een regel bij een wijziging van IP of hostnaam, of bij terugkeer.
CREATE TABLE IF NOT EXISTS observations (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT NOT NULL,
    mac       TEXT NOT NULL,
    ip        TEXT,
    hostname  TEXT,
    source    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_observations_mac ON observations (mac, ts);

CREATE TABLE IF NOT EXISTS scans (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           TEXT NOT NULL,
    mac          TEXT NOT NULL,
    ip           TEXT NOT NULL,
    kind         TEXT NOT NULL,
    duration_s   REAL,
    host_up      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_mac ON scans (mac, ts);

CREATE TABLE IF NOT EXISTS ports (
    scan_id   INTEGER NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    port      INTEGER NOT NULL,
    proto     TEXT NOT NULL,
    service   TEXT,
    version   TEXT,
    PRIMARY KEY (scan_id, port, proto)
);

CREATE TABLE IF NOT EXISTS events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT NOT NULL,
    type      TEXT NOT NULL,
    mac       TEXT,
    detail    TEXT NOT NULL,
    notified  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events (ts);

-- Pushmeldingen die niet aankwamen (HA even weg); worden later opnieuw geprobeerd.
CREATE TABLE IF NOT EXISTS outbox (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    event_id    INTEGER,
    title       TEXT NOT NULL,
    message     TEXT NOT NULL,
    url         TEXT,
    note_id     TEXT,  -- melding in HA zelf, als die ook niet lukte
    note_text   TEXT,
    tries       INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS meta (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);
"""


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def label(device, fallback: str = "Onbekend") -> str:
    """Naam om te tonen: eigen naam, dan UniFi-naam, hostnaam of fabrikant."""
    keys = device.keys()
    alias = device["alias"] if "alias" in keys else None
    return alias or device["name"] or device["hostname"] or device["vendor"] or fallback


class Database:
    def __init__(self, path: Path | str):
        self.conn = sqlite3.connect(str(path), timeout=30, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript(SCHEMA)
        columns = {r["name"] for r in self.conn.execute("PRAGMA table_info(devices)")}
        if "review" not in columns:
            self.conn.execute("ALTER TABLE devices ADD COLUMN review TEXT")
        if "alias" not in columns:
            self.conn.execute("ALTER TABLE devices ADD COLUMN alias TEXT")

    def close(self) -> None:
        self.conn.close()

    # meta

    def get_meta(self, key: str) -> str | None:
        row = self.conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    def set_meta(self, key: str, value: str) -> None:
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES (?, ?) "
            "ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            (key, value),
        )

    # devices

    def device(self, mac: str) -> sqlite3.Row | None:
        return self.conn.execute("SELECT * FROM devices WHERE mac = ?", (mac,)).fetchone()

    def device_by_ip(self, ip: str) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM devices WHERE ip = ? ORDER BY last_seen DESC LIMIT 1", (ip,)
        ).fetchone()

    def device_count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]

    def present_devices(self) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM devices WHERE present = 1 AND ip IS NOT NULL ORDER BY ip"
        ).fetchall()

    def upsert_device(self, mac: str, ts: str, **fields) -> None:
        existing = self.device(mac)
        if existing is None:
            cols = ["mac", "first_seen", "last_seen", *fields]
            vals = [mac, ts, ts, *fields.values()]
            self.conn.execute(
                f"INSERT INTO devices ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})",
                vals,
            )
            return
        sets = ["last_seen = ?"] + [f"{k} = ?" for k in fields]
        self.conn.execute(
            f"UPDATE devices SET {', '.join(sets)} WHERE mac = ?",
            [ts, *fields.values(), mac],
        )

    def set_present(self, mac: str, present: bool) -> None:
        self.conn.execute("UPDATE devices SET present = ? WHERE mac = ?", (int(present), mac))

    def set_trusted(self, macs: set[str]) -> None:
        """Vertrouwd = goedgekeurd, of in trusted_macs zolang het niet is afgekeurd."""
        self.conn.execute("UPDATE devices SET trusted = (review IS 'approved')")
        self.conn.executemany(
            "UPDATE devices SET trusted = 1 WHERE mac = ? AND review IS NOT 'rejected'", [(m,) for m in macs]
        )

    def set_review(self, mac: str, review: str) -> bool:
        cur = self.conn.execute(
            "UPDATE devices SET review = ?, trusted = ? WHERE mac = ?",
            (review, int(review == "approved"), mac),
        )
        return cur.rowcount > 0

    def set_alias(self, mac: str, alias: str | None) -> bool:
        cur = self.conn.execute("UPDATE devices SET alias = ? WHERE mac = ?", (alias or None, mac))
        return cur.rowcount > 0

    def all_devices(self) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM devices ORDER BY present DESC, ip").fetchall()

    def pending_devices(self) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM devices WHERE trusted = 0 AND review IS NULL ORDER BY present DESC, last_seen DESC"
        ).fetchall()

    def stale_devices(self, before: str) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM devices WHERE present = 1 AND last_seen < ?", (before,)
        ).fetchall()

    def add_observation(self, ts: str, mac: str, ip: str | None, hostname: str | None, source: str) -> None:
        self.conn.execute(
            "INSERT INTO observations (ts, mac, ip, hostname, source) VALUES (?, ?, ?, ?, ?)",
            (ts, mac, ip, hostname, source),
        )

    # scans

    def last_scan_ports(self, mac: str, kind: str) -> dict[tuple[int, str], dict] | None:
        """Poorten van de laatste geslaagde scan van dit soort, of None als die er nog niet is.

        Scans worden alleen met hetzelfde soort vergeleken: een volledige scan ziet meer
        poorten dan een top-scan, en dat is geen wijziging op het apparaat.
        """
        scan = self.conn.execute(
            "SELECT id FROM scans WHERE mac = ? AND kind = ? AND host_up = 1 ORDER BY id DESC LIMIT 1",
            (mac, kind),
        ).fetchone()
        if scan is None:
            return None
        rows = self.conn.execute(
            "SELECT port, proto, service, version FROM ports WHERE scan_id = ?", (scan["id"],)
        ).fetchall()
        return {(r["port"], r["proto"]): {"service": r["service"], "version": r["version"]} for r in rows}

    def latest_ports(self) -> dict[str, list[dict]]:
        """Open poorten uit de laatste geslaagde scan per apparaat (elk soort scan)."""
        rows = self.conn.execute(
            """
            SELECT s.mac, p.port, p.proto, p.service, p.version
            FROM scans s
            JOIN (SELECT mac, MAX(id) AS id FROM scans WHERE host_up = 1 GROUP BY mac) last
              ON last.id = s.id
            JOIN ports p ON p.scan_id = s.id
            ORDER BY s.mac, p.proto, p.port
            """
        ).fetchall()
        result: dict[str, list[dict]] = {}
        for r in rows:
            result.setdefault(r["mac"], []).append(
                {"port": r["port"], "proto": r["proto"], "service": r["service"], "version": r["version"]}
            )
        return result

    def scanned_macs(self) -> set[str]:
        return {r["mac"] for r in self.conn.execute("SELECT DISTINCT mac FROM scans WHERE host_up = 1")}

    def recent_events(self, limit: int) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()

    def add_scan(self, ts: str, mac: str, ip: str, kind: str, duration_s: float, host_up: bool,
                 ports: dict[tuple[int, str], dict]) -> int:
        cur = self.conn.execute(
            "INSERT INTO scans (ts, mac, ip, kind, duration_s, host_up) VALUES (?, ?, ?, ?, ?, ?)",
            (ts, mac, ip, kind, duration_s, int(host_up)),
        )
        scan_id = cur.lastrowid
        self.conn.executemany(
            "INSERT INTO ports (scan_id, port, proto, service, version) VALUES (?, ?, ?, ?, ?)",
            [(scan_id, port, proto, p.get("service"), p.get("version")) for (port, proto), p in ports.items()],
        )
        return scan_id

    # events

    def add_event(self, ts: str, type_: str, mac: str | None, detail: dict) -> int:
        cur = self.conn.execute(
            "INSERT INTO events (ts, type, mac, detail) VALUES (?, ?, ?, ?)",
            (ts, type_, mac, json.dumps(detail, ensure_ascii=False)),
        )
        return cur.lastrowid

    def mark_notified(self, event_id: int) -> None:
        self.conn.execute("UPDATE events SET notified = 1 WHERE id = ?", (event_id,))

    def events_between(self, start: str, end: str) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM events WHERE ts >= ? AND ts < ? ORDER BY ts", (start, end)
        ).fetchall()

    # meldingen die nog weg moeten

    def queue_push(self, ts: str, event_id: int | None, title: str, message: str | None, url: str | None,
                   note_id: str | None = None, note_text: str | None = None) -> None:
        """`message` None: de push kwam aan, alleen de melding in HA nog niet."""
        self.conn.execute(
            "INSERT INTO outbox (ts, event_id, title, message, url, note_id, note_text) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (ts, event_id, title, message or "", url, note_id, note_text),
        )

    def outbox(self) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM outbox ORDER BY id").fetchall()

    def update_outbox(self, row_id: int, push_done: bool, note_done: bool) -> None:
        if push_done and note_done:
            self.conn.execute("DELETE FROM outbox WHERE id = ?", (row_id,))
            return
        sets = ["tries = tries + 1"]
        if push_done:
            sets.append("message = ''")
        if note_done:
            sets.append("note_id = NULL")
        self.conn.execute(f"UPDATE outbox SET {', '.join(sets)} WHERE id = ?", (row_id,))

    def drop_outbox_before(self, before: str) -> int:
        return self.conn.execute("DELETE FROM outbox WHERE ts < ?", (before,)).rowcount

    # onderhoud

    def prune(self, now: datetime) -> None:
        """Waarnemingen na 90 dagen weg, scans en gebeurtenissen na een jaar (de laatste scan per apparaat blijft)."""
        self.conn.execute("DELETE FROM observations WHERE ts < ?", (iso(now - timedelta(days=90)),))
        self.conn.execute(
            "DELETE FROM scans WHERE ts < ? AND id NOT IN (SELECT MAX(id) FROM scans GROUP BY mac, kind)",
            (iso(now - timedelta(days=365)),),
        )
        self.conn.execute("DELETE FROM events WHERE ts < ?", (iso(now - timedelta(days=365)),))
