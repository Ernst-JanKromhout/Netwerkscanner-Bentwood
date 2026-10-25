"""Leest de add-on-opties uit /data/options.json."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import time
from pathlib import Path

OPTIONS_PATH = Path("/data/options.json")
DB_PATH = Path("/data/netwerkscanner.db")


def _parse_time(value: str) -> time:
    hours, minutes = value.split(":")
    return time(int(hours), int(minutes))


@dataclass
class Config:
    unifi_host: str = ""
    unifi_username: str = ""
    unifi_password: str = ""
    unifi_site: str = "default"
    unifi_verify_ssl: bool = False
    subnets: list[str] = field(default_factory=list)
    notify_services: list[str] = field(default_factory=list)
    dashboard_path: str = "/dashboard-netwerk/overzicht"
    create_dashboard: bool = True
    trusted_macs: set[str] = field(default_factory=set)
    unifi_interval_seconds: int = 60
    ping_interval_minutes: int = 15
    nightly_scan_time: time = time(3, 0)
    weekly_full_scan: bool = True
    report_time: time = time(7, 30)
    report_to_notify: bool = True
    absent_hours: int = 24
    top_ports: int = 1000
    log_level: str = "info"

    @property
    def unifi_enabled(self) -> bool:
        return bool(self.unifi_host and self.unifi_username and self.unifi_password)

    @classmethod
    def from_dict(cls, raw: dict) -> "Config":
        cfg = cls()
        for key, value in raw.items():
            if not hasattr(cfg, key):
                continue
            if key in ("nightly_scan_time", "report_time"):
                value = _parse_time(value)
            elif key == "trusted_macs":
                value = {normalize_mac(m) for m in value}
            setattr(cfg, key, value)
        return cfg

    @classmethod
    def load(cls, path: Path = OPTIONS_PATH) -> "Config":
        return cls.from_dict(json.loads(path.read_text()))


def normalize_mac(mac: str) -> str:
    return mac.strip().lower().replace("-", ":")
