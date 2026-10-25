"""Kleine hulpfuncties voor dagelijkse tijdstippen."""

from __future__ import annotations

from datetime import datetime, time, timedelta


def next_daily(now: datetime, at: time) -> datetime:
    """Eerstvolgende moment op tijdstip `at` na `now` (lokale tijd)."""
    candidate = now.replace(hour=at.hour, minute=at.minute, second=0, microsecond=0)
    if candidate <= now:
        candidate += timedelta(days=1)
    return candidate


def nightly_kind(when: datetime, weekly_full_scan: bool) -> str:
    """Zondagnacht een volledige scan, de andere nachten de top-poorten."""
    return "full" if weekly_full_scan and when.weekday() == 6 else "top"
