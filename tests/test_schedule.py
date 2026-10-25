from datetime import datetime, time

from scanner.config import Config
from scanner.schedule import next_daily, nightly_kind


def test_next_daily_today_or_tomorrow():
    assert next_daily(datetime(2026, 10, 25, 2, 0), time(3, 0)) == datetime(2026, 10, 25, 3, 0)
    assert next_daily(datetime(2026, 10, 25, 3, 0), time(3, 0)) == datetime(2026, 10, 26, 3, 0)


def test_full_scan_on_sunday_only():
    assert nightly_kind(datetime(2026, 10, 25, 3, 0), True) == "full"  # zondag
    assert nightly_kind(datetime(2026, 10, 26, 3, 0), True) == "top"
    assert nightly_kind(datetime(2026, 10, 25, 3, 0), False) == "top"


def test_config_from_options():
    cfg = Config.from_dict({"report_time": "07:30", "trusted_macs": ["AA-BB-CC-DD-EE-FF"], "onbekend": 1})
    assert cfg.report_time == time(7, 30)
    assert cfg.trusted_macs == {"aa:bb:cc:dd:ee:ff"}


def test_time_zone_from_home_assistant():
    from scanner.homeassistant import HomeAssistant

    class Resp:
        def raise_for_status(self):
            pass

        def json(self):
            return {"time_zone": "Europe/Amsterdam"}

    ha = HomeAssistant(token="x")
    ha.session.get = lambda url, timeout: Resp()
    assert ha.time_zone() == "Europe/Amsterdam"
