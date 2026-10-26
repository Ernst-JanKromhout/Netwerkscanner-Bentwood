from scanner.__main__ import ScanWorker
from scanner.config import Config
from scanner.db import Database
from scanner.nmap import Host


class FakeHA:
    def __init__(self):
        self.notes = []

    def persistent_notification(self, notification_id, title, message):
        self.notes.append((notification_id, title, message))
        return True


def test_scan_now_queues_once_and_reports(tmp_path):
    ha = FakeHA()
    worker = ScanWorker(Config(), ha)
    assert worker.scan_now("00:11:32:00:00:01", "192.168.1.253")
    assert not worker.scan_now("00:11:32:00:00:01", "192.168.1.253")
    assert worker.jobs.get_nowait() == ("00:11:32:00:00:01", "192.168.1.253", "top")

    db = Database(tmp_path / "t.db")
    host = Host("192.168.1.253", True, ports={(22, "tcp"): {"service": "ssh"}, (8123, "tcp"): {}})
    worker._report_manual(db, "00:11:32:00:00:01", "192.168.1.253", host, 12)
    note_id, title, text = ha.notes[0]
    assert note_id == "netwerkscanner_scan_001132000001" and title == "Scan klaar in 12 s"
    assert "2 open poort(en)" in text and "🟠 **22/tcp**" in text and "🟢 **8123/tcp** Home Assistant" in text
