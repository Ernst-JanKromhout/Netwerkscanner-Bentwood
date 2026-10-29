from scanner.__main__ import PRIO_NIGHTLY, ScanWorker
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
    assert worker.next_job(block=False) == ("00:11:32:00:00:01", "192.168.1.253", "top")

    db = Database(tmp_path / "t.db")
    host = Host("192.168.1.253", True, ports={(22, "tcp"): {"service": "ssh"}, (8123, "tcp"): {}})
    worker._report_manual(db, "00:11:32:00:00:01", "192.168.1.253", host, 12)
    note_id, title, text = ha.notes[0]
    assert note_id == "netwerkscanner_scan_001132000001" and title == "Scan klaar in 12 s"
    assert "2 open poort(en)" in text and "🟠 **22/tcp**" in text and "🟢 **8123/tcp** Home Assistant" in text


def test_new_device_and_manual_scans_jump_the_nightly_queue():
    worker = ScanWorker(Config(), FakeHA())
    for i in range(3):
        assert worker.request(f"00:11:32:00:00:0{i}", f"192.168.1.{i}", "full", PRIO_NIGHTLY)
    assert worker.request("00:11:32:00:00:09", "192.168.1.9", "top")  # nieuw apparaat
    assert worker.scan_now("00:11:32:00:00:02", "192.168.1.2")
    order = [worker.next_job(block=False) for _ in range(5)]
    assert order[0] == ("00:11:32:00:00:02", "192.168.1.2", "top")
    assert order[1] == ("00:11:32:00:00:09", "192.168.1.9", "top")
    assert [o[0] for o in order[2:]] == ["00:11:32:00:00:00", "00:11:32:00:00:01", "00:11:32:00:00:02"]


def test_higher_priority_replaces_queued_scan_and_running_scan_is_not_doubled():
    worker = ScanWorker(Config(), FakeHA())
    mac, ip = "00:11:32:00:00:01", "192.168.1.1"
    assert worker.request(mac, ip, "top", PRIO_NIGHTLY)
    assert not worker.request(mac, ip, "top", PRIO_NIGHTLY)
    assert worker.scan_now(mac, ip)  # schuift naar voren
    assert worker.next_job(block=False) == (mac, ip, "top")
    assert worker.next_job(block=False) is None  # de oude plek in de rij vervalt
    assert not worker.scan_now(mac, ip)  # loopt al; de uitslag komt toch als melding
    assert mac in worker.manual
