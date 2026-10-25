from pathlib import Path

from scanner.nmap import parse_xml

FIXTURE = Path(__file__).parent / "fixtures" / "portscan.xml"


def test_parse_open_ports_with_versions():
    host = parse_xml(FIXTURE.read_text())[0]
    assert host.ip == "192.168.1.50"
    assert host.mac == "aa:bb:cc:00:11:22"
    assert host.vendor == "Synology"
    assert host.hostname == "nas.local"
    assert host.up
    assert host.ports == {
        (22, "tcp"): {"service": "ssh", "version": "OpenSSH 9.6"},
        (443, "tcp"): {"service": "https", "version": "nginx"},
    }


def test_timed_out_host_counts_as_not_scanned():
    host = parse_xml(FIXTURE.read_text())[1]
    assert host.ip == "192.168.30.12"
    assert not host.up
