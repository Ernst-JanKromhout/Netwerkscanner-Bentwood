"""Draait nmap en leest de XML-uitvoer."""

from __future__ import annotations

import logging
import subprocess
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from .config import normalize_mac

log = logging.getLogger(__name__)


@dataclass
class Host:
    ip: str
    up: bool
    mac: str | None = None
    vendor: str | None = None
    hostname: str | None = None
    ports: dict[tuple[int, str], dict] = field(default_factory=dict)


def parse_xml(xml_text: str) -> list[Host]:
    root = ET.fromstring(xml_text)
    hosts: list[Host] = []
    for el in root.findall("host"):
        status = el.find("status")
        # Een host die tegen --host-timeout aanliep heeft onvolledige poorten: telt als niet gescand.
        up = status is not None and status.get("state") == "up" and el.get("timedout") != "true"
        host = Host(ip="", up=up)
        for addr in el.findall("address"):
            if addr.get("addrtype") == "ipv4":
                host.ip = addr.get("addr", "")
            elif addr.get("addrtype") == "mac":
                host.mac = normalize_mac(addr.get("addr", ""))
                host.vendor = addr.get("vendor")
        name = el.find("hostnames/hostname")
        if name is not None:
            host.hostname = name.get("name")
        for port in el.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            version = None
            if service is not None:
                version = " ".join(v for v in (service.get("product"), service.get("version")) if v) or None
            host.ports[(int(port.get("portid")), port.get("protocol"))] = {
                "service": service.get("name") if service is not None else None,
                "version": version,
            }
        if host.ip:
            hosts.append(host)
    return hosts


def _run(args: list[str], timeout: int) -> tuple[list[Host], float]:
    cmd = ["nmap", "-oX", "-", *args]
    log.debug("Start: %s", " ".join(cmd))
    started = time.monotonic()
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    duration = time.monotonic() - started
    if result.returncode != 0:
        raise RuntimeError(f"nmap faalde ({result.returncode}): {result.stderr.strip()[:300]}")
    return parse_xml(result.stdout), duration


def ping_sweep(subnets: list[str]) -> list[Host]:
    hosts, _ = _run(["-sn", "-n", *subnets], timeout=600)
    return [h for h in hosts if h.up]


def port_scan(ip: str, kind: str, top_ports: int) -> tuple[Host | None, float]:
    """kind 'top': top-N TCP-poorten met versies. kind 'full': alle TCP-poorten plus top 100 UDP.

    Geen -Pn: een apparaat dat niet reageert telt als 'down', zodat een uitgeschakeld
    apparaat niet ineens als 'alle poorten dicht' wordt gemeld.
    """
    if kind != "full":
        hosts, duration = _run(["-sS", "-sV", "--version-light", "--top-ports", str(top_ports), "-T4",
                                  "--host-timeout", "20m", ip], 1800)
        return (hosts[0] if hosts else None), duration

    tcp_hosts, tcp_s = _run(["-sS", "-sV", "--version-light", "-p-", "-T4", "--host-timeout", "45m", ip], 3600)
    if not tcp_hosts or not tcp_hosts[0].up:
        return (tcp_hosts[0] if tcp_hosts else None), tcp_s
    udp_hosts, udp_s = _run(["-sU", "--top-ports", "100", "-T4", "--max-retries", "2",
                              "--host-timeout", "20m", ip], 1800)
    host = tcp_hosts[0]
    if not udp_hosts or not udp_hosts[0].up:
        # Zonder volledige UDP-uitslag geen halve vergelijking: dan telt de hele scan niet.
        host.up = False
        return host, tcp_s + udp_s
    host.ports.update(udp_hosts[0].ports)
    return host, tcp_s + udp_s
