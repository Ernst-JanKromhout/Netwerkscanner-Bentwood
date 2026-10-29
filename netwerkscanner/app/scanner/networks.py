"""Welke netwerken horen bij jou, en welke IP-adressen vallen daarbuiten.

Een IP uit een privé-reeks die in geen van je eigen netwerken past, betekent meestal dat er iets
een eigen netwerk opzet: een extra router of extender, een apparaat met een eigen hotspot, een VPN,
of een apparaat met een verkeerd ingesteld vast IP. Precies wat je wilt weten.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

IPv4Network = ipaddress.IPv4Network

# Alleen deze reeksen tellen: publieke adressen zijn internet, link-local (169.254) is een apparaat zonder DHCP.
PRIVATE = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10")]


@dataclass(frozen=True)
class KnownNetwork:
    network: IPv4Network
    name: str  # bijvoorbeeld 'Default (UniFi)' of 'internetkant van de gateway'


def parse_network(value: str) -> IPv4Network | None:
    """'192.168.1.1/24' (zoals UniFi het geeft) of '192.168.1.0/24'; None als het geen IPv4-netwerk is."""
    try:
        net = ipaddress.ip_network(str(value).strip(), strict=False)
    except ValueError:
        return None
    return net if isinstance(net, IPv4Network) else None


def unifi_networks(networkconf: list[dict]) -> list[KnownNetwork]:
    """Netwerken uit rest/networkconf van UniFi: LAN's, VLAN's en VPN's met een eigen subnet."""
    result = []
    for raw in networkconf:
        net = parse_network(raw.get("ip_subnet") or "")
        if net is not None:
            result.append(KnownNetwork(net, f"{raw.get('name') or 'netwerk'} (UniFi)"))
    return result


def wan_networks(devices: list[dict]) -> list[KnownNetwork]:
    """De internetkant van de gateway, zoals het netwerk van een modem ervoor (dubbele NAT)."""
    result = []
    for raw in devices:
        for key in ("wan1", "wan2"):
            wan = raw.get(key)
            if not isinstance(wan, dict) or not wan.get("ip") or not wan.get("netmask"):
                continue
            net = parse_network(f"{wan['ip']}/{wan['netmask']}")
            if net is not None and is_private(wan["ip"]):
                result.append(KnownNetwork(net, f"internetkant van {raw.get('name') or 'de gateway'} ({key})"))
    return result


def configured_networks(subnets: list[str], known_subnets: list[str]) -> list[KnownNetwork]:
    result = []
    for value, name in [*((s, "scanner-subnet") for s in subnets), *((s, "zelf goedgekeurd") for s in known_subnets)]:
        net = parse_network(value)
        if net is not None:
            result.append(KnownNetwork(net, name))
    return result


def is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return False
    return isinstance(addr, ipaddress.IPv4Address) and any(addr in n for n in PRIVATE)


def strip_port(address: str) -> str:
    """'192.168.4.2:5353' wordt '192.168.4.2' (alleen IPv4 heeft precies één dubbele punt)."""
    return address.rsplit(":", 1)[0] if address.count(":") == 1 else address


def find_known(ip: str, known: list[KnownNetwork]) -> KnownNetwork | None:
    addr = ipaddress.ip_address(ip)
    return next((k for k in known if addr in k.network), None)


def unknown_network(ip: str, known: list[KnownNetwork]) -> IPv4Network | None:
    """Het /24 rond dit IP als het privé is en in geen bekend netwerk valt, anders None."""
    if not is_private(ip) or find_known(ip, known) is not None:
        return None
    return ipaddress.ip_network(f"{ip}/24", strict=False)
