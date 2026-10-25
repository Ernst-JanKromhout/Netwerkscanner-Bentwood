"""Pure vergelijkingen: wat is er veranderd tussen twee waarnemingen of twee scans."""

from __future__ import annotations

from dataclasses import dataclass

PortKey = tuple[int, str]
PortMap = dict[PortKey, dict]


@dataclass(frozen=True)
class Change:
    type: str
    detail: dict


def diff_ports(previous: PortMap, current: PortMap) -> list[Change]:
    changes: list[Change] = []
    for key in sorted(current.keys() - previous.keys()):
        changes.append(Change("port_opened", _port_detail(key, current[key])))
    for key in sorted(previous.keys() - current.keys()):
        changes.append(Change("port_closed", _port_detail(key, previous[key])))
    for key in sorted(previous.keys() & current.keys()):
        old, new = previous[key], current[key]
        if (old.get("service"), old.get("version")) != (new.get("service"), new.get("version")):
            detail = _port_detail(key, new)
            detail["old_service"] = old.get("service")
            detail["old_version"] = old.get("version")
            changes.append(Change("service_changed", detail))
    return changes


def _port_detail(key: PortKey, info: dict) -> dict:
    port, proto = key
    return {"port": port, "proto": proto, "service": info.get("service"), "version": info.get("version")}


def diff_identity(old_ip: str | None, old_hostname: str | None,
                  new_ip: str | None, new_hostname: str | None) -> list[Change]:
    """IP- en naamwissels. Een ontbrekende nieuwe waarde is geen wissel."""
    changes: list[Change] = []
    if new_ip and old_ip and new_ip != old_ip:
        changes.append(Change("ip_changed", {"old": old_ip, "new": new_ip}))
    if new_hostname and old_hostname and new_hostname != old_hostname:
        changes.append(Change("hostname_changed", {"old": old_hostname, "new": new_hostname}))
    return changes


def is_random_mac(mac: str) -> bool:
    """Lokaal beheerd MAC-adres (bit 2 van het eerste octet), meestal een privé-wifiadres."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except ValueError:
        return False
