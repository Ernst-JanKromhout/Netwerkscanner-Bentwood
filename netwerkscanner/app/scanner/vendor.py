"""Wie maakte dit apparaat? Fabrikant via het MAC-prefix, plus hints uit de hostnaam.

De prefixlijst komt uit het nmap-pakket dat al in de app zit (nmap-mac-prefixes), dus er is geen
internet nodig. Fabrikanten kunnen hun prefix anoniem registreren; die staan erin als 'Private'.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path

from .diff import is_random_mac

log = logging.getLogger(__name__)

PREFIX_FILES = (
    os.environ.get("NETWERKSCANNER_MAC_PREFIXES", ""),
    "/usr/share/nmap/nmap-mac-prefixes",
    "/usr/local/share/nmap/nmap-mac-prefixes",
)

# Zo staan anonieme registraties in de lijst, en zo geeft UniFi ze soms door.
HIDDEN = {"private", "ieee registration authority"}

# Standaardnamen uit bouwsets en chips. Een apparaat met zo'n naam heeft de fabrikant niet eens hernoemd.
HOSTNAME_HINTS: tuple[tuple[str, str], ...] = (
    (r"imx[6-9]", "NXP i.MX-chip met embedded Linux: vaak industriële, energie- of audio-apparatuur"),
    (r"rk3[0-9]{3}|rockchip", "Rockchip-chip: vaak een mediaspeler, tablet of goedkope camera"),
    (r"^esp[-_]|esp32|esp8266|espressif", "ESP-chip: een klein slim apparaat (stekker, sensor, ESPHome)"),
    (r"tasmota", "Tasmota-firmware: een slimme stekker of schakelaar"),
    (r"shelly", "Shelly: slimme schakelaar of meter"),
    (r"raspberrypi|^rpi", "Raspberry Pi"),
    (r"^android[-_]", "Android-apparaat: telefoon, tablet of tv-box"),
    (r"^(localhost|buildroot|yocto|poky|openwrt)$", "standaardnaam van een bouwset, de fabrikant heeft niets ingevuld"),
)


@dataclass(frozen=True)
class VendorInfo:
    vendor: str | None  # leesbare fabrikant, None als die niet bekend is
    status: str  # 'bekend', 'verborgen', 'onbekend', 'willekeurig' of 'geen lijst'

    @property
    def suspicious(self) -> bool:
        return self.status in ("verborgen", "onbekend")


class PrefixTable:
    def __init__(self, path: str | Path | None = None):
        self._path = path
        self._table: dict[str, str] | None = None

    def _load(self) -> dict[str, str]:
        if self._table is not None:
            return self._table
        paths = [self._path] if self._path else [p for p in PREFIX_FILES if p]
        table: dict[str, str] = {}
        for p in paths:
            try:
                with open(p, encoding="utf-8", errors="replace") as f:
                    for line in f:
                        if not line.strip() or line.startswith("#"):
                            continue
                        prefix, _, name = line.strip().partition(" ")
                        if name:
                            table[prefix.upper()] = name.strip()
                break
            except OSError:
                continue
        if not table:
            log.warning("Geen lijst met MAC-prefixen gevonden, fabrikanten worden niet opgezocht")
        self._table = table
        return table

    def lookup(self, mac: str) -> str | None:
        """Fabrikant voor dit MAC-adres, langste prefix eerst (ook de kleinere MA-M- en MA-S-blokken)."""
        table = self._load()
        hexmac = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
        for length in (9, 7, 6):
            name = table.get(hexmac[:length])
            if name:
                return name
        return None

    @property
    def available(self) -> bool:
        return bool(self._load())


_default = PrefixTable()


def identify(mac: str, known_vendor: str | None = None, table: PrefixTable | None = None) -> VendorInfo:
    """Fabrikant en hoe betrouwbaar die is. Een fabrikant van UniFi gaat voor, tenzij die ook verborgen is."""
    table = table or _default
    if is_random_mac(mac):
        return VendorInfo(None, "willekeurig")
    for name in (known_vendor, table.lookup(mac)):
        if name and name.strip().lower() not in HIDDEN:
            return VendorInfo(name.strip(), "bekend")
    if (known_vendor and known_vendor.strip().lower() in HIDDEN) or table.lookup(mac):
        return VendorInfo(None, "verborgen")
    if not table.available:
        return VendorInfo(None, "geen lijst")
    return VendorInfo(None, "onbekend")


def prefix(mac: str) -> str:
    return mac.upper()[:8]


def hostname_hint(hostname: str | None) -> str | None:
    if not hostname:
        return None
    name = hostname.lower()
    for pattern, hint in HOSTNAME_HINTS:
        if re.search(pattern, name):
            return hint
    return None


def describe_vendor(mac: str, info: VendorInfo, hostname: str | None = None) -> list[str]:
    """Regels voor een melding: fabrikant of waarschuwing, plus wat de hostnaam verraadt."""
    lines: list[str] = []
    if info.status == "bekend":
        lines.append(f"Fabrikant: {info.vendor}")
    elif info.status == "verborgen":
        lines.append(f"⚠️ Fabrikant verborgen: prefix {prefix(mac)} is anoniem geregistreerd.")
    elif info.status == "onbekend":
        lines.append(f"⚠️ Fabrikant onbekend: prefix {prefix(mac)} staat in geen enkele lijst.")
    hint = hostname_hint(hostname)
    if hint:
        lines.append(f"Hostnaam wijst op: {hint}.")
    return lines
