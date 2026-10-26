"""Korte Nederlandse uitleg bij bekende poorten, zodat je ziet waar een open poort voor dient."""

from __future__ import annotations

PORT_INFO: dict[int, str] = {
    21: "FTP, bestanden overzetten zonder versleuteling",
    22: "SSH, beheer op afstand via de opdrachtregel",
    23: "Telnet, onversleuteld beheer op afstand (liever uit)",
    5900: "VNC, scherm overnemen op afstand",
    25: "SMTP, mail versturen",
    53: "DNS, zet namen om naar IP-adressen",
    80: "Webpagina zonder versleuteling (HTTP)",
    111: "RPC-portmapper, hoort bij NFS (gedeelde mappen)",
    123: "NTP, tijd synchroniseren",
    139: "Windows-bestandsdeling (oud NetBIOS)",
    161: "SNMP, apparaatstatus uitlezen",
    443: "Beveiligde webpagina (HTTPS)",
    445: "Windows-bestandsdeling (SMB)",
    548: "AFP, Apple-bestandsdeling",
    554: "RTSP, videostream van camera of mediaspeler",
    631: "Printen via het netwerk (IPP)",
    873: "Rsync, back-ups en mappen synchroniseren",
    1443: "Beheerpoort, vaak een webinterface of app-koppeling",
    1883: "MQTT, berichten tussen slimme apparaten",
    1935: "RTMP, live videostream",
    1984: "Webinterface, vaak go2rtc (camerastreams)",
    2049: "NFS, gedeelde mappen voor Linux en NAS",
    3000: "Webinterface van een app of dienst",
    3389: "Extern bureaublad van Windows (liever niet open)",
    3689: "DAAP, muziek delen (iTunes/AirPlay)",
    4045: "NFS-vergrendeling, hoort bij gedeelde mappen",
    5000: "Webinterface, bij een Synology het beheerscherm (HTTP)",
    5001: "Webinterface, bij een Synology het beheerscherm (HTTPS)",
    5080: "Webinterface van een app of dienst",
    5353: "mDNS, apparaten vinden elkaar in het netwerk",
    5357: "Windows-apparaatdetectie (WSD)",
    6668: "Tuya, slimme stekkers en lampen",
    6789: "UniFi, snelheidstest van de controller",
    7000: "AirPlay, streamen vanaf Apple-apparaten",
    8000: "Webinterface van een app of dienst",
    8008: "Chromecast/Google Cast",
    8009: "Chromecast/Google Cast, besturing",
    8080: "Webinterface, vaak een beheer- of proxy-pagina",
    8123: "Home Assistant",
    8181: "Webinterface van een app of dienst",
    8443: "Beveiligde webinterface, vaak UniFi-beheer",
    8800: "Webinterface van een app of dienst",
    8883: "MQTT versleuteld, berichten tussen slimme apparaten",
    9000: "Webinterface of beheerdienst",
    9900: "Webinterface van een app of dienst",
    10001: "UniFi, apparaten vinden elkaar",
    49160: "Dynamische poort, vaak UPnP of een app",
    50001: "Dynamische poort, vaak UPnP of een app",
    50002: "Dynamische poort, vaak UPnP of een app",
}

SERVICE_INFO: dict[str, str] = {
    "http": "Webinterface (HTTP)",
    "https": "Beveiligde webinterface (HTTPS)",
    "ssh": "SSH, beheer op afstand",
    "rtsp": "Videostream",
    "upnp": "UPnP, apparaten regelen zelf poorten en vinden elkaar",
}


# Hoog: diensten die je nooit open wilt hebben voor iets dat je niet vertrouwt, vaak zonder versleuteling
# of met een lange geschiedenis van lekken. Let op: beheer of onversleuteld verkeer, prima als je het zelf gebruikt.
HIGH = {21, 23, 111, 139, 161, 445, 873, 2049, 3389, 4045, 5900}
WATCH = {22, 80, 554, 548, 1443, 1883, 1935, 1984, 3000, 5000, 5080, 6668, 8000, 8080, 8181, 8800, 9000, 9900,
         49160, 50001, 50002}

RISK_LABELS = {"hoog": "🔴", "let op": "🟠", "normaal": "🟢"}


def risk(port: int) -> str:
    """'hoog', 'let op' of 'normaal'. Een onbekende poort is 'let op': je weet niet wat er draait."""
    if port in HIGH:
        return "hoog"
    if port in WATCH or port not in PORT_INFO:
        return "let op"
    return "normaal"


def explain(port: int, service: str | None = None) -> str:
    if port in PORT_INFO:
        return PORT_INFO[port]
    if service and service in SERVICE_INFO:
        return SERVICE_INFO[service]
    return "Onbekende dienst, zoek het apparaat erbij op"
