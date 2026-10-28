"""Sensoren via MQTT-discovery: echte entiteiten met een vaste unique_id.

Sensoren die via de REST-API (POST /api/states) gezet worden, verdwijnen bij elke herstart van Home Assistant
tot de volgende ronde, staan niet in het entiteitenregister en zijn niet te hernoemen of aan een ruimte te koppelen.
Via MQTT-discovery staan ze in het register, horen ze bij één apparaat 'Netwerkscanner' en houdt de broker de
laatste waarde vast (retain), zodat HA ze na een herstart meteen weer heeft.
"""

from __future__ import annotations

import json
import logging
import threading

import requests

from .homeassistant import supervisor_token

log = logging.getLogger(__name__)

DISCOVERY_PREFIX = "homeassistant"
BASE_TOPIC = "netwerkscanner"
STATUS_TOPIC = f"{BASE_TOPIC}/status"
ENTITY_PREFIX = "sensor.netwerkscanner_"
DEVICE = {
    "identifiers": ["netwerkscanner_bentwood"],
    "name": "Netwerkscanner",
    "manufacturer": "Netwerkscanner-Bentwood",
    "model": "Home Assistant-app",
}
ORIGIN_URL = "https://github.com/Ernst-JanKromhout/Netwerkscanner-Bentwood"
# Deze attributen beschrijven de sensor zelf; ze gaan in de discovery-config, niet bij de attributen.
META_KEYS = ("friendly_name", "icon", "unit_of_measurement")


def broker_settings(base_url: str = "http://supervisor", token: str | None = None) -> dict | None:
    """Gegevens van de MQTT-broker (de Mosquitto-app) uit de Supervisor, of None als er geen is."""
    try:
        resp = requests.get(f"{base_url}/services/mqtt",
                            headers={"Authorization": f"Bearer {token or supervisor_token()}"}, timeout=10)
        if resp.status_code != 200:
            log.info("Geen MQTT-broker beschikbaar (Supervisor gaf HTTP %s)", resp.status_code)
            return None
        data = resp.json().get("data") or {}
    except (requests.RequestException, ValueError) as exc:
        log.info("Geen MQTT-broker beschikbaar: %s", exc)
        return None
    return data if data.get("host") else None


def object_id(entity_id: str) -> str:
    return entity_id.split(".", 1)[1]


def topic_base(entity_id: str) -> str:
    """netwerkscanner/apparaten_online voor sensor.netwerkscanner_apparaten_online."""
    return f"{BASE_TOPIC}/{object_id(entity_id).removeprefix('netwerkscanner_')}"


def name_from(friendly_name: str | None, entity_id: str) -> str:
    """'Netwerk: apparaten online' wordt 'Apparaten online'; HA zet de apparaatnaam er zelf voor."""
    name = (friendly_name or object_id(entity_id).replace("netwerkscanner_", "").replace("_", " ")).strip()
    if name.lower().startswith("netwerk:"):
        name = name.split(":", 1)[1].strip()
    return name[:1].upper() + name[1:]


def split_attributes(attributes: dict) -> tuple[dict, dict]:
    meta = {k: v for k, v in attributes.items() if k in META_KEYS}
    extra = {k: v for k, v in attributes.items() if k not in META_KEYS}
    return meta, extra


def discovery(entity_id: str, meta: dict, version: str) -> tuple[str, dict]:
    """(topic, config) voor MQTT-discovery van één sensor."""
    oid = object_id(entity_id)
    base = topic_base(entity_id)
    config = {
        "name": name_from(meta.get("friendly_name"), entity_id),
        "unique_id": oid,
        "default_entity_id": entity_id,  # zelfde entity_id als voorheen, dus dashboards blijven werken
        "state_topic": f"{base}/state",
        "json_attributes_topic": f"{base}/attributes",
        "availability_topic": STATUS_TOPIC,
        "device": {**DEVICE, "sw_version": version},
        "origin": {"name": "Netwerkscanner", "sw_version": version, "support_url": ORIGIN_URL},
    }
    if meta.get("icon"):
        config["icon"] = meta["icon"]
    if meta.get("unit_of_measurement"):
        config["unit_of_measurement"] = meta["unit_of_measurement"]
        config["state_class"] = "measurement"
    return f"{DISCOVERY_PREFIX}/sensor/{oid}/config", config


class MqttSensors:
    """Publiceert sensoren. `client` is een verbonden paho-client (of iets met dezelfde publish)."""

    def __init__(self, client, version: str):
        self.client = client
        self.version = version
        self._lock = threading.Lock()
        self._announced: set[str] = set()

    def forget_announcements(self) -> None:
        """Na een nieuwe verbinding de configs opnieuw sturen, voor het geval de broker ze kwijt is."""
        with self._lock:
            self._announced.clear()

    def set_sensor(self, entity_id: str, state, attributes: dict) -> None:
        meta, extra = split_attributes(attributes)
        with self._lock:
            if entity_id not in self._announced:
                topic, config = discovery(entity_id, meta, self.version)
                self.client.publish(topic, json.dumps(config), qos=1, retain=True)
                self._announced.add(entity_id)
        base = topic_base(entity_id)
        self.client.publish(f"{base}/attributes", json.dumps(extra, ensure_ascii=False), qos=1, retain=True)
        self.client.publish(f"{base}/state", str(state), qos=1, retain=True)

    @classmethod
    def connect(cls, settings: dict, version: str, timeout: float = 15) -> "MqttSensors | None":
        """Verbindt met de broker; None als dat niet lukt binnen `timeout` seconden."""
        try:
            import paho.mqtt.client as paho  # alleen in de add-on nodig
        except ImportError:
            log.warning("paho-mqtt ontbreekt: sensoren via de REST-API")
            return None

        # paho 2.x wil weten welke versie van de callbacks we gebruiken; 1.x kent dat niet.
        if hasattr(paho, "CallbackAPIVersion"):
            client = paho.Client(paho.CallbackAPIVersion.VERSION1, client_id="netwerkscanner")
        else:
            client = paho.Client(client_id="netwerkscanner")
        if settings.get("username"):
            client.username_pw_set(settings["username"], settings.get("password"))
        if settings.get("ssl"):
            client.tls_set()
        client.will_set(STATUS_TOPIC, "offline", qos=1, retain=True)

        sensors = cls(client, version)
        connected = threading.Event()

        def on_connect(c, userdata, flags, rc, *args):
            if rc != 0:
                log.warning("MQTT-broker weigert de verbinding (code %s)", rc)
                return
            sensors.forget_announcements()
            c.publish(STATUS_TOPIC, "online", qos=1, retain=True)
            if connected.is_set():
                log.info("Weer verbonden met de MQTT-broker")
            connected.set()

        def on_disconnect(c, userdata, rc, *args):
            if rc != 0:
                log.warning("Verbinding met de MQTT-broker verbroken (code %s), paho verbindt opnieuw", rc)

        client.on_connect = on_connect
        client.on_disconnect = on_disconnect
        try:
            client.connect(settings["host"], int(settings.get("port") or 1883), keepalive=60)
        except (OSError, ValueError) as exc:
            log.warning("MQTT-broker %s niet bereikbaar: %s", settings.get("host"), exc)
            return None
        client.loop_start()
        if not connected.wait(timeout):
            log.warning("Geen antwoord van de MQTT-broker binnen %.0f s", timeout)
            client.loop_stop()
            client.disconnect()
            return None
        log.info("Sensoren via MQTT op %s:%s", settings["host"], settings.get("port") or 1883)
        return sensors
