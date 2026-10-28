import json
from pathlib import Path

import scanner
from scanner.__main__ import migrate_to_mqtt
from scanner.db import Database
from scanner.homeassistant import HomeAssistant
from scanner.mqtt import MqttSensors, discovery, name_from
from scanner.overview import SENSOR_IDS

ATTRS = {"friendly_name": "Netwerk: apparaten online", "unit_of_measurement": "apparaten",
         "icon": "mdi:lan", "bekend_totaal": 74}


class FakeClient:
    def __init__(self):
        self.messages = []

    def publish(self, topic, payload, qos=0, retain=False):
        self.messages.append((topic, payload, qos, retain))


def test_discovery_keeps_entity_id_and_moves_meta_out_of_attributes():
    topic, config = discovery("sensor.netwerkscanner_apparaten_online", ATTRS, "0.1.11")
    assert topic == "homeassistant/sensor/netwerkscanner_apparaten_online/config"
    assert config["default_entity_id"] == "sensor.netwerkscanner_apparaten_online"
    assert config["unique_id"] == "netwerkscanner_apparaten_online"
    assert config["name"] == "Apparaten online"
    assert config["unit_of_measurement"] == "apparaten" and config["state_class"] == "measurement"
    assert config["device"]["name"] == "Netwerkscanner" and config["device"]["sw_version"] == "0.1.11"
    _, text = discovery("sensor.netwerkscanner_laatste_wijzigingen",
                        {"friendly_name": "Netwerk: laatste wijzigingen"}, "0.1.11")
    assert "unit_of_measurement" not in text and "state_class" not in text


def test_set_sensor_announces_once_and_retains_everything():
    client = FakeClient()
    sensors = MqttSensors(client, "0.1.11")
    sensors.set_sensor("sensor.netwerkscanner_apparaten_online", 12, ATTRS)
    sensors.set_sensor("sensor.netwerkscanner_apparaten_online", 13, ATTRS)
    topics = [m[0] for m in client.messages]
    assert topics.count("homeassistant/sensor/netwerkscanner_apparaten_online/config") == 1
    assert all(m[3] for m in client.messages), "alles retained, zodat HA het na een herstart meteen heeft"
    state = [m for m in client.messages if m[0] == "netwerkscanner/apparaten_online/state"]
    assert [m[1] for m in state] == ["12", "13"]
    attrs = json.loads(next(m[1] for m in client.messages if m[0].endswith("/attributes")))
    assert attrs == {"bekend_totaal": 74}

    sensors.forget_announcements()  # nieuwe verbinding: config opnieuw sturen
    sensors.set_sensor("sensor.netwerkscanner_apparaten_online", 14, ATTRS)
    assert [m[0] for m in client.messages].count("homeassistant/sensor/netwerkscanner_apparaten_online/config") == 2


def test_name_from_friendly_name():
    assert name_from("Netwerk: aanvallen en mislukte logins vandaag", "sensor.x") == \
        "Aanvallen en mislukte logins vandaag"
    assert name_from(None, "sensor.netwerkscanner_te_beoordelen") == "Te beoordelen"


class RecordingHA(HomeAssistant):
    def __init__(self):
        super().__init__(base_url="http://ha", token="t")
        self.deleted = []

    def delete_state(self, entity_id):
        self.deleted.append(entity_id)


def test_migration_removes_rest_states_once(tmp_path):
    db = Database(tmp_path / "t.db")
    ha = RecordingHA()
    db.set_meta("sensor_transport", "rest")
    migrate_to_mqtt(db, ha)
    assert ha.deleted == list(SENSOR_IDS)
    migrate_to_mqtt(db, ha)
    assert len(ha.deleted) == len(SENSOR_IDS), "tweede keer niets meer weghalen"


def test_set_sensor_goes_to_mqtt_when_connected():
    ha = HomeAssistant(base_url="http://ha", token="t")
    client = FakeClient()
    ha.sensors = MqttSensors(client, "0.1.11")
    ha.session.post = lambda *a, **kw: (_ for _ in ()).throw(AssertionError("geen REST meer"))
    ha.set_sensor("sensor.netwerkscanner_te_beoordelen", 0, {"friendly_name": "Netwerk: te beoordelen"})
    assert any(m[0] == "netwerkscanner/te_beoordelen/state" for m in client.messages)


def test_version_matches_add_on_config():
    config = Path(__file__).parents[1] / "netwerkscanner" / "config.yaml"
    assert f'version: "{scanner.__version__}"' in config.read_text()
