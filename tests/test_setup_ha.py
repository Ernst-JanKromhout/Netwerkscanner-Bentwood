from scanner import setup_ha
from scanner.review import SELECT_ENTITY


class FakeHA:
    def __init__(self, existing=()):
        self.existing = set(existing)
        self.scripts = {}

    def state(self, entity_id):
        return {"state": "on"} if entity_id in self.existing else None

    def save_script(self, script_id, config):
        self.scripts[script_id] = config
        return True


class FakeWS:
    def __init__(self, dashboards=()):
        self.dashboards = [{"url_path": d} for d in dashboards]
        self.calls = []
        self.closed = False

    def call(self, type_, **data):
        self.calls.append((type_, data))
        return self.dashboards if type_ == "lovelace/dashboards/list" else None

    def close(self):
        self.closed = True


def test_creates_everything_when_missing():
    ha, ws = FakeHA(), FakeWS()
    created = setup_ha.ensure(ha, "/dashboard-netwerk/overzicht", lambda: ws)
    assert set(ha.scripts) == set(setup_ha.SCRIPTS)
    types = [t for t, _ in ws.calls]
    assert types == ["input_select/create", "lovelace/dashboards/list",
                     "lovelace/dashboards/create", "lovelace/config/save"]
    assert ws.calls[2][1]["url_path"] == "dashboard-netwerk"
    assert ws.calls[3][1]["config"]["views"][0]["path"] == "overzicht"
    assert "dashboard /dashboard-netwerk/overzicht" in created
    assert ws.closed


def test_leaves_existing_alone():
    existing = [SELECT_ENTITY] + [f"script.{s}" for s in setup_ha.SCRIPTS]
    ha, ws = FakeHA(existing), FakeWS(["dashboard-netwerk"])
    assert setup_ha.ensure(ha, "/dashboard-netwerk/overzicht", lambda: ws) == []
    assert ha.scripts == {}
    assert [t for t, _ in ws.calls] == ["lovelace/dashboards/list"]


def test_dashboard_path_without_hyphen_is_skipped():
    existing = [SELECT_ENTITY] + [f"script.{s}" for s in setup_ha.SCRIPTS]
    ws = FakeWS()
    assert setup_ha.ensure(FakeHA(existing), "/netwerk", lambda: ws) == []
    assert ws.calls == []


def test_split_path():
    assert setup_ha.split_path("/dashboard-netwerk/overzicht") == ("dashboard-netwerk", "overzicht")
    assert setup_ha.split_path("/dashboard-netwerk") == ("dashboard-netwerk", "overzicht")
