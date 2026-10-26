from scanner import setup_ha


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
    def __init__(self, dashboards=(), config=None):
        self.dashboards = [{"url_path": d} for d in dashboards]
        self.config = config
        self.calls = []
        self.closed = False

    def call(self, type_, **data):
        self.calls.append((type_, data))
        if type_ == "lovelace/dashboards/list":
            return self.dashboards
        return self.config if type_ == "lovelace/config" else None

    def close(self):
        self.closed = True


def test_creates_everything_when_missing(tmp_path):
    ha, ws = FakeHA(), FakeWS()
    created = setup_ha.ensure(ha, "/dashboard-netwerk/overzicht", lambda: ws, tmp_path / "h")
    assert set(ha.scripts) == set(setup_ha.SCRIPTS)
    types = [t for t, _ in ws.calls]
    assert types == ["input_select/create", "input_select/create", "input_text/create", "lovelace/dashboards/list",
                     "lovelace/dashboards/create", "lovelace/config/save"]
    assert ws.calls[4][1]["url_path"] == "dashboard-netwerk"
    assert ws.calls[5][1]["config"]["views"][0]["path"] == "overzicht"
    assert "dashboard /dashboard-netwerk/overzicht" in created
    assert ws.closed


EXISTING = [e for e, _, _ in setup_ha.HELPERS] + [f"script.{s}" for s in setup_ha.SCRIPTS]


def test_leaves_up_to_date_dashboard_alone(tmp_path):
    ha = FakeHA(EXISTING)
    ws = FakeWS(["dashboard-netwerk"], setup_ha.dashboard_config("overzicht"))
    assert setup_ha.ensure(ha, "/dashboard-netwerk/overzicht", lambda: ws, tmp_path / "h") == []
    assert ha.scripts == {}
    assert [t for t, _ in ws.calls] == ["lovelace/dashboards/list", "lovelace/config"]


def test_updates_our_unchanged_dashboard(tmp_path):
    old = {"views": [{"title": "Overzicht", "path": "overzicht", "sections": []}]}
    hash_path = tmp_path / "h"
    hash_path.write_text(setup_ha._hash(old))
    ws = FakeWS(["dashboard-netwerk"], old)
    created = setup_ha.ensure(FakeHA(EXISTING), "/dashboard-netwerk/overzicht", lambda: ws, hash_path)
    assert created == ["nieuwe indeling dashboard /dashboard-netwerk/overzicht"]
    assert ws.calls[-1][0] == "lovelace/config/save"
    assert hash_path.read_text() == setup_ha._hash(setup_ha.dashboard_config("overzicht"))


def test_keeps_dashboard_the_user_edited(tmp_path):
    old = {"views": [{"title": "Overzicht", "path": "overzicht", "sections": []}]}
    hash_path = tmp_path / "h"
    hash_path.write_text(setup_ha._hash(old))
    edited = {"views": [{"title": "Overzicht", "path": "overzicht", "sections": [{"type": "grid"}]}]}
    ws = FakeWS(["dashboard-netwerk"], edited)
    assert setup_ha.ensure(FakeHA(EXISTING), "/dashboard-netwerk/overzicht", lambda: ws, hash_path) == []
    assert "lovelace/config/save" not in [t for t, _ in ws.calls]


def test_legacy_dashboard_without_hash_is_recognised(tmp_path):
    old = {"views": [{"title": "Overzicht", "path": "overzicht", "sections": []}]}
    ws = FakeWS(["dashboard-netwerk"], old)
    created = setup_ha.ensure(FakeHA(EXISTING), "/dashboard-netwerk/overzicht", lambda: ws, tmp_path / "h")
    assert created and (tmp_path / "h").exists()


def test_dashboard_path_without_hyphen_is_skipped(tmp_path):
    ws = FakeWS()
    assert setup_ha.ensure(FakeHA(EXISTING), "/netwerk", lambda: ws, tmp_path / "h") == []
    assert ws.calls == []


def test_split_path():
    assert setup_ha.split_path("/dashboard-netwerk/overzicht") == ("dashboard-netwerk", "overzicht")
    assert setup_ha.split_path("/dashboard-netwerk") == ("dashboard-netwerk", "overzicht")
