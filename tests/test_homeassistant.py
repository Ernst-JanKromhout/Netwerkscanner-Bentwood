from scanner.homeassistant import supervisor_token


def test_token_from_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("SUPERVISOR_TOKEN", "uit-env")
    assert supervisor_token(tmp_path) == "uit-env"


def test_token_from_s6_environment_file(monkeypatch, tmp_path):
    monkeypatch.delenv("SUPERVISOR_TOKEN", raising=False)
    (tmp_path / "SUPERVISOR_TOKEN").write_text("uit-bestand\n")
    assert supervisor_token(tmp_path) == "uit-bestand"


def test_missing_token_is_empty(monkeypatch, tmp_path):
    monkeypatch.delenv("SUPERVISOR_TOKEN", raising=False)
    assert supervisor_token(tmp_path) == ""
