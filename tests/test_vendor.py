from pathlib import Path

from scanner.vendor import PrefixTable, describe_vendor, hostname_hint, identify

TABLE = PrefixTable(Path(__file__).parent / "fixtures" / "mac-prefixes")


def test_known_vendor_from_prefix():
    info = identify("b8:27:eb:12:34:56", None, TABLE)
    assert (info.vendor, info.status, info.suspicious) == ("Raspberry Pi Foundation", "bekend", False)


def test_private_prefix_is_hidden_and_suspicious():
    info = identify("24:fd:fa:10:d2:db", None, TABLE)
    assert (info.vendor, info.status, info.suspicious) == (None, "verborgen", True)


def test_unifi_private_does_not_count_as_vendor():
    assert identify("24:fd:fa:10:d2:db", "Private", TABLE).status == "verborgen"


def test_unifi_vendor_wins():
    assert identify("24:fd:fa:10:d2:db", "Acme", TABLE).vendor == "Acme"


def test_unregistered_prefix_is_unknown():
    assert identify("00:00:5c:00:00:01", None, TABLE).status == "onbekend"


def test_random_mac_is_not_flagged():
    info = identify("da:a1:19:00:00:05", None, TABLE)
    assert info.status == "willekeurig" and not info.suspicious


def test_longest_prefix_wins_for_small_blocks():
    assert identify("70:b3:d5:f2:c0:01", None, TABLE).vendor == "Kleine Fabrikant BV"
    assert identify("70:b3:d5:01:00:01", None, TABLE).status == "verborgen"


def test_missing_list_does_not_raise_false_alarm(tmp_path):
    info = identify("24:fd:fa:10:d2:db", None, PrefixTable(tmp_path / "bestaat-niet"))
    assert info.status == "geen lijst" and not info.suspicious


def test_hostname_hints():
    assert "NXP i.MX" in hostname_hint("imx8mm-ferrari")
    assert "ESP" in hostname_hint("esp32-keuken")
    assert hostname_hint("macbook-ernst-jan") is None


def test_describe_vendor_for_tonights_device():
    lines = describe_vendor("24:fd:fa:10:d2:db", identify("24:fd:fa:10:d2:db", None, TABLE), "imx8mm-ferrari")
    assert lines[0].startswith("⚠️ Fabrikant verborgen: prefix 24:FD:FA")
    assert "NXP i.MX" in lines[1]
