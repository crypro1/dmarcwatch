"""config.py - Atomarität der Zustandsdateien-Schreibvorgänge, is_own_domain-
Normalisierung und die Fehlertoleranz der Reader-Funktionen. Dateirechte
selbst sind bereits in test_permissions.py abgedeckt.
"""
import json

import pytest

from dmarcwatch.config import (
    Config,
    read_last_fetch_date,
    write_config,
    write_default_config_if_missing,
)


def _config(**overrides) -> Config:
    return Config.from_dict({"own_domains": ["example.com"], **overrides})


# --- is_own_domain() ---


def test_is_own_domain_case_and_trailing_dot_insensitive():
    config = _config(own_domains=["Example.com"])
    assert config.is_own_domain("example.com") is True
    assert config.is_own_domain("EXAMPLE.COM.") is True
    assert config.is_own_domain("other.example") is False


def test_is_own_domain_blank_entries_do_not_match_empty_input():
    """Eine versehentliche Leerzeile in own_domains darf keinen leeren
    Domain-String als "eigen" durchgehen lassen."""
    config = _config(own_domains=["example.com", "", "   "])
    assert config.is_own_domain("") is False
    assert config.is_own_domain("example.com") is True


def test_is_own_domain_result_is_consistent_across_repeated_calls():
    """Regression: is_own_domain baute früher bei jedem Aufruf ein neues
    Set - reiner Konsistenz-/Wartungscheck, kein beobachtbarer
    Verhaltensunterschied, aber ein wiederholter Aufruf muss dasselbe
    Ergebnis liefern wie der erste."""
    config = _config(own_domains=["example.com"])
    results = [config.is_own_domain("example.com") for _ in range(5)]
    assert all(results)


# --- Atomare Schreibvorgänge ---


def test_write_config_leaves_no_temp_file_behind_on_success(tmp_path):
    path = tmp_path / "config.json"
    write_config({"own_domains": ["example.com"]}, path)
    remaining = list(tmp_path.iterdir())
    assert remaining == [path]


def test_write_config_failure_does_not_corrupt_existing_file(tmp_path, monkeypatch):
    """Kernregression: ein Absturz mitten im Schreiben darf die bereits
    vorhandene, gültige config.json nicht antasten - load_config() würde
    sonst beim nächsten Start mit einem ungefangenen JSONDecodeError
    sterben (die App bliebe tot bis zum manuellen Eingriff). Simuliert
    über einen fehlschlagenden os.replace() (z. B. Platte voll beim
    finalen Rename) - der Schreibversuch in die .tmp-Datei ist zu diesem
    Zeitpunkt zwar schon passiert, aber die eigentliche Zieldatei wurde
    noch nicht ersetzt."""
    import dmarcwatch.config as config_module

    path = tmp_path / "config.json"
    write_config({"own_domains": ["good.example"]}, path)
    original_content = path.read_text(encoding="utf-8")

    def failing_replace(*args, **kwargs):
        raise OSError("simulated disk full during rename")

    monkeypatch.setattr(config_module.os, "replace", failing_replace)
    with pytest.raises(OSError):
        write_config({"own_domains": ["bad.example"]}, path)

    assert path.read_text(encoding="utf-8") == original_content
    assert json.loads(path.read_text(encoding="utf-8"))["own_domains"] == ["good.example"]


def test_write_default_config_if_missing_is_valid_json(tmp_path):
    path = write_default_config_if_missing(tmp_path / "config.json")
    # Muss lesbar sein, nicht leer/halb geschrieben.
    with open(path, encoding="utf-8") as f:
        json.load(f)


# --- read_last_fetch_date() Fehlertoleranz ---


def test_read_last_fetch_date_survives_corrupted_binary_marker(tmp_path):
    """UnicodeDecodeError erbt von ValueError - read_skipped_items und
    read_dns_check_result fangen (OSError, ValueError) ab,
    read_last_fetch_date fing früher nur OSError, eine binär-kaputte
    Markerdatei (z. B. durch einen abgebrochenen Schreibvorgang) hätte den
    fetch-Start mit einer ungefangenen Exception abstürzen lassen."""
    path = tmp_path / "last_fetch_success"
    path.write_bytes(b"\xff\xfe\x00garbage\x80\x81")
    assert read_last_fetch_date(path) is None


def test_read_last_fetch_date_missing_file_returns_none(tmp_path):
    assert read_last_fetch_date(tmp_path / "does_not_exist") is None
