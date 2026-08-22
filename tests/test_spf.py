"""SPF-Auflösung (spf.py) für den "Aus SPF ermitteln"-Knopf im Setup-Fenster.

Tests mocken `dig` per subprocess - ein automatisierter Testlauf darf nicht
von echtem DNS abhängen (Flakiness, Offline-Fähigkeit), gleiche Begründung
wie bei test_whois.py fürs Netzwerk. Deckt insbesondere die
RFC-7208-Schutzmechanismen ab: Lookup-Limit und Zyklus-Erkennung gegen
kaputte oder böswillig verschachtelte Records.
"""
import subprocess
from unittest.mock import patch

import pytest

from dmarcwatch.spf import SPFResolutionError, resolve_own_ip_networks, validate_spf


def _dig_result(stdout: str, returncode: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr="")


def _txt(record: str) -> subprocess.CompletedProcess:
    return _dig_result(f'"{record}"\n')


def test_resolves_plain_ip4_and_ip6_mechanisms():
    spf = "v=spf1 ip4:203.0.113.0/24 ip6:2001:db8::/32 ~all"
    with patch("dmarcwatch.spf.subprocess.run", return_value=_txt(spf)):
        result = resolve_own_ip_networks("example.com")
    # set-Vergleich statt exakter Reihenfolge: sorted() sortiert
    # lexikographisch als String, nicht "IPv4 vor IPv6" - die Reihenfolge
    # selbst ist nicht Teil des Vertrags.
    assert set(result) == {"203.0.113.0/24", "2001:db8::/32"}


def test_bare_ip4_without_cidr_becomes_slash_32():
    spf = "v=spf1 ip4:203.0.113.9 ~all"
    with patch("dmarcwatch.spf.subprocess.run", return_value=_txt(spf)):
        result = resolve_own_ip_networks("example.com")
    assert result == ["203.0.113.9/32"]


def test_resolves_include_recursively():
    responses = {
        ("TXT", "example.com"): _txt("v=spf1 include:_spf.provider.example ~all"),
        ("TXT", "_spf.provider.example"): _txt("v=spf1 ip4:198.51.100.0/24 ~all"),
    }

    def fake_run(cmd, **kwargs):
        record_type, name = cmd[-2], cmd[-1]
        return responses[(record_type, name)]

    with patch("dmarcwatch.spf.subprocess.run", side_effect=fake_run):
        result = resolve_own_ip_networks("example.com")
    assert result == ["198.51.100.0/24"]


def test_resolves_redirect():
    responses = {
        ("TXT", "example.com"): _txt("v=spf1 redirect=_spf.other.example"),
        ("TXT", "_spf.other.example"): _txt("v=spf1 ip4:198.51.100.0/24 ~all"),
    }

    def fake_run(cmd, **kwargs):
        record_type, name = cmd[-2], cmd[-1]
        return responses[(record_type, name)]

    with patch("dmarcwatch.spf.subprocess.run", side_effect=fake_run):
        result = resolve_own_ip_networks("example.com")
    assert result == ["198.51.100.0/24"]


def test_resolves_mx_mechanism():
    responses = {
        ("TXT", "example.com"): _txt("v=spf1 mx ~all"),
        ("MX", "example.com"): _dig_result("10 mail.example.com.\n"),
        ("A", "mail.example.com"): _dig_result("203.0.113.5\n"),
        ("AAAA", "mail.example.com"): _dig_result(""),
    }

    def fake_run(cmd, **kwargs):
        record_type, name = cmd[-2], cmd[-1]
        return responses[(record_type, name)]

    with patch("dmarcwatch.spf.subprocess.run", side_effect=fake_run):
        result = resolve_own_ip_networks("example.com")
    assert result == ["203.0.113.5/32"]


def test_multi_segment_txt_record_is_concatenated():
    # dig gibt sehr lange TXT-Einträge (> 255 Byte) als mehrere
    # Anführungszeichen-Segmente auf einer Zeile aus.
    long_spf = _dig_result('"v=spf1 ip4:203.0" "." "113.0/24 ~all"\n')
    with patch("dmarcwatch.spf.subprocess.run", return_value=long_spf):
        result = resolve_own_ip_networks("example.com")
    assert result == ["203.0.113.0/24"]


def test_ignores_non_spf_txt_records():
    combined = _dig_result(
        '"google-site-verification=abc123"\n"v=spf1 ip4:203.0.113.0/24 ~all"\n'
    )
    with patch("dmarcwatch.spf.subprocess.run", return_value=combined):
        result = resolve_own_ip_networks("example.com")
    assert result == ["203.0.113.0/24"]


def test_missing_spf_record_raises_clear_error():
    with patch("dmarcwatch.spf.subprocess.run", return_value=_dig_result("")):
        with pytest.raises(SPFResolutionError, match="Kein SPF-Eintrag"):
            resolve_own_ip_networks("example.com")


def test_dig_failure_raises_clear_error():
    with patch("dmarcwatch.spf.subprocess.run", return_value=_dig_result("", returncode=9)):
        with pytest.raises(SPFResolutionError, match="DNS-Abfrage fehlgeschlagen"):
            resolve_own_ip_networks("example.com")


def test_dig_timeout_raises_clear_error():
    with patch(
        "dmarcwatch.spf.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="dig", timeout=5.0),
    ):
        with pytest.raises(SPFResolutionError, match="DNS-Abfrage fehlgeschlagen"):
            resolve_own_ip_networks("example.com")


def test_deeply_nested_includes_hit_rfc7208_lookup_limit():
    # 15 verschachtelte includes - mehr als die von RFC 7208 erlaubten 10
    # DNS-Lookups. Muss sauber abbrechen statt zu hängen oder abzustürzen.
    responses = {}
    for i in range(15):
        domain = f"level{i}.example.com"
        next_domain = f"level{i + 1}.example.com"
        responses[("TXT", domain)] = _txt(f"v=spf1 include:{next_domain} ~all")
    responses[("TXT", "level15.example.com")] = _txt("v=spf1 ip4:203.0.113.0/24 ~all")

    def fake_run(cmd, **kwargs):
        record_type, name = cmd[-2], cmd[-1]
        return responses[(record_type, name)]

    with patch("dmarcwatch.spf.subprocess.run", side_effect=fake_run):
        with pytest.raises(SPFResolutionError, match="Zu viele verschachtelte SPF-Lookups"):
            resolve_own_ip_networks("level0.example.com")


def test_circular_include_is_detected_not_infinite_loop():
    responses = {
        ("TXT", "a.example.com"): _txt("v=spf1 include:b.example.com ~all"),
        ("TXT", "b.example.com"): _txt("v=spf1 include:a.example.com ~all"),
    }

    def fake_run(cmd, **kwargs):
        record_type, name = cmd[-2], cmd[-1]
        return responses[(record_type, name)]

    with patch("dmarcwatch.spf.subprocess.run", side_effect=fake_run):
        with pytest.raises(SPFResolutionError, match="Zyklus"):
            resolve_own_ip_networks("a.example.com")


def test_deduplicates_overlapping_networks():
    responses = {
        ("TXT", "example.com"): _txt("v=spf1 ip4:203.0.113.0/24 include:_spf.other.example ~all"),
        ("TXT", "_spf.other.example"): _txt("v=spf1 ip4:203.0.113.0/24 ~all"),
    }

    def fake_run(cmd, **kwargs):
        record_type, name = cmd[-2], cmd[-1]
        return responses[(record_type, name)]

    with patch("dmarcwatch.spf.subprocess.run", side_effect=fake_run):
        result = resolve_own_ip_networks("example.com")
    assert result == ["203.0.113.0/24"]


def test_never_uses_shell_true():
    """Die Domain landet als reines Argument in einer Argumentliste, nie in
    einem per Shell interpretierten String - keine Command-Injection über
    einen böswillig gewählten Domainnamen möglich."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["shell"] = kwargs.get("shell", False)
        return _txt("v=spf1 ip4:203.0.113.0/24 ~all")

    with patch("dmarcwatch.spf.subprocess.run", side_effect=fake_run):
        resolve_own_ip_networks("example.com; rm -rf /")

    assert captured["shell"] is False
    assert isinstance(captured["cmd"], list)


# --- validate_spf() für `dmarcwatch verify-dns` ---


def test_validate_spf_reports_missing_record():
    with patch("dmarcwatch.spf.subprocess.run", return_value=_dig_result("")):
        result = validate_spf("example.com")
    assert result.exists is False
    assert any("Kein SPF-Eintrag" in w for w in result.warnings)


def test_validate_spf_valid_record_no_warnings():
    with patch("dmarcwatch.spf.subprocess.run", return_value=_txt("v=spf1 ip4:203.0.113.0/24 -all")):
        result = validate_spf("example.com")
    assert result.exists is True
    assert result.warnings == []
    assert result.lookup_limit_ok is True
    assert result.lookup_count == 1


def test_validate_spf_flags_multiple_records():
    combined = _dig_result('"v=spf1 ip4:203.0.113.0/24 -all"\n"v=spf1 ip4:198.51.100.0/24 -all"\n')
    with patch("dmarcwatch.spf.subprocess.run", return_value=combined):
        result = validate_spf("example.com")
    assert any("2 SPF-Einträge" in w for w in result.warnings)


def test_validate_spf_flags_missing_all_mechanism():
    with patch("dmarcwatch.spf.subprocess.run", return_value=_txt("v=spf1 ip4:203.0.113.0/24")):
        result = validate_spf("example.com")
    assert any("Kein 'all'-Mechanismus" in w for w in result.warnings)


def test_validate_spf_flags_permissive_plus_all():
    with patch("dmarcwatch.spf.subprocess.run", return_value=_txt("v=spf1 ip4:203.0.113.0/24 +all")):
        result = validate_spf("example.com")
    assert any("erlaubt praktisch jedem Server" in w for w in result.warnings)


def test_validate_spf_counts_lookups_and_flags_limit_exceeded():
    responses = {}
    for i in range(15):
        domain = f"level{i}.example.com"
        next_domain = f"level{i + 1}.example.com"
        responses[("TXT", domain)] = _txt(f"v=spf1 include:{next_domain} ~all")
    responses[("TXT", "level15.example.com")] = _txt("v=spf1 ip4:203.0.113.0/24 ~all")

    def fake_run(cmd, **kwargs):
        record_type, name = cmd[-2], cmd[-1]
        return responses[(record_type, name)]

    with patch("dmarcwatch.spf.subprocess.run", side_effect=fake_run):
        result = validate_spf("level0.example.com")

    assert result.exists is True  # der Top-Level-Eintrag selbst existiert ja
    assert result.lookup_limit_ok is False
    assert any("Zu viele verschachtelte SPF-Lookups" in w for w in result.warnings)
