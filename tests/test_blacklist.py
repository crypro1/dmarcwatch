"""Spamhaus-ZEN-Abfrage: rein informativ, siehe blacklist.py-Modul-Docstring.
Tests mocken `dig` - gleiche Begründung wie bei test_spf.py/test_dns_verify.py:
kein automatisierter Testlauf darf von echtem DNS abhängen."""
import subprocess
from unittest.mock import patch

import pytest

from dmarcwatch.blacklist import BlacklistCheckError, check_ip_blacklist
from dmarcwatch.spf import SPFResolutionError


def _dig_result(stdout: str, returncode: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr="")


def test_not_listed_ip_returns_clean_result():
    with patch("dmarcwatch.blacklist._dig_checked", return_value=[]) as mock_dig:
        result = check_ip_blacklist("192.0.2.1")
    assert result.listed is False
    assert result.reasons == []
    # Reverse-Oktett-Reihenfolge + Zonenname, wie von Spamhaus verlangt.
    mock_dig.assert_called_once_with("A", "1.2.0.192.zen.spamhaus.org")


def test_listed_ip_returns_known_reason():
    with patch("dmarcwatch.blacklist._dig_checked", return_value=["127.0.0.2"]):
        result = check_ip_blacklist("198.51.100.5")
    assert result.listed is True
    assert result.reasons == ["SBL - bekannte Spam-Quelle"]


def test_multiple_return_codes_produce_multiple_reasons():
    with patch("dmarcwatch.blacklist._dig_checked", return_value=["127.0.0.2", "127.0.0.4"]):
        result = check_ip_blacklist("198.51.100.5")
    assert result.listed is True
    assert len(result.reasons) == 2


def test_unknown_return_code_shown_without_crashing():
    with patch("dmarcwatch.blacklist._dig_checked", return_value=["127.0.0.99"]):
        result = check_ip_blacklist("198.51.100.5")
    assert result.listed is True
    assert "Unbekannter Rückgabecode 127.0.0.99" in result.reasons[0]


def test_invalid_ip_raises_blacklist_check_error():
    with pytest.raises(BlacklistCheckError):
        check_ip_blacklist("not-an-ip")


def test_ipv6_raises_blacklist_check_error_not_supported():
    with pytest.raises(BlacklistCheckError, match="IPv4"):
        check_ip_blacklist("2001:db8::1")


def test_dns_failure_raises_blacklist_check_error():
    with patch("dmarcwatch.blacklist._dig_checked", side_effect=SPFResolutionError("Zeitüberschreitung")):
        with pytest.raises(BlacklistCheckError):
            check_ip_blacklist("198.51.100.5")


def test_servfail_raises_blacklist_check_error_instead_of_false_clean():
    # `dig +short` liefert bei SERVFAIL (z. B. Drosselung eines
    # gemeinsam genutzten Resolvers durch Spamhaus) genau wie bei einer
    # echten Leerantwort Exit-Code 0 und leeres stdout - ohne die
    # Status-Prüfung in _dig_checked() würde das fälschlich als
    # listed=False ("IP sauber") durchgehen statt als fehlgeschlagener
    # Check gemeldet zu werden.
    servfail = _dig_result(
        ";; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 1\n"
        ";; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0\n"
    )
    with patch("dmarcwatch.spf.subprocess.run", return_value=servfail):
        with pytest.raises(BlacklistCheckError):
            check_ip_blacklist("198.51.100.5")


def test_cname_alias_in_answer_section_not_mistaken_for_return_code():
    # dig kann vor der eigentlichen A-Antwort eine CNAME-Zeile liefern (hier
    # simuliert, auch wenn Spamhaus ZEN das in der Praxis nicht tut) - ohne
    # Prüfung der Record-Type-Spalte würde der Alias-Hostname fälschlich als
    # 127.0.0.x-Rückgabecode interpretiert statt korrekt herausgefiltert.
    answer = _dig_result(
        ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n"
        ";; flags: qr rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 0\n"
        "\n"
        ";; ANSWER SECTION:\n"
        "1.2.0.192.zen.spamhaus.org. 300 IN CNAME some-alias.spamhaus.org.\n"
        "some-alias.spamhaus.org. 300 IN A 127.0.0.2\n"
    )
    with patch("dmarcwatch.spf.subprocess.run", return_value=answer):
        result = check_ip_blacklist("198.51.100.5")
    assert result.listed is True
    assert result.reasons == ["SBL - bekannte Spam-Quelle"]
    assert not any("some-alias.spamhaus.org" in reason for reason in result.reasons)


def test_spamhaus_error_codes_are_errors_not_listings():
    """127.255.255.x sind laut Spamhaus Fehlercodes (z. B. .254 = Abfrage
    über einen öffentlichen Resolver), keine Listings - sonst erschiene bei
    so einem Resolver JEDE IP als gelistet und würde so gecacht."""
    for code in ("127.255.255.252", "127.255.255.254", "127.255.255.255"):
        with patch("dmarcwatch.blacklist._dig_checked", return_value=[code]):
            with pytest.raises(BlacklistCheckError, match="kein Listing"):
                check_ip_blacklist("192.0.2.1")
