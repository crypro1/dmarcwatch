"""Spamhaus-ZEN-Abfrage: rein informativ, siehe blacklist.py-Modul-Docstring.
Tests mocken `dig` - gleiche Begründung wie bei test_spf.py/test_dns_verify.py:
kein automatisierter Testlauf darf von echtem DNS abhängen."""
from unittest.mock import patch

import pytest

from dmarcwatch.blacklist import BlacklistCheckError, check_ip_blacklist
from dmarcwatch.spf import SPFResolutionError


def test_not_listed_ip_returns_clean_result():
    with patch("dmarcwatch.blacklist._dig", return_value=[]) as mock_dig:
        result = check_ip_blacklist("192.0.2.1")
    assert result.listed is False
    assert result.reasons == []
    # Reverse-Oktett-Reihenfolge + Zonenname, wie von Spamhaus verlangt.
    mock_dig.assert_called_once_with("A", "1.2.0.192.zen.spamhaus.org")


def test_listed_ip_returns_known_reason():
    with patch("dmarcwatch.blacklist._dig", return_value=["127.0.0.2"]):
        result = check_ip_blacklist("198.51.100.5")
    assert result.listed is True
    assert result.reasons == ["SBL - bekannte Spam-Quelle"]


def test_multiple_return_codes_produce_multiple_reasons():
    with patch("dmarcwatch.blacklist._dig", return_value=["127.0.0.2", "127.0.0.4"]):
        result = check_ip_blacklist("198.51.100.5")
    assert result.listed is True
    assert len(result.reasons) == 2


def test_unknown_return_code_shown_without_crashing():
    with patch("dmarcwatch.blacklist._dig", return_value=["127.0.0.99"]):
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
    with patch("dmarcwatch.blacklist._dig", side_effect=SPFResolutionError("Zeitüberschreitung")):
        with pytest.raises(BlacklistCheckError):
            check_ip_blacklist("198.51.100.5")
