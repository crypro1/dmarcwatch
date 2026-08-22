"""DMARC/SPF/DKIM-DNS-Prüfung (dns_verify.py) für `dmarcwatch verify-dns`.

Tests mocken `dig` per subprocess - gleiche Begründung wie bei
test_spf.py/test_whois.py: kein automatisierter Testlauf darf von echtem
DNS abhängen. Der CNAME-Test (test_check_dkim_follows_cname_to_provider)
ist ein Regressionstest für einen echten, gegen eine mailbox.org-Domain
gefundenen Bug: `dig` zeigt bei einem CNAME-delegierten DKIM-Eintrag zuerst
das unquotierte CNAME-Ziel und erst danach den eigentlichen TXT-Inhalt -
naiv die erste Zeile zu nehmen liefert dann fälschlich "kein Public Key".
"""
import subprocess
from unittest.mock import patch

from dmarcwatch.dns_verify import check_dkim, check_dmarc


def _dig_result(stdout: str, returncode: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr="")


def _txt(record: str) -> subprocess.CompletedProcess:
    return _dig_result(f'"{record}"\n')


# --- check_dmarc() ---


def test_check_dmarc_missing_record():
    with patch("dmarcwatch.dns_verify._txt_records", return_value=[]):
        result = check_dmarc("example.com")
    assert result.exists is False
    assert any("Kein DMARC-Eintrag" in w for w in result.warnings)


def test_check_dmarc_valid_record_no_warnings():
    record = "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=100"
    with patch("dmarcwatch.dns_verify._txt_records", return_value=[record]):
        result = check_dmarc("example.com")
    assert result.exists is True
    assert result.policy == "reject"
    assert result.rua == "mailto:dmarc@example.com"
    assert result.warnings == []


def test_check_dmarc_flags_multiple_records():
    records = [
        "v=DMARC1; p=reject; rua=mailto:a@example.com",
        "v=DMARC1; p=none; rua=mailto:b@example.com",
    ]
    with patch("dmarcwatch.dns_verify._txt_records", return_value=records):
        result = check_dmarc("example.com")
    assert any("2 DMARC-Einträge" in w for w in result.warnings)


def test_check_dmarc_flags_missing_rua():
    with patch("dmarcwatch.dns_verify._txt_records", return_value=["v=DMARC1; p=reject"]):
        result = check_dmarc("example.com")
    assert any("rua" in w for w in result.warnings)


def test_check_dmarc_flags_p_none_as_informational_only():
    with patch(
        "dmarcwatch.dns_verify._txt_records",
        return_value=["v=DMARC1; p=none; rua=mailto:a@example.com"],
    ):
        result = check_dmarc("example.com")
    assert any("noch keine Durchsetzung" in w for w in result.warnings)


def test_check_dmarc_flags_invalid_policy_value():
    with patch(
        "dmarcwatch.dns_verify._txt_records",
        return_value=["v=DMARC1; p=blockeverything; rua=mailto:a@example.com"],
    ):
        result = check_dmarc("example.com")
    assert any("Ungültiger Policy-Wert" in w for w in result.warnings)


def test_check_dmarc_flags_partial_pct_rollout():
    record = "v=DMARC1; p=reject; pct=50; rua=mailto:a@example.com"
    with patch("dmarcwatch.dns_verify._txt_records", return_value=[record]):
        result = check_dmarc("example.com")
    assert result.pct == 50
    assert any("nur 50%" in w for w in result.warnings)


def test_check_dmarc_missing_required_p_tag():
    with patch(
        "dmarcwatch.dns_verify._txt_records", return_value=["v=DMARC1; rua=mailto:a@example.com"]
    ):
        result = check_dmarc("example.com")
    assert any("Pflicht-Tag 'p'" in w for w in result.warnings)


# --- check_dkim() ---


def test_check_dkim_valid_rsa_key():
    record = _txt("v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCg==")
    with patch("dmarcwatch.dns_verify.subprocess.run", return_value=record):
        result = check_dkim("example.com", "selector1")
    assert result.exists is True
    assert result.key_type == "rsa"
    assert result.warnings == []


def test_check_dkim_valid_ed25519_key():
    record = _txt("v=DKIM1; k=ed25519; p=MCowBQYDK2VwAyEA")
    with patch("dmarcwatch.dns_verify.subprocess.run", return_value=record):
        result = check_dkim("example.com", "selector1")
    assert result.key_type == "ed25519"
    assert result.warnings == []


def test_check_dkim_flags_empty_public_key():
    with patch("dmarcwatch.dns_verify.subprocess.run", return_value=_txt("v=DKIM1; k=rsa; p=")):
        result = check_dkim("example.com", "selector1")
    assert any("Kein Public Key" in w for w in result.warnings)


def test_check_dkim_missing_record():
    with patch("dmarcwatch.dns_verify.subprocess.run", return_value=_dig_result("")):
        result = check_dkim("example.com", "selector1")
    assert result.exists is False


def test_check_dkim_follows_cname_to_provider():
    """Regressionstest für den echten, gegen eine mailbox.org-Domain
    gefundenen Bug: `dig` liefert bei CNAME-Delegation zuerst das
    unquotierte CNAME-Ziel, erst danach den quotierten TXT-Inhalt mit dem
    eigentlichen Key - nicht blind die erste Zeile nehmen."""
    dig_output = (
        "selector1._domainkey.provider.example.\n"
        '"v=DKIM1; k=rsa; " "p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCg=="\n'
    )
    with patch("dmarcwatch.dns_verify.subprocess.run", return_value=_dig_result(dig_output)):
        result = check_dkim("example.com", "selector1")
    assert result.exists is True
    assert result.key_type == "rsa"
    # Der Bug hätte hier fälschlich "kein Public Key" gemeldet, weil die
    # erste (unquotierte CNAME-Ziel-)Zeile keinen 'p'-Tag enthält.
    assert result.warnings == []


def test_check_dkim_unknown_key_type():
    with patch(
        "dmarcwatch.dns_verify.subprocess.run",
        return_value=_txt("v=DKIM1; k=dsa; p=abc"),
    ):
        result = check_dkim("example.com", "selector1")
    assert any("Unbekannter Key-Typ" in w for w in result.warnings)
