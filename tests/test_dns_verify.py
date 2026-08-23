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

from dmarcwatch.dns_verify import (
    DKIMCheckResult,
    DMARCCheckResult,
    DomainVerification,
    MTASTSCheckResult,
    MXBlacklistCheckResult,
    TLSRPTDNSCheckResult,
    WildcardSPFCheckResult,
    _fetch_mta_sts_policy,
    check_dkim,
    check_dmarc,
    check_mta_sts,
    check_mx_blacklist,
    check_tlsrpt_dns,
    check_wildcard_spf,
    has_warnings,
)
from dmarcwatch.blacklist import BlacklistCheckError, BlacklistResult
from dmarcwatch.spf import SPFCheckResult, SPFResolutionError


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


# --- has_warnings() ---


def _clean_result(domain: str = "example.com") -> DomainVerification:
    return DomainVerification(
        domain=domain,
        dmarc=DMARCCheckResult(exists=True, record="v=DMARC1; p=reject; rua=mailto:a@example.com", policy="reject"),
        spf=SPFCheckResult(exists=True, record="v=spf1 -all", lookup_count=0, lookup_limit_ok=True),
        dkim=[DKIMCheckResult(selector="default", exists=True, key_type="rsa")],
        mta_sts=MTASTSCheckResult(configured=False),
        tlsrpt_dns=TLSRPTDNSCheckResult(configured=False),
        wildcard_spf=WildcardSPFCheckResult(configured=False),
        mx_blacklist=MXBlacklistCheckResult(checked=False),
    )


def test_has_warnings_false_for_clean_result():
    assert has_warnings(_clean_result()) is False


def test_has_warnings_true_for_dmarc_warning():
    result = _clean_result()
    result.dmarc.warnings.append("p=none: rein beobachtend")
    assert has_warnings(result) is True


def test_has_warnings_true_for_spf_warning():
    result = _clean_result()
    result.spf.warnings.append("SPF: fehlender all-Mechanismus")
    assert has_warnings(result) is True


def test_has_warnings_true_for_spf_error_even_without_warning_list():
    """Ein harter SPF-Fehler (z. B. DNS nicht erreichbar) landet nicht in
    warnings, sondern in error - zählt aber genauso als Auffälligkeit."""
    result = _clean_result()
    result.spf = SPFCheckResult(exists=False, error="DNS-Abfrage fehlgeschlagen")
    assert has_warnings(result) is True


def test_has_warnings_true_for_dkim_warning():
    result = _clean_result()
    result.dkim[0].warnings.append("Kein Public Key")
    assert has_warnings(result) is True


def test_has_warnings_true_for_mx_blacklist_warning():
    result = _clean_result()
    result.mx_blacklist.warnings.append("Mailserver mail.example.com (198.51.100.5) ist bei Spamhaus ZEN gelistet")
    assert has_warnings(result) is True


# --- check_mta_sts() ---


def test_check_mta_sts_absent_is_not_configured_no_warning():
    with patch("dmarcwatch.dns_verify._dig", return_value=[]):
        with patch("dmarcwatch.dns_verify._txt_records", return_value=[]):
            result = check_mta_sts("example.com")
    assert result.configured is False
    assert result.warnings == []


def test_check_mta_sts_fully_configured_no_warning():
    def fake_dig(record_type, name):
        if record_type == "CNAME" and name == "mta-sts.example.com":
            return ["assets.provider.example."]
        return []

    with patch("dmarcwatch.dns_verify._dig", side_effect=fake_dig):
        with patch(
            "dmarcwatch.dns_verify._txt_records",
            return_value=["v=STSv1; id=20260101000000Z"],
        ):
            with patch("dmarcwatch.dns_verify._fetch_mta_sts_policy", return_value=(True, None)):
                result = check_mta_sts("example.com")
    assert result.configured is True
    assert result.cname_target == "assets.provider.example"
    assert result.policy_reachable is True
    assert result.warnings == []


def test_check_mta_sts_policy_without_hostname_warns():
    """Regressionstest für den echten, per Hand gefundenen Bug: ein
    Policy-TXT-Eintrag existiert, aber der Hostname (mta-sts.<domain>) ist
    nicht erreichbar - z. B. weil er im DNS-Panel versehentlich unter einem
    doppelt zusammengesetzten Namen gelandet ist."""
    with patch("dmarcwatch.dns_verify._dig", return_value=[]):
        with patch("dmarcwatch.dns_verify._txt_records", return_value=["v=STSv1; id=123"]):
            result = check_mta_sts("example.com")
    assert result.configured is True
    assert any("weder CNAME noch A/AAAA" in w for w in result.warnings)


def test_check_mta_sts_hostname_without_policy_warns():
    with patch("dmarcwatch.dns_verify._dig", return_value=["assets.provider.example."]):
        with patch("dmarcwatch.dns_verify._txt_records", return_value=[]):
            with patch("dmarcwatch.dns_verify._fetch_mta_sts_policy", return_value=(True, None)):
                result = check_mta_sts("example.com")
    assert result.configured is True
    assert any("keinen gültigen" in w for w in result.warnings)


def test_check_mta_sts_missing_id_tag_warns():
    with patch("dmarcwatch.dns_verify._dig", return_value=["assets.provider.example."]):
        with patch("dmarcwatch.dns_verify._txt_records", return_value=["v=STSv1; mode=testing"]):
            with patch("dmarcwatch.dns_verify._fetch_mta_sts_policy", return_value=(True, None)):
                result = check_mta_sts("example.com")
    assert any("id=" in w for w in result.warnings)


def test_check_mta_sts_unreachable_policy_file_warns():
    """Hostname und DNS-Policy-Eintrag sind korrekt, aber die tatsächliche
    Policy-Datei ist per HTTPS nicht erreichbar (z. B. Hosting-Ausfall
    oder falsch konfigurierter Webserver) - das ist ein eigenständiger
    Fehlerfall, den reine DNS-Prüfung nicht abdecken würde."""
    with patch("dmarcwatch.dns_verify._dig", return_value=["assets.provider.example."]):
        with patch("dmarcwatch.dns_verify._txt_records", return_value=["v=STSv1; id=123"]):
            with patch(
                "dmarcwatch.dns_verify._fetch_mta_sts_policy",
                return_value=(False, "HTTP 404"),
            ):
                result = check_mta_sts("example.com")
    assert result.policy_reachable is False
    assert any("nicht erreichbar" in w and "HTTP 404" in w for w in result.warnings)


def test_check_mta_sts_absent_skips_https_fetch_entirely():
    """Ohne konfigurierten Hostnamen wird gar nicht erst versucht, die
    Policy-Datei abzurufen - kein unnötiger Netzverkehr, wenn schon die
    DNS-Prüfung zeigt, dass MTA-STS nicht genutzt wird."""
    with patch("dmarcwatch.dns_verify._dig", return_value=[]):
        with patch("dmarcwatch.dns_verify._txt_records", return_value=[]):
            with patch("dmarcwatch.dns_verify._fetch_mta_sts_policy") as mock_fetch:
                result = check_mta_sts("example.com")
    mock_fetch.assert_not_called()
    assert result.policy_reachable is None


# --- check_tlsrpt_dns() ---


def test_check_tlsrpt_dns_absent_is_not_configured_no_warning():
    with patch("dmarcwatch.dns_verify._txt_records", return_value=[]):
        result = check_tlsrpt_dns("example.com")
    assert result.configured is False
    assert result.warnings == []


def test_check_tlsrpt_dns_valid_no_warning():
    with patch(
        "dmarcwatch.dns_verify._txt_records",
        return_value=["v=TLSRPTv1; rua=mailto:tlsrpt@example.com"],
    ):
        result = check_tlsrpt_dns("example.com")
    assert result.configured is True
    assert result.warnings == []


def test_check_tlsrpt_dns_missing_rua_warns():
    with patch("dmarcwatch.dns_verify._txt_records", return_value=["v=TLSRPTv1"]):
        result = check_tlsrpt_dns("example.com")
    assert any("rua=" in w for w in result.warnings)


def test_check_tlsrpt_dns_multiple_records_warns():
    with patch(
        "dmarcwatch.dns_verify._txt_records",
        return_value=["v=TLSRPTv1; rua=mailto:a@example.com", "v=TLSRPTv1; rua=mailto:b@example.com"],
    ):
        result = check_tlsrpt_dns("example.com")
    assert any("2 TLS-RPT-Einträge" in w for w in result.warnings)


# --- check_wildcard_spf() ---


def test_check_wildcard_spf_absent_is_not_configured_no_warning():
    with patch("dmarcwatch.dns_verify._txt_records", return_value=[]):
        result = check_wildcard_spf("example.com")
    assert result.configured is False
    assert result.warnings == []


def test_check_wildcard_spf_restrictive_no_warning():
    with patch("dmarcwatch.dns_verify._txt_records", return_value=["v=spf1 -all"]):
        result = check_wildcard_spf("example.com")
    assert result.configured is True
    assert result.warnings == []


def test_check_wildcard_spf_permissive_warns():
    with patch("dmarcwatch.dns_verify._txt_records", return_value=["v=spf1 +all"]):
        result = check_wildcard_spf("example.com")
    assert any("-all" in w for w in result.warnings)


# --- _fetch_mta_sts_policy() ---


class _FakeHTTPResponse:
    def __init__(self, status: int, body: bytes):
        self.status = status
        self._body = body

    def read(self, n=-1):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def test_fetch_mta_sts_policy_valid_response():
    fake_response = _FakeHTTPResponse(200, b"version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 604800")
    with patch("dmarcwatch.dns_verify.urllib.request.urlopen", return_value=fake_response):
        reachable, error = _fetch_mta_sts_policy("mta-sts.example.com")
    assert reachable is True
    assert error is None


def test_fetch_mta_sts_policy_wrong_content():
    fake_response = _FakeHTTPResponse(200, b"<html>not a policy file</html>")
    with patch("dmarcwatch.dns_verify.urllib.request.urlopen", return_value=fake_response):
        reachable, error = _fetch_mta_sts_policy("mta-sts.example.com")
    assert reachable is False
    assert error is not None


def test_fetch_mta_sts_policy_http_error_status():
    fake_response = _FakeHTTPResponse(404, b"not found")
    with patch("dmarcwatch.dns_verify.urllib.request.urlopen", return_value=fake_response):
        reachable, error = _fetch_mta_sts_policy("mta-sts.example.com")
    assert reachable is False
    assert "404" in error


def test_fetch_mta_sts_policy_connection_error():
    with patch("dmarcwatch.dns_verify.urllib.request.urlopen", side_effect=OSError("connection refused")):
        reachable, error = _fetch_mta_sts_policy("mta-sts.example.com")
    assert reachable is False


# --- check_mx_blacklist() ---


def test_check_mx_blacklist_no_mx_records_not_checked():
    with patch("dmarcwatch.dns_verify._dig", return_value=[]):
        result = check_mx_blacklist("example.com")
    assert result.checked is False
    assert result.warnings == []


def test_check_mx_blacklist_dns_failure_not_checked():
    with patch("dmarcwatch.dns_verify._dig", side_effect=SPFResolutionError("Zeitüberschreitung")):
        result = check_mx_blacklist("example.com")
    assert result.checked is False


def test_check_mx_blacklist_clean_mx_no_warning():
    def fake_dig(record_type, name):
        if record_type == "MX" and name == "example.com":
            return ["10 mail.example.com."]
        if record_type == "A" and name == "mail.example.com":
            return ["198.51.100.5"]
        return []

    with patch("dmarcwatch.dns_verify._dig", side_effect=fake_dig):
        with patch(
            "dmarcwatch.dns_verify.check_ip_blacklist",
            return_value=BlacklistResult(ip="198.51.100.5", listed=False),
        ):
            result = check_mx_blacklist("example.com")
    assert result.checked is True
    assert result.mx_hosts == ["mail.example.com"]
    assert result.listed == []
    assert result.warnings == []


def test_check_mx_blacklist_listed_mx_warns():
    def fake_dig(record_type, name):
        if record_type == "MX" and name == "example.com":
            return ["10 mail.example.com."]
        if record_type == "A" and name == "mail.example.com":
            return ["198.51.100.5"]
        return []

    with patch("dmarcwatch.dns_verify._dig", side_effect=fake_dig):
        with patch(
            "dmarcwatch.dns_verify.check_ip_blacklist",
            return_value=BlacklistResult(
                ip="198.51.100.5", listed=True, reasons=["SBL - bekannte Spam-Quelle"]
            ),
        ):
            result = check_mx_blacklist("example.com")
    assert result.checked is True
    assert any("mail.example.com" in entry and "198.51.100.5" in entry for entry in result.listed)
    assert any("Spamhaus ZEN gelistet" in w for w in result.warnings)


def test_check_mx_blacklist_duplicate_ip_only_queried_once():
    """Mehrere MX-Hosts können auf dieselbe IP zeigen (Failover) - die
    Spamhaus-Abfrage soll trotzdem nur einmal pro eindeutiger IP passieren."""

    def fake_dig(record_type, name):
        if record_type == "MX" and name == "example.com":
            return ["10 mail1.example.com.", "20 mail2.example.com."]
        if record_type == "A":
            return ["198.51.100.5"]
        return []

    with patch("dmarcwatch.dns_verify._dig", side_effect=fake_dig):
        with patch(
            "dmarcwatch.dns_verify.check_ip_blacklist",
            return_value=BlacklistResult(ip="198.51.100.5", listed=False),
        ) as mock_check:
            check_mx_blacklist("example.com")
    mock_check.assert_called_once_with("198.51.100.5")


def test_check_mx_blacklist_query_error_warns_without_crashing():
    def fake_dig(record_type, name):
        if record_type == "MX" and name == "example.com":
            return ["10 mail.example.com."]
        if record_type == "A" and name == "mail.example.com":
            return ["198.51.100.5"]
        return []

    with patch("dmarcwatch.dns_verify._dig", side_effect=fake_dig):
        with patch(
            "dmarcwatch.dns_verify.check_ip_blacklist",
            side_effect=BlacklistCheckError("Zeitüberschreitung"),
        ):
            result = check_mx_blacklist("example.com")
    assert result.checked is True
    assert result.listed == []
    assert any("fehlgeschlagen" in w for w in result.warnings)
