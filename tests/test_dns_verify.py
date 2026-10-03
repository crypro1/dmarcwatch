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
    _BIMI_MAX_SVG_SIZE_BYTES,
    BIMICheckResult,
    DANECheckResult,
    DKIMCheckResult,
    DMARCCheckResult,
    DNSSECCheckResult,
    DomainVerification,
    MTASTSCheckResult,
    MXBlacklistCheckResult,
    TLSRPTDNSCheckResult,
    WildcardSPFCheckResult,
    _fetch_bimi_logo,
    _fetch_mta_sts_policy,
    _fingerprint,
    _validate_bimi_svg,
    check_bimi,
    check_dane,
    check_dkim,
    check_dmarc,
    check_dnssec,
    check_mta_sts,
    check_mx_blacklist,
    check_tlsrpt_dns,
    check_wildcard_spf,
    diff_and_update_snapshot,
    has_warnings,
)
from dmarcwatch.blacklist import BlacklistCheckError, BlacklistResult
from dmarcwatch.spf import SPFCheckResult, SPFResolutionError
from dmarcwatch.store import connect, get_and_replace_dns_snapshot


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


def test_check_dmarc_dns_failure_reports_warning_instead_of_raising():
    with patch(
        "dmarcwatch.dns_verify._txt_records", side_effect=SPFResolutionError("Zeitüberschreitung")
    ):
        result = check_dmarc("example.com")
    assert result.exists is False
    assert any("DMARC-Abfrage fehlgeschlagen" in w and "Zeitüberschreitung" in w for w in result.warnings)


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
        dnssec=DNSSECCheckResult(configured=False),
        dane=DANECheckResult(configured=False),
        bimi=BIMICheckResult(configured=False),
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


def test_has_warnings_true_for_dnssec_warning():
    result = _clean_result()
    result.dnssec.warnings.append("DNSSEC-Validierung schlägt fehl")
    assert has_warnings(result) is True


def test_has_warnings_true_for_dane_warning():
    result = _clean_result()
    result.dane.warnings.append("TLSA vorhanden, aber DNSSEC validiert nicht")
    assert has_warnings(result) is True


def test_has_warnings_true_for_bimi_warning():
    result = _clean_result()
    result.bimi.warnings.append("BIMI ohne durchgesetzte DMARC-Policy")
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


# --- check_dnssec() ---


def _dig_full_result(stdout: str, returncode: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr="")


_VALIDATED_FLAGS = _dig_full_result(";; flags: qr rd ra ad; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 1\n")
_UNVALIDATED_FLAGS = _dig_full_result(";; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n")


def test_check_dnssec_absent_is_not_configured_no_warning():
    with patch("dmarcwatch.dns_verify._dig", return_value=[]):
        result = check_dnssec("example.com")
    assert result.configured is False
    assert result.validated is None
    assert result.warnings == []


def test_check_dnssec_fully_configured_and_validated_no_warning():
    def fake_dig(record_type, name):
        if record_type == "DNSKEY":
            return ["257 3 13 abcd=="]
        if record_type == "DS":
            return ["2371 13 2 abcd"]
        return []

    with patch("dmarcwatch.dns_verify._dig", side_effect=fake_dig):
        with patch("dmarcwatch.dns_verify.subprocess.run", return_value=_VALIDATED_FLAGS):
            result = check_dnssec("example.com")
    assert result.configured is True
    assert result.validated is True
    assert result.warnings == []


def test_check_dnssec_ds_without_dnskey_warns():
    def fake_dig(record_type, name):
        if record_type == "DS":
            return ["2371 13 2 abcd"]
        return []

    with patch("dmarcwatch.dns_verify._dig", side_effect=fake_dig):
        with patch("dmarcwatch.dns_verify.subprocess.run", return_value=_UNVALIDATED_FLAGS):
            result = check_dnssec("example.com")
    assert result.configured is True
    assert any("kein DNSKEY gefunden" in w for w in result.warnings)


def test_check_dnssec_dnskey_without_ds_warns():
    def fake_dig(record_type, name):
        if record_type == "DNSKEY":
            return ["257 3 13 abcd=="]
        return []

    with patch("dmarcwatch.dns_verify._dig", side_effect=fake_dig):
        with patch("dmarcwatch.dns_verify.subprocess.run", return_value=_UNVALIDATED_FLAGS):
            result = check_dnssec("example.com")
    assert result.configured is True
    assert any("kein DS-Eintrag" in w for w in result.warnings)


def test_check_dnssec_validation_fails_warns():
    """Regressionstest für den echten dnssec-failed.org-Fall: DS vorhanden,
    aber die Kette validiert nicht - z. B. abgelaufene Signatur."""

    def fake_dig(record_type, name):
        if record_type == "DNSKEY":
            return ["257 3 13 abcd=="]
        if record_type == "DS":
            return ["2371 13 2 abcd"]
        return []

    with patch("dmarcwatch.dns_verify._dig", side_effect=fake_dig):
        with patch("dmarcwatch.dns_verify.subprocess.run", return_value=_UNVALIDATED_FLAGS):
            result = check_dnssec("example.com")
    assert result.configured is True
    assert result.validated is False
    assert any("Vertrauenskette ist" in w for w in result.warnings)


def test_check_dnssec_validation_query_error_warns():
    def fake_dig(record_type, name):
        if record_type == "DNSKEY":
            return ["257 3 13 abcd=="]
        if record_type == "DS":
            return ["2371 13 2 abcd"]
        return []

    with patch("dmarcwatch.dns_verify._dig", side_effect=fake_dig):
        with patch("dmarcwatch.dns_verify.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="dig", timeout=3)):
            result = check_dnssec("example.com")
    assert result.configured is True
    assert result.validated is None
    assert any("nicht geprüft werden" in w for w in result.warnings)


# --- check_dane() ---


def test_check_dane_no_mx_not_configured():
    with patch("dmarcwatch.dns_verify._dig", return_value=[]):
        result = check_dane("example.com")
    assert result.configured is False
    assert result.warnings == []


def test_check_dane_mx_without_tlsa_not_configured():
    def fake_dig(record_type, name):
        if record_type == "MX" and name == "example.com":
            return ["10 mail.example.com."]
        return []

    with patch("dmarcwatch.dns_verify._dig", side_effect=fake_dig):
        result = check_dane("example.com")
    assert result.configured is False


def test_check_dane_with_tlsa_and_validated_dnssec_no_warning():
    def fake_dig(record_type, name):
        if record_type == "MX" and name == "example.com":
            return ["10 mail.example.com."]
        if record_type == "TLSA" and name == "_25._tcp.mail.example.com":
            return ["3 1 1 abcd"]
        return []

    with patch("dmarcwatch.dns_verify._dig", side_effect=fake_dig):
        with patch("dmarcwatch.dns_verify.subprocess.run", return_value=_VALIDATED_FLAGS):
            result = check_dane("example.com")
    assert result.configured is True
    assert result.mx_hosts_with_tlsa == ["mail.example.com"]
    assert result.warnings == []


def test_check_dane_tlsa_without_validated_dnssec_warns():
    """TLSA ohne intaktes DNSSEC bietet keinen echten Schutz - siehe
    DANECheckResult-Docstring."""

    def fake_dig(record_type, name):
        if record_type == "MX" and name == "example.com":
            return ["10 mail.example.com."]
        if record_type == "TLSA" and name == "_25._tcp.mail.example.com":
            return ["3 1 1 abcd"]
        return []

    with patch("dmarcwatch.dns_verify._dig", side_effect=fake_dig):
        with patch("dmarcwatch.dns_verify.subprocess.run", return_value=_UNVALIDATED_FLAGS):
            result = check_dane("example.com")
    assert result.configured is True
    assert any("DNSSEC validiert" in w for w in result.warnings)


# --- check_bimi() ---


def _dmarc_enforced() -> DMARCCheckResult:
    return DMARCCheckResult(exists=True, record="v=DMARC1; p=reject", policy="reject", pct=100)


def _dmarc_none() -> DMARCCheckResult:
    return DMARCCheckResult(exists=True, record="v=DMARC1; p=none", policy="none")


def test_check_bimi_absent_is_not_configured_no_warning():
    with patch("dmarcwatch.dns_verify._txt_records", return_value=[]):
        result = check_bimi("example.com", _dmarc_enforced())
    assert result.configured is False
    assert result.warnings == []


def test_check_bimi_valid_with_enforced_dmarc_no_warning():
    record = "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem"
    with patch("dmarcwatch.dns_verify._txt_records", return_value=[record]):
        with patch(
            "dmarcwatch.dns_verify._fetch_bimi_logo",
            return_value=("<svg baseProfile=\"tiny-ps\"></svg>", True, []),
        ):
            result = check_bimi("example.com", _dmarc_enforced())
    assert result.configured is True
    assert result.logo_reachable is True
    assert result.warnings == []


def test_check_bimi_missing_logo_tag_warns():
    with patch("dmarcwatch.dns_verify._txt_records", return_value=["v=BIMI1; a=https://example.com/vmc.pem"]):
        result = check_bimi("example.com", _dmarc_enforced())
    assert any("l=" in w for w in result.warnings)


def test_check_bimi_without_enforced_dmarc_warns():
    record = "v=BIMI1; l=https://example.com/logo.svg"
    with patch("dmarcwatch.dns_verify._txt_records", return_value=[record]):
        with patch("dmarcwatch.dns_verify._fetch_bimi_logo", return_value=(None, None, [])):
            result = check_bimi("example.com", _dmarc_none())
    assert any("nicht vollständig durchgesetzt" in w for w in result.warnings)


def test_check_bimi_pct_below_100_warns():
    record = "v=BIMI1; l=https://example.com/logo.svg"
    dmarc = DMARCCheckResult(exists=True, record="v=DMARC1; p=reject; pct=50", policy="reject", pct=50)
    with patch("dmarcwatch.dns_verify._txt_records", return_value=[record]):
        with patch("dmarcwatch.dns_verify._fetch_bimi_logo", return_value=(None, None, [])):
            result = check_bimi("example.com", dmarc)
    assert any("nicht vollständig durchgesetzt" in w for w in result.warnings)


# --- _fetch_bimi_logo() / _validate_bimi_svg() ---


_VALID_BIMI_SVG = (
    '<?xml version="1.0"?>'
    '<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" '
    'viewBox="0 0 100 100"><title>Example</title>'
    '<rect x="0" y="0" width="100" height="100" fill="#000"/></svg>'
).encode()


def test_fetch_bimi_logo_rejects_non_https():
    svg, reachable, warnings = _fetch_bimi_logo("http://example.com/logo.svg")
    assert svg is None
    assert reachable is False
    assert any("HTTPS" in w for w in warnings)


def test_fetch_bimi_logo_valid_svg_no_warnings():
    fake_response = _FakeHTTPResponse(200, _VALID_BIMI_SVG)
    with patch("dmarcwatch.dns_verify.urllib.request.urlopen", return_value=fake_response):
        svg, reachable, warnings = _fetch_bimi_logo("https://example.com/logo.svg")
    assert reachable is True
    assert svg is not None
    assert warnings == []


def test_validate_bimi_svg_missing_base_profile_warns():
    svg = _VALID_BIMI_SVG.decode().replace('baseProfile="tiny-ps"', "").encode()
    warnings = _validate_bimi_svg(svg)
    assert any("baseProfile" in w for w in warnings)


def test_validate_bimi_svg_missing_title_warns():
    svg = _VALID_BIMI_SVG.decode().replace("<title>Example</title>", "").encode()
    warnings = _validate_bimi_svg(svg)
    assert any("<title>" in w for w in warnings)


def test_validate_bimi_svg_forbidden_script_element_warns():
    svg = _VALID_BIMI_SVG.decode().replace("</svg>", "<script>alert(1)</script></svg>").encode()
    warnings = _validate_bimi_svg(svg)
    assert any("script" in w for w in warnings)


def test_validate_bimi_svg_external_reference_warns():
    svg = (
        '<?xml version="1.0"?>'
        '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" '
        'version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 100"><title>Example</title>'
        '<use xlink:href="https://evil.example/x.svg#a"/></svg>'
    ).encode()
    warnings = _validate_bimi_svg(svg)
    assert any("externe Ressource" in w for w in warnings)


def test_validate_bimi_svg_non_square_warns():
    svg = _VALID_BIMI_SVG.decode().replace('viewBox="0 0 100 100"', 'viewBox="0 0 100 50"').encode()
    warnings = _validate_bimi_svg(svg)
    assert any("quadratisch" in w for w in warnings)


def test_validate_bimi_svg_too_large_warns():
    padding = " " * (_BIMI_MAX_SVG_SIZE_BYTES + 100)
    svg = _VALID_BIMI_SVG.decode().replace("<title>", f"<title>{padding}", 1).encode()
    warnings = _validate_bimi_svg(svg)
    assert any("32" in w or "Byte" in w for w in warnings)


def test_validate_bimi_svg_valid_has_no_warnings():
    assert _validate_bimi_svg(_VALID_BIMI_SVG) == []


# --- _fingerprint() / diff_and_update_snapshot() ---


def test_fingerprint_returns_expected_shape():
    result = _clean_result()
    result.dmarc = DMARCCheckResult(
        exists=True, record="v=DMARC1; p=reject; rua=mailto:a@example.com",
        policy="reject", subdomain_policy="quarantine", pct=100,
    )
    result.spf = SPFCheckResult(exists=True, record="v=spf1 -all", lookup_count=0, lookup_limit_ok=True)
    result.dkim = [
        DKIMCheckResult(selector="default", exists=True, key_type="rsa", key_fingerprint="deadbeefcafe0000"),
        DKIMCheckResult(selector="unused", exists=False),
    ]
    result.mta_sts = MTASTSCheckResult(configured=True, policy_txt="v=STSv1; id=1")
    result.tlsrpt_dns = TLSRPTDNSCheckResult(configured=True, record="v=TLSRPTv1; rua=mailto:t@example.com")
    result.dane = DANECheckResult(configured=True, mx_hosts_with_tlsa=["mail.example.com"])
    result.bimi = BIMICheckResult(configured=True, record="v=BIMI1; l=https://example.com/logo.svg")

    assert _fingerprint(result) == {
        "dmarc_record": "v=DMARC1; p=reject; rua=mailto:a@example.com",
        "dmarc_policy": "reject",
        "dmarc_subdomain_policy": "quarantine",
        "dmarc_pct": 100,
        "spf_record": "v=spf1 -all",
        # Nur exists=True-Selektoren zählen - "unused" existiert nicht.
        "dkim": ["default:rsa:deadbeefcafe0000"],
        "mta_sts_policy_txt": "v=STSv1; id=1",
        "tlsrpt_record": "v=TLSRPTv1; rua=mailto:t@example.com",
        "dane_mx_hosts_with_tlsa": ["mail.example.com"],
        "bimi_record": "v=BIMI1; l=https://example.com/logo.svg",
    }


def test_diff_and_update_snapshot_first_check_has_no_baseline_but_persists(tmp_path):
    conn = connect(tmp_path / "dns.db")
    result = _clean_result()

    change = diff_and_update_snapshot(conn, result)
    assert change.has_baseline is False
    assert change.changes == []
    assert change.policy_weakened is False

    # Zweiter, identischer Lauf: die Baseline wurde beim ersten Mal bereits
    # angelegt, jetzt gibt es etwas zum Vergleichen, aber nichts hat sich
    # geändert.
    change2 = diff_and_update_snapshot(conn, result)
    assert change2.has_baseline is True
    assert change2.changes == []
    assert change2.policy_weakened is False
    conn.close()


def test_diff_and_update_snapshot_policy_regression_flags_weakened(tmp_path):
    conn = connect(tmp_path / "dns.db")
    reject_result = _clean_result()
    reject_result.dmarc = DMARCCheckResult(
        exists=True, record="v=DMARC1; p=reject; rua=mailto:a@example.com", policy="reject",
    )
    diff_and_update_snapshot(conn, reject_result)

    none_result = _clean_result()
    none_result.dmarc = DMARCCheckResult(
        exists=True, record="v=DMARC1; p=none; rua=mailto:a@example.com", policy="none",
    )
    change = diff_and_update_snapshot(conn, none_result)

    assert change.has_baseline is True
    assert change.policy_weakened is True
    assert any("reject" in c and "none" in c for c in change.changes)
    conn.close()


def test_diff_and_update_snapshot_non_policy_change_does_not_flag_weakened(tmp_path):
    """Ein geänderter DKIM-Key-Typ ist eine echte, meldenswerte Änderung -
    aber keine DMARC-Policy-Rückstufung, also darf policy_weakened nicht
    gesetzt werden."""
    conn = connect(tmp_path / "dns.db")
    rsa_result = _clean_result()
    rsa_result.dkim = [DKIMCheckResult(selector="default", exists=True, key_type="rsa")]
    diff_and_update_snapshot(conn, rsa_result)

    ed25519_result = _clean_result()
    ed25519_result.dkim = [DKIMCheckResult(selector="default", exists=True, key_type="ed25519")]
    change = diff_and_update_snapshot(conn, ed25519_result)

    assert change.policy_weakened is False
    assert change.changes != []
    conn.close()


def test_diff_and_update_snapshot_transient_dmarc_error_does_not_look_like_removal(tmp_path):
    """Regressionstest: ein einzelner Resolver-Timeout beim DMARC-Lookup
    (DMARCCheckResult.error) darf NICHT wie ein echtes Entfernen des
    DMARC-Eintrags aussehen - weder als "geschwächt" gemeldet werden, noch
    die gespeicherte Baseline mit dem fehlgeschlagenen None-Zustand
    überschreiben."""
    conn = connect(tmp_path / "dns.db")
    baseline = _clean_result()
    baseline.dmarc = DMARCCheckResult(
        exists=True, record="v=DMARC1; p=reject; rua=mailto:a@example.com",
        policy="reject", subdomain_policy="reject", pct=100,
    )
    diff_and_update_snapshot(conn, baseline)

    failed = _clean_result()
    failed.dmarc = DMARCCheckResult(
        exists=False, error="DNS-Abfrage fehlgeschlagen (TXT _dmarc.example.com): timeout",
        warnings=["DMARC-Abfrage fehlgeschlagen: timeout"],
    )
    change = diff_and_update_snapshot(conn, failed)

    assert change.has_baseline is True
    assert change.changes == []
    assert change.policy_weakened is False

    # Peek: get_and_replace_dns_snapshot() mit einem leeren Ersatzwert gibt
    # den zuvor gespeicherten Stand zurück, bevor es ihn selbst überschreibt.
    stored = get_and_replace_dns_snapshot(conn, "example.com", {})
    assert stored["dmarc_record"] == "v=DMARC1; p=reject; rua=mailto:a@example.com"
    assert stored["dmarc_policy"] == "reject"
    assert stored["dmarc_subdomain_policy"] == "reject"
    assert stored["dmarc_pct"] == 100
    conn.close()


def test_diff_and_update_snapshot_sp_inherits_p_when_absent_flags_weakened(tmp_path):
    """RFC 7489: ein fehlendes sp-Tag ERBT den Rang von p - eine Baseline
    mit p=reject und ohne sp bedeutet also implizit "Subdomains ebenfalls
    reject". Wird sp später explizit auf none gesetzt, ist das ein echter
    Rückschritt, auch wenn p selbst unverändert bleibt."""
    conn = connect(tmp_path / "dns.db")
    baseline = _clean_result()
    baseline.dmarc = DMARCCheckResult(
        exists=True, record="v=DMARC1; p=reject", policy="reject", subdomain_policy=None,
    )
    diff_and_update_snapshot(conn, baseline)

    weakened = _clean_result()
    weakened.dmarc = DMARCCheckResult(
        exists=True, record="v=DMARC1; p=reject; sp=none", policy="reject", subdomain_policy="none",
    )
    change = diff_and_update_snapshot(conn, weakened)

    assert change.policy_weakened is True
    conn.close()


def test_diff_and_update_snapshot_removing_redundant_sp_tag_not_flagged(tmp_path):
    """Umgekehrter Fall: ein redundantes sp=reject-Tag wird entfernt, p
    bleibt reject - sp erbt danach wieder reject von p, also KEINE
    tatsächliche Änderung, kein falscher "geschwächt"-Alarm."""
    conn = connect(tmp_path / "dns.db")
    baseline = _clean_result()
    baseline.dmarc = DMARCCheckResult(
        exists=True, record="v=DMARC1; p=reject; sp=reject", policy="reject", subdomain_policy="reject",
    )
    diff_and_update_snapshot(conn, baseline)

    unchanged = _clean_result()
    unchanged.dmarc = DMARCCheckResult(
        exists=True, record="v=DMARC1; p=reject", policy="reject", subdomain_policy=None,
    )
    change = diff_and_update_snapshot(conn, unchanged)

    assert change.policy_weakened is False
    conn.close()


def test_diff_and_update_snapshot_pct_regression_flags_weakened(tmp_path):
    """Ein sinkender pct-Wert lässt einen Großteil der Mail wieder
    unauthentifiziert durch, auch ohne Rückstufung von p/sp - das muss
    ebenfalls als geschwächt zählen (RFC 7489), nicht nur unauffällig im
    generischen 'DMARC-Eintrag geändert' verschwinden."""
    conn = connect(tmp_path / "dns.db")
    baseline = _clean_result()
    baseline.dmarc = DMARCCheckResult(
        exists=True, record="v=DMARC1; p=reject; pct=100", policy="reject", pct=100,
    )
    diff_and_update_snapshot(conn, baseline)

    reduced = _clean_result()
    reduced.dmarc = DMARCCheckResult(
        exists=True, record="v=DMARC1; p=reject; pct=10", policy="reject", pct=10,
    )
    change = diff_and_update_snapshot(conn, reduced)

    assert change.policy_weakened is True
    assert any("100" in c and "10" in c for c in change.changes)
    conn.close()


def test_check_dkim_key_fingerprint_changes_with_key_material():
    """Ein Key-Tausch bei gleichem Selektor/Key-Typ (z. B. jährliche
    DKIM-Rotation) muss sich im key_fingerprint niederschlagen, sonst ist
    er für die Änderungserkennung unsichtbar (siehe _fingerprint())."""
    record_a = _txt("v=DKIM1; k=rsa; p=AAAAB3NzaC1yc2EAAAADAQABAAAA")
    record_b = _txt("v=DKIM1; k=rsa; p=BBBBB3NzaC1yc2EAAAADAQABAAAA")
    with patch("dmarcwatch.dns_verify.subprocess.run", return_value=record_a):
        result_a = check_dkim("example.com", "selector1")
    with patch("dmarcwatch.dns_verify.subprocess.run", return_value=record_b):
        result_b = check_dkim("example.com", "selector1")

    assert result_a.key_fingerprint is not None
    assert result_a.key_fingerprint != result_b.key_fingerprint


def test_fingerprint_dkim_includes_key_fingerprint_for_rotation_detection():
    """Selector:key_type allein bleibt bei einem reinen Schlüsseltausch
    identisch (siehe check_dkim()-Docstring) - der Fingerprint muss den
    key_fingerprint mit einbeziehen, sonst ist die Rotation unsichtbar."""
    result_a = _clean_result()
    result_a.dkim = [DKIMCheckResult(selector="default", exists=True, key_type="rsa", key_fingerprint="aaaa")]
    result_b = _clean_result()
    result_b.dkim = [DKIMCheckResult(selector="default", exists=True, key_type="rsa", key_fingerprint="bbbb")]

    assert _fingerprint(result_a)["dkim"] != _fingerprint(result_b)["dkim"]


# --- SERVFAIL vs. fehlender Eintrag, Rollout-Schritte, Carry-forward ---

_SERVFAIL_FULL = _dig_result(";; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 1\n")


def _servfail_run(cmd, **kwargs):
    # `dig +short` liefert bei SERVFAIL leeres stdout mit Exit-Code 0, erst
    # die volle Ausgabe zeigt den Status.
    return _dig_result("") if "+short" in cmd else _SERVFAIL_FULL


def test_check_dmarc_servfail_sets_error_instead_of_missing_record():
    """Regressionstest: ein SERVFAIL beim DMARC-Lookup darf nicht wie ein
    entfernter Eintrag aussehen (error=None), sonst greift das Carry-forward
    in diff_and_update_snapshot() nicht und es gibt einen falschen
    "DMARC-Policy geschwächt"-Alarm."""
    with patch("dmarcwatch.spf.subprocess.run", side_effect=_servfail_run):
        result = check_dmarc("example.com")
    assert result.exists is False
    assert result.error is not None
    assert "SERVFAIL" in result.error


def test_servfail_dmarc_lookup_does_not_flag_weakened(tmp_path):
    conn = connect(tmp_path / "dns.db")
    baseline = _clean_result()
    baseline.dmarc = DMARCCheckResult(exists=True, record="v=DMARC1; p=reject", policy="reject", pct=100)
    diff_and_update_snapshot(conn, baseline)

    blip = _clean_result()
    with patch("dmarcwatch.spf.subprocess.run", side_effect=_servfail_run):
        blip.dmarc = check_dmarc("example.com")
    change = diff_and_update_snapshot(conn, blip)

    assert change.policy_weakened is False
    assert change.changes == []
    conn.close()


def test_check_dkim_servfail_sets_error():
    with patch("dmarcwatch.dns_verify.subprocess.run", side_effect=_servfail_run):
        result = check_dkim("example.com", "default")
    assert result.exists is False
    assert result.error is not None


def test_check_dkim_missing_record_has_no_error():
    with patch("dmarcwatch.dns_verify.subprocess.run", return_value=_dig_result("")):
        result = check_dkim("example.com", "default")
    assert result.exists is False
    assert result.error is None


def _dmarc(policy: str, pct: int | None) -> DMARCCheckResult:
    record = f"v=DMARC1; p={policy}" + (f"; pct={pct}" if pct is not None else "")
    return DMARCCheckResult(exists=True, record=record, policy=policy, pct=pct)


def test_recommended_rollout_steps_are_not_flagged_weakened(tmp_path):
    """Regressionstest: genau die von report._next_dmarc_rollout_step
    empfohlenen Schritte (none -> quarantine;pct=25, quarantine;pct=100 ->
    reject;pct=25) senken pct, sind aber reine Verschärfungen - laut RFC
    7489 bekommt der nicht erfasste Rest die nächstniedrigere Policy."""
    for old, new in [
        (("none", None), ("quarantine", 25)),
        (("quarantine", 100), ("reject", 25)),
        (("reject", 25), ("reject", 50)),
    ]:
        conn = connect(tmp_path / f"dns-{old[0]}-{new[0]}-{new[1]}.db")
        before = _clean_result()
        before.dmarc = _dmarc(*old)
        diff_and_update_snapshot(conn, before)

        after = _clean_result()
        after.dmarc = _dmarc(*new)
        change = diff_and_update_snapshot(conn, after)

        assert change.policy_weakened is False, (old, new)
        conn.close()


def test_pct_drop_within_same_policy_level_still_flags_weakened(tmp_path):
    conn = connect(tmp_path / "dns.db")
    before = _clean_result()
    before.dmarc = _dmarc("quarantine", 50)
    diff_and_update_snapshot(conn, before)

    after = _clean_result()
    after.dmarc = _dmarc("quarantine", 25)
    change = diff_and_update_snapshot(conn, after)

    assert change.policy_weakened is True
    assert any("pct=50->25" in c for c in change.changes)
    conn.close()


def test_transient_dkim_error_is_carried_forward_not_reported_as_removal(tmp_path):
    """Wie beim DMARC-Lookup: ein Timeout beim DKIM-Lookup darf weder als
    "Selektor entfernt" gemeldet noch so gespeichert werden (sonst im
    nächsten Lauf zusätzlich ein falsches "wieder da")."""
    conn = connect(tmp_path / "dns.db")
    baseline = _clean_result()
    baseline.dkim = [DKIMCheckResult(selector="default", exists=True, key_type="rsa", key_fingerprint="aa")]
    diff_and_update_snapshot(conn, baseline)

    blip = _clean_result()
    blip.dkim = [DKIMCheckResult(selector="default", exists=False, error="timeout")]
    assert diff_and_update_snapshot(conn, blip).changes == []
    assert diff_and_update_snapshot(conn, baseline).changes == []
    conn.close()


def test_check_dane_mx_lookup_failure_sets_error():
    with patch("dmarcwatch.dns_verify._dig", side_effect=SPFResolutionError("Zeitüberschreitung")):
        result = check_dane("example.com")
    assert result.configured is False
    assert result.error is not None
