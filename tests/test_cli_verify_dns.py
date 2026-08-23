"""cmd_verify_dns() --json: Ausgabeformat für die Menüleisten-App
(DNSVerifyView.swift) - die parst das statt die menschenlesbare
Textausgabe, deshalb muss die Feldstruktur stabil sein."""
import argparse
import json
import time
from unittest.mock import patch

from dmarcwatch import cli
from dmarcwatch.config import read_dns_check_result, write_config
from dmarcwatch.dns_verify import (
    DKIMCheckResult,
    DMARCCheckResult,
    DomainVerification,
    MTASTSCheckResult,
    TLSRPTDNSCheckResult,
    WildcardSPFCheckResult,
)
from dmarcwatch.spf import SPFCheckResult


def _args(**overrides):
    defaults = dict(domain=None, json=False)
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def _sample_result(domain: str) -> DomainVerification:
    return DomainVerification(
        domain=domain,
        dmarc=DMARCCheckResult(
            exists=True, record="v=DMARC1; p=reject; rua=mailto:a@example.com",
            policy="reject", subdomain_policy=None, pct=100,
            rua="mailto:a@example.com", ruf=None, adkim="r", aspf="r", warnings=[],
        ),
        spf=SPFCheckResult(
            exists=True, record="v=spf1 ip4:203.0.113.0/24 -all",
            lookup_count=1, lookup_limit_ok=True, warnings=[],
        ),
        dkim=[DKIMCheckResult(selector="default", exists=True, key_type="rsa", warnings=[])],
        mta_sts=MTASTSCheckResult(configured=False),
        tlsrpt_dns=TLSRPTDNSCheckResult(configured=False),
        wildcard_spf=WildcardSPFCheckResult(configured=False),
    )


def test_json_output_structure(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    write_config({"own_domains": ["example.com"]})

    with patch.object(cli, "verify_domain", return_value=_sample_result("example.com")):
        result = cli.cmd_verify_dns(_args(json=True))

    assert result == 0
    output = json.loads(capsys.readouterr().out)
    assert len(output) == 1
    entry = output[0]
    assert entry["domain"] == "example.com"
    assert entry["dmarc"]["policy"] == "reject"
    assert entry["dmarc"]["rua"] == "mailto:a@example.com"
    assert entry["spf"]["lookup_count"] == 1
    assert entry["dkim"] == [
        {"selector": "default", "exists": True, "key_type": "rsa", "warnings": []}
    ]


def test_explicit_domain_overrides_config(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    write_config({"own_domains": ["configured.example"]})

    with patch.object(cli, "verify_domain", return_value=_sample_result("other.example")) as mock_verify:
        cli.cmd_verify_dns(_args(domain="other.example", json=True))

    mock_verify.assert_called_once()
    assert mock_verify.call_args[0][1] == "other.example"


def test_no_domain_and_no_config_fails_clearly(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    write_config({"own_domains": []})

    result = cli.cmd_verify_dns(_args())
    assert result == 2


def test_result_is_persisted_for_menubar_app(tmp_path, monkeypatch):
    """Jeder verify-dns-Lauf (Klick auf "DNS prüfen…" oder Terminal) muss
    das Ergebnis speichern, damit die Menüleisten-App den letzten bekannten
    Stand zeigen kann (Rot-Färbung/Details), ohne selbst eine DNS-Abfrage
    zu machen - siehe config.read_dns_check_result()."""
    monkeypatch.setenv("HOME", str(tmp_path))
    write_config({"own_domains": ["example.com"]})

    with patch.object(cli, "verify_domain", return_value=_sample_result("example.com")):
        cli.cmd_verify_dns(_args(json=True))

    stored = read_dns_check_result()
    assert stored is not None
    assert stored["checked_at"] == time.strftime("%Y-%m-%d")
    assert len(stored["domains"]) == 1
    assert stored["domains"][0]["domain"] == "example.com"
    assert stored["domains"][0]["has_warnings"] is False


def test_persisted_result_flags_warnings(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    write_config({"own_domains": ["example.com"]})
    result = _sample_result("example.com")
    result.dmarc.warnings.append("p=none: rein beobachtend")

    with patch.object(cli, "verify_domain", return_value=result):
        cli.cmd_verify_dns(_args(json=True))

    stored = read_dns_check_result()
    assert stored["domains"][0]["has_warnings"] is True
