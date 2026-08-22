"""cmd_verify_dns() --json: Ausgabeformat für die Menüleisten-App
(DNSVerifyView.swift) - die parst das statt die menschenlesbare
Textausgabe, deshalb muss die Feldstruktur stabil sein."""
import argparse
import json
from unittest.mock import patch

from dmarcwatch import cli
from dmarcwatch.config import write_config
from dmarcwatch.dns_verify import DKIMCheckResult, DMARCCheckResult, DomainVerification
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
