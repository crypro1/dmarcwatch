"""cmd_tls_report() --json: Ausgabeformat für die Menüleisten-App
(TLSReportView.swift) - die parst das statt die menschenlesbare
Textausgabe, deshalb muss die Feldstruktur stabil sein."""
import argparse
import json

from dmarcwatch import cli
from dmarcwatch.config import Config, db_path
from dmarcwatch.store import connect, ingest_tls_report
from dmarcwatch.tls_parser import parse_tls_report


def _args(**overrides):
    defaults = dict(days=7, json=False)
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def _sample(policy_domain: str = "example.com") -> bytes:
    return json.dumps(
        {
            "organization-name": "Mail Provider",
            "date-range": {
                "start-datetime": "2026-08-21T00:00:00Z",
                "end-datetime": "2026-08-22T00:00:00Z",
            },
            "report-id": "report-id-1",
            "policies": [
                {
                    "policy": {
                        "policy-type": "sts",
                        "policy-string": ["version: STSv1"],
                        "policy-domain": policy_domain,
                        "mx-host": ["mx1.example.com"],
                    },
                    "summary": {"total-successful-session-count": 10, "total-failure-session-count": 1},
                    "failure-details": [
                        {"result-type": "certificate-expired", "failed-session-count": 1}
                    ],
                }
            ],
        }
    ).encode("utf-8")


def _seed(monkeypatch, tmp_path, policy_domain: str = "example.com") -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    conn = connect(db_path())
    config = Config.from_dict({"own_domains": [policy_domain]})
    report = parse_tls_report(_sample(policy_domain), 2 * 1024 * 1024)
    ingest_tls_report(conn, report, config)
    conn.close()


def test_json_output_structure(tmp_path, monkeypatch, capsys):
    _seed(monkeypatch, tmp_path)

    result = cli.cmd_tls_report(_args(json=True))

    assert result == 1  # es gibt einen Fehlschlag im Beispiel
    output = json.loads(capsys.readouterr().out)
    assert output["total_failure_count"] == 1
    assert len(output["policies"]) == 1
    entry = output["policies"][0]
    assert entry["policy_domain"] == "example.com"
    assert entry["policy_type"] == "sts"
    assert entry["successful_session_count"] == 10
    assert entry["failure_count"] == 1
    assert entry["failure_result_types"] == ["certificate-expired"]


def test_table_output_when_json_not_set(tmp_path, monkeypatch, capsys):
    _seed(monkeypatch, tmp_path)

    result = cli.cmd_tls_report(_args(json=False))

    assert result == 1
    out = capsys.readouterr().out
    assert "example.com" in out
    assert "certificate-expired" in out


def test_no_reports_returns_zero(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    conn = connect(db_path())
    conn.close()

    result = cli.cmd_tls_report(_args(json=True))

    assert result == 0
    output = json.loads(capsys.readouterr().out)
    assert output["policies"] == []
    assert output["total_failure_count"] == 0
