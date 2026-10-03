"""cmd_stats() --json: Ausgabeformat für eine mögliche native Statistik-
Ansicht - mirrors test_cli_tls_report.py. Prüft die CLI-Verdrahtung
(echter Ingest -> collect_rows -> report.py-Berechnungen), die reinen
Berechnungen selbst sind bereits in test_stats.py abgedeckt."""
import argparse
import json
import time

from dmarcwatch import cli
from dmarcwatch.config import Config, db_path
from dmarcwatch.parser import parse_aggregate_report
from dmarcwatch.report import DMARCReadiness
from dmarcwatch.store import connect, ingest_report


def _xml() -> str:
    # Relativ zu "jetzt" statt einem festen Datum - ein fest eingetragenes
    # Datum fällt nach genug verstrichener Zeit irgendwann außerhalb des
    # Abfragefensters (genau das ist test_cli_tls_report.py real passiert).
    end = int(time.time()) - 3600
    begin = end - 3600
    return f"""<?xml version="1.0"?>
<feedback>
<report_metadata><org_name>Enterprise Outlook</org_name><email>dmarcreport@microsoft.com</email>
<report_id>stats-test-1</report_id>
<date_range><begin>{begin}</begin><end>{end}</end></date_range></report_metadata>
<policy_published><domain>example.com</domain><p>quarantine</p><pct>100</pct></policy_published>
<record>
<row><source_ip>192.0.2.1</source_ip><count>1</count>
<policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
<identifiers><header_from>example.com</header_from></identifiers>
</record>
<record>
<row><source_ip>203.0.113.5</source_ip><count>1</count>
<policy_evaluated><disposition>quarantine</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row>
<identifiers><header_from>example.com</header_from></identifiers>
</record>
</feedback>"""


def _args(**overrides):
    defaults = dict(days=90, json=False)
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def _seed(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    config = Config.from_dict({"own_domains": ["example.com"], "own_ip_networks": ["192.0.2.0/24"]})
    conn = connect(db_path())
    report = parse_aggregate_report(_xml().encode(), config.max_xml_size_bytes)
    ingest_report(conn, report, config)
    conn.close()


def test_json_output_structure(tmp_path, monkeypatch, capsys):
    _seed(tmp_path, monkeypatch)

    result = cli.cmd_stats(_args(json=True))

    assert result == 0
    output = json.loads(capsys.readouterr().out)
    assert output["days"] == 90
    assert len(output["daily"]) == 1
    assert output["daily"][0]["clean_count"] == 1
    assert output["daily"][0]["flagged_count"] == 1
    assert len(output["dmarc_readiness"]) == 1
    readiness = output["dmarc_readiness"][0]
    assert readiness["domain"] == "example.com"
    assert readiness["current_policy"] == "quarantine"
    # 203.0.113.5 ist eine unbekannte IP (nicht in own_ip_networks), also
    # unknown_ip - zählt nicht gegen die Bereitschaft.
    assert readiness["unknown_ip_failures"] == 1
    assert readiness["own_ip_auth_failures"] == 0
    # Der Report ist real erst ~2 Stunden alt, obwohl --days 90 angefragt
    # wurde - observed_days muss das tatsächliche Alter widerspiegeln
    # (hier < 1 Tag, auf 1 gerundet), nicht das angefragte Fenster selbst,
    # deshalb noch nicht bereit trotz 0 own_ip_auth_failures.
    assert readiness["observed_days"] == 1
    assert readiness["ready_for_next_step"] is False
    assert output["mta_sts_readiness"] == []


def test_table_output_when_json_not_set(tmp_path, monkeypatch, capsys):
    _seed(tmp_path, monkeypatch)

    result = cli.cmd_stats(_args(json=False))

    assert result == 0
    out = capsys.readouterr().out
    assert "example.com" in out
    assert "Noch nicht bereit" in out


def _readiness(**overrides) -> DMARCReadiness:
    defaults = dict(
        domain="example.com", current_policy="quarantine", current_pct=100,
        total_count=20, unknown_ip_failures=0, own_ip_auth_failures=0,
        avg_daily_volume=2.0, recommended_observation_days=7, observed_days=14,
        clean_days=14, last_failure_date=None, has_reporting_gap=False,
        reporting_gap_days=0, next_recommended_policy="reject", next_recommended_pct=100,
        fully_enforced=False, ready_for_next_step=True, needs_recheck=False,
        excluded_count=0, excluded_reporters=[], current_sp="reject",
        next_step_pct_adjusted_for_sp=True, sp_behind_recommendation=None,
    )
    defaults.update(overrides)
    return DMARCReadiness(**defaults)


def test_pct_adjusted_for_sp_note_printed_once_when_ready(tmp_path, monkeypatch, capsys):
    # Regression: die "pct-Zwischenstufe uebersprungen..."-Meldung haengt
    # NUR von next_step_pct_adjusted_for_sp ab, nicht davon, welcher der
    # fully_enforced/ready_for_next_step/sonst-Zweige gefeuert hat - sie
    # darf pro Domain nur einmal erscheinen, nicht einmal pro Zweig.
    monkeypatch.setenv("HOME", str(tmp_path))
    conn = connect(db_path())
    conn.close()
    monkeypatch.setattr(cli, "compute_dmarc_readiness", lambda *a, **kw: [_readiness(ready_for_next_step=True)])
    monkeypatch.setattr(cli, "compute_mta_sts_readiness", lambda *a, **kw: [])

    result = cli.cmd_stats(_args(json=False))

    assert result == 0
    out = capsys.readouterr().out
    assert out.count("pct-Zwischenstufe übersprungen") == 1


def test_pct_adjusted_for_sp_note_printed_once_when_not_ready(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    conn = connect(db_path())
    conn.close()
    monkeypatch.setattr(
        cli, "compute_dmarc_readiness",
        lambda *a, **kw: [_readiness(ready_for_next_step=False, clean_days=1, own_ip_auth_failures=1, last_failure_date="2026-01-01")],
    )
    monkeypatch.setattr(cli, "compute_mta_sts_readiness", lambda *a, **kw: [])

    result = cli.cmd_stats(_args(json=False))

    assert result == 0
    out = capsys.readouterr().out
    assert out.count("pct-Zwischenstufe übersprungen") == 1


def test_no_reports_returns_empty_structure(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    conn = connect(db_path())
    conn.close()

    result = cli.cmd_stats(_args(json=True))

    assert result == 0
    output = json.loads(capsys.readouterr().out)
    assert output["daily"] == []
    assert output["dmarc_readiness"] == []
    assert output["mta_sts_readiness"] == []


def test_text_output_sanitizes_attacker_controlled_report_fields(tmp_path, monkeypatch, capsys):
    """org_name (ausgeschlossene Reporter) und TLS-organization-name kommen
    aus unauthentifizierten Reports - JSON erlaubt echte ESC-Zeichen
    (\\u001b) und Zeilenumbrüche, die sonst ungefiltert im Terminal landen
    (Bildschirm löschen, gefälschte Statuszeilen)."""
    from dmarcwatch.store import ingest_tls_report
    from dmarcwatch.tls_parser import parse_tls_report

    _seed(tmp_path, monkeypatch)
    day = time.strftime("%Y-%m-%dT00:00:00Z", time.gmtime(time.time() - 86400))
    report = {
        "organization-name": "\u001b[2J\u001b[31mZZ\n  Bereit für mode=enforce, falls noch nicht aktiv.",
        "contact-info": "x@q.invalid",
        "report-id": "tls-injection-1",
        "date-range": {"start-datetime": day, "end-datetime": day},
        "policies": [
            {
                "policy": {"policy-type": "sts", "policy-domain": "example.com"},
                "summary": {"total-successful-session-count": 5, "total-failure-session-count": 0},
            }
        ],
    }
    config = Config.from_dict({"own_domains": ["example.com"]})
    conn = connect(db_path())
    ingest_tls_report(conn, parse_tls_report(json.dumps(report).encode(), 10**6), config)
    conn.close()

    cli.cmd_stats(_args(json=False))
    out = capsys.readouterr().out

    assert "\x1b" not in out
    assert "\n  Bereit für mode=enforce, falls noch nicht aktiv." not in out
