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
from dmarcwatch.store import connect, ingest_report


def _xml() -> str:
    # Relativ zu "jetzt" statt einem festen Datum - ein fest eingetragenes
    # Datum fällt nach genug verstrichener Zeit irgendwann außerhalb des
    # Abfragefensters (genau das ist test_cli_tls_report.py real passiert).
    end = int(time.time()) - 3600
    begin = end - 3600
    return f"""<?xml version="1.0"?>
<feedback>
<report_metadata><org_name>Enterprise Outlook</org_name><report_id>stats-test-1</report_id>
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
