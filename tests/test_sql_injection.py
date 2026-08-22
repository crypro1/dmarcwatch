"""Report-Felder sind unvertrauenswürdig (Spezifikation 4.5) - ein
SQL-Injection-Payload als org_name/header_from muss folgenlos als reiner
Text landen, nicht als SQL interpretiert werden."""
from dmarcwatch.config import Config
from dmarcwatch.parser import parse_aggregate_report
from dmarcwatch.store import IngestStatus, connect, ingest_report

MAX_SIZE = 10 * 1024 * 1024

INJECTION_XML = """<?xml version="1.0"?>
<feedback>
<report_metadata>
<org_name>evil'; DROP TABLE reports; --</org_name>
<report_id>sqli-test-1</report_id>
<date_range><begin>1700000000</begin><end>1700086399</end></date_range>
</report_metadata>
<policy_published><domain>example.com</domain><p>none</p></policy_published>
<record>
<row><source_ip>192.0.2.1</source_ip><count>1</count>
<policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
<identifiers><header_from>example.com'); DELETE FROM reports WHERE ('1'='1</header_from></identifiers>
</record>
</feedback>"""


def _config() -> Config:
    return Config.from_dict({"own_domains": ["example.com"], "own_ip_networks": ["192.0.2.0/24"]})


def test_sql_injection_payload_stored_as_literal_text_not_executed(tmp_path):
    conn = connect(tmp_path / "dmarc.sqlite")
    config = _config()

    report = parse_aggregate_report(INJECTION_XML.encode(), MAX_SIZE)
    result = ingest_report(conn, report, config)
    assert result.status == IngestStatus.INSERTED

    # Ein erfolgreicher Injection-Angriff hätte die Tabelle gelöscht.
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "reports" in tables
    assert "records" in tables

    row = conn.execute("SELECT org_name FROM reports WHERE report_id = 'sqli-test-1'").fetchone()
    assert row[0] == "evil'; DROP TABLE reports; --"

    count = conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
    assert count == 1
