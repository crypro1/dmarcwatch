"""to_json_dict(): strukturierte, nach Tag gruppierte Ausgabe für native
Konsumenten (Swift-Menüleisten-App), Gegenstück zu render_swiftbar()."""
import json
from pathlib import Path

from dmarcwatch.config import Config
from dmarcwatch.parser import parse_aggregate_report
from dmarcwatch.report import collect_rows, to_json_dict
from dmarcwatch.store import connect, ingest_report

FIXTURES = Path(__file__).parent / "fixtures"


def _config() -> Config:
    return Config.from_dict(
        {"own_domains": ["example.com"], "own_ip_networks": ["192.0.2.0/24", "2001:db8:1::/48"]}
    )


def test_grouping_and_counts(tmp_path):
    conn = connect(tmp_path / "dmarc.sqlite")
    config = _config()
    xml = (FIXTURES / "microsoft_two_records.xml").read_bytes()
    report = parse_aggregate_report(xml, config.max_xml_size_bytes)
    ingest_report(conn, report, config)

    rows = collect_rows(conn, since_ts=0, until_ts=2_000_000_000)
    data = to_json_dict(rows, days=7)

    assert data["total_count"] == 2
    assert data["flagged_count"] == 1
    assert len(data["days_grouped"]) == 1
    day = data["days_grouped"][0]
    assert day["flagged_count"] == 1
    assert len(day["records"]) == 2

    flagged_record = next(r for r in day["records"] if r["is_flagged"])
    assert flagged_record["source_ip"] == "192.0.2.99"
    assert "SPF+DKIM fehlgeschlagen (eigene IP)" in flagged_record["flag_labels"]
    assert "Disposition ≠ none" in flagged_record["flag_labels"]


def test_output_is_valid_json_even_with_injection_payload(tmp_path):
    conn = connect(tmp_path / "dmarc.sqlite")
    config = _config()
    xml = (FIXTURES / "injection_field.xml").read_bytes()
    report = parse_aggregate_report(xml, config.max_xml_size_bytes)
    ingest_report(conn, report, config)

    rows = collect_rows(conn, since_ts=0, until_ts=2_000_000_000)
    data = to_json_dict(rows, days=7)

    # json.dumps darf nicht scheitern, und das Ergebnis muss sich wieder
    # sauber parsen lassen - keine kaputte Struktur durch Sonderzeichen.
    encoded = json.dumps(data)
    reparsed = json.loads(encoded)
    assert reparsed == data

    record = data["days_grouped"][0]["records"][0]
    assert "|" not in record["org_name"]


def test_empty_range_produces_zero_counts(tmp_path):
    conn = connect(tmp_path / "dmarc.sqlite")
    data = to_json_dict([], days=7)
    assert data["total_count"] == 0
    assert data["flagged_count"] == 0
    assert data["days_grouped"] == []
    conn.close()
