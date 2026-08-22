from pathlib import Path

from dmarcwatch.config import Config
from dmarcwatch.parser import parse_aggregate_report
from dmarcwatch.store import IngestStatus, connect, ingest_report, query_records

FIXTURES = Path(__file__).parent / "fixtures"
MAX_SIZE = 10 * 1024 * 1024


def _config() -> Config:
    return Config.from_dict(
        {
            "own_domains": ["example.com"],
            "own_ip_networks": ["192.0.2.0/24", "2001:db8:1::/48"],
        }
    )


def _load(name: str):
    return parse_aggregate_report((FIXTURES / name).read_bytes(), MAX_SIZE)


def test_ingest_and_dedup(tmp_path):
    conn = connect(tmp_path / "dmarc.sqlite")
    config = _config()
    report = _load("ses_single_pass.xml")

    result1 = ingest_report(conn, report, config)
    assert result1.status == IngestStatus.INSERTED
    assert result1.flagged_count == 0

    result2 = ingest_report(conn, report, config)
    assert result2.status == IngestStatus.DUPLICATE

    rows = query_records(conn, since_ts=0, until_ts=2_000_000_000)
    assert len(rows) == 1


def test_foreign_domain_rejected(tmp_path):
    conn = connect(tmp_path / "dmarc.sqlite")
    config = _config()
    report = _load("foreign_domain.xml")

    result = ingest_report(conn, report, config)
    assert result.status == IngestStatus.REJECTED_FOREIGN_DOMAIN

    rows = query_records(conn, since_ts=0, until_ts=2_000_000_000)
    assert len(rows) == 0


def test_microsoft_report_flags_auth_failure_on_own_ip(tmp_path):
    conn = connect(tmp_path / "dmarc.sqlite")
    config = _config()
    report = _load("microsoft_two_records.xml")

    result = ingest_report(conn, report, config)
    assert result.status == IngestStatus.INSERTED
    assert result.total_records == 2
    assert result.flagged_count == 1

    rows = query_records(conn, since_ts=0, until_ts=2_000_000_000, only_flagged=True)
    assert len(rows) == 1
    flagged = rows[0]
    assert flagged["source_ip"] == "192.0.2.99"
    assert "own_ip_auth_fail" in flagged["flag_reasons"]
    assert "disposition_not_none" in flagged["flag_reasons"]


def test_unknown_ip_is_flagged(tmp_path):
    conn = connect(tmp_path / "dmarc.sqlite")
    config = _config()
    report = _load("unknown_ip.xml")

    result = ingest_report(conn, report, config)
    assert result.flagged_count == 1

    rows = query_records(conn, since_ts=0, until_ts=2_000_000_000, only_flagged=True)
    assert rows[0]["flag_reasons"] == "unknown_ip"


def test_injection_field_stored_verbatim_and_flagged(tmp_path):
    conn = connect(tmp_path / "dmarc.sqlite")
    config = _config()
    report = _load("injection_field.xml")

    result = ingest_report(conn, report, config)
    assert result.status == IngestStatus.INSERTED
    assert result.flagged_count == 1

    rows = query_records(conn, since_ts=0, until_ts=2_000_000_000)
    assert "|" in rows[0]["header_from"]
    assert "bash=" in rows[0]["header_from"]
