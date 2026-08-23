import json
from pathlib import Path

from dmarcwatch.config import Config
from dmarcwatch.parser import parse_aggregate_report
from dmarcwatch.store import (
    IngestStatus,
    TLSIngestStatus,
    connect,
    get_known_dkim_selectors,
    ingest_report,
    ingest_tls_report,
    query_records,
    query_tls_failure_details,
    query_tls_policies,
)
from dmarcwatch.tls_parser import parse_tls_report

FIXTURES = Path(__file__).parent / "fixtures"
MAX_SIZE = 10 * 1024 * 1024
MAX_JSON_SIZE = 2 * 1024 * 1024


def _config() -> Config:
    return Config.from_dict(
        {
            "own_domains": ["example.com"],
            "own_ip_networks": ["192.0.2.0/24", "2001:db8:1::/48"],
        }
    )


def _load(name: str):
    return parse_aggregate_report((FIXTURES / name).read_bytes(), MAX_SIZE)


def _tls_sample(**overrides) -> dict:
    sample = {
        "organization-name": "Mail Provider",
        "date-range": {
            "start-datetime": "2026-08-21T00:00:00Z",
            "end-datetime": "2026-08-22T00:00:00Z",
        },
        "contact-info": "tls-reports@provider.example",
        "report-id": "report-id-12345",
        "policies": [
            {
                "policy": {
                    "policy-type": "sts",
                    "policy-string": ["version: STSv1", "mode: testing"],
                    "policy-domain": "example.com",
                    "mx-host": ["mx1.example.com"],
                },
                "summary": {"total-successful-session-count": 42, "total-failure-session-count": 1},
                "failure-details": [
                    {
                        "result-type": "certificate-expired",
                        "sending-mta-ip": "198.51.100.1",
                        "failed-session-count": 1,
                    }
                ],
            }
        ],
    }
    sample.update(overrides)
    return sample


def _load_tls(data: dict):
    return parse_tls_report(json.dumps(data).encode("utf-8"), MAX_JSON_SIZE)


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


def test_get_known_dkim_selectors_reads_real_selectors_from_reports(tmp_path):
    """Für `dmarcwatch verify-dns` (dns_verify.py): Selektoren werden aus
    bereits abgerufenen, echten Reports gelesen statt geraten."""
    conn = connect(tmp_path / "dmarc.sqlite")
    config = _config()
    ingest_report(conn, _load("microsoft_two_records.xml"), config)

    selectors = get_known_dkim_selectors(conn, "example.com")
    assert selectors == ["default"]


def test_get_known_dkim_selectors_empty_for_unknown_domain(tmp_path):
    conn = connect(tmp_path / "dmarc.sqlite")
    config = _config()
    ingest_report(conn, _load("microsoft_two_records.xml"), config)

    assert get_known_dkim_selectors(conn, "never-seen.example") == []


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


def test_ingest_tls_report_and_dedup(tmp_path):
    conn = connect(tmp_path / "dmarc.sqlite")
    config = _config()
    report = _load_tls(_tls_sample())

    result1 = ingest_tls_report(conn, report, config)
    assert result1.status == TLSIngestStatus.INSERTED
    assert result1.total_failure_count == 1

    result2 = ingest_tls_report(conn, report, config)
    assert result2.status == TLSIngestStatus.DUPLICATE

    rows = query_tls_policies(conn, since_ts=0, until_ts=2_000_000_000)
    assert len(rows) == 1
    assert rows[0]["policy_domain"] == "example.com"
    assert rows[0]["failure_count"] == 1
    assert rows[0]["successful_session_count"] == 42
    assert json.loads(rows[0]["mx_host_json"]) == ["mx1.example.com"]

    failure_rows = query_tls_failure_details(conn, rows[0]["id"])
    assert len(failure_rows) == 1
    assert failure_rows[0]["result_type"] == "certificate-expired"
    assert failure_rows[0]["sending_mta_ip"] == "198.51.100.1"


def test_tls_report_foreign_domain_rejected(tmp_path):
    conn = connect(tmp_path / "dmarc.sqlite")
    config = _config()
    sample = _tls_sample()
    sample["policies"][0]["policy"]["policy-domain"] = "not-mine.example"
    report = _load_tls(sample)

    result = ingest_tls_report(conn, report, config)
    assert result.status == TLSIngestStatus.REJECTED_FOREIGN_DOMAIN
    assert query_tls_policies(conn, since_ts=0, until_ts=2_000_000_000) == []


def test_tls_report_mixed_domains_keeps_only_own(tmp_path):
    """Ein Report kann laut RFC 8460 mehrere policies-Einträge für
    verschiedene Domains enthalten (z. B. bei einem Anbieter, der mehrere
    Kunden im selben Bericht zusammenfasst) - nur die eigene(n) Domain(s)
    werden gespeichert, der Report wird nicht komplett verworfen."""
    conn = connect(tmp_path / "dmarc.sqlite")
    config = _config()
    sample = _tls_sample()
    foreign_policy = json.loads(json.dumps(sample["policies"][0]))
    foreign_policy["policy"]["policy-domain"] = "not-mine.example"
    sample["policies"].append(foreign_policy)
    report = _load_tls(sample)

    result = ingest_tls_report(conn, report, config)
    assert result.status == TLSIngestStatus.INSERTED

    rows = query_tls_policies(conn, since_ts=0, until_ts=2_000_000_000)
    assert len(rows) == 1
    assert rows[0]["policy_domain"] == "example.com"
