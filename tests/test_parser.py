from pathlib import Path

import pytest

from dmarcwatch.parser import ReportParseError, parse_aggregate_report

FIXTURES = Path(__file__).parent / "fixtures"
MAX_SIZE = 10 * 1024 * 1024


def _load(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def test_ses_single_record_all_pass():
    report = parse_aggregate_report(_load("ses_single_pass.xml"), MAX_SIZE)
    assert report.metadata.org_name == "Amazon SES"
    assert report.metadata.report_id == "ses-report-0001"
    assert report.policy_published.domain == "example.com"
    assert len(report.records) == 1
    rec = report.records[0]
    assert rec.source_ip == "192.0.2.12"
    assert rec.count == 3
    assert rec.policy_evaluated.disposition == "none"
    assert rec.policy_evaluated.dkim == "pass"
    assert rec.policy_evaluated.spf == "pass"


def test_microsoft_two_records_crlf_and_field_order():
    report = parse_aggregate_report(_load("microsoft_two_records.xml"), MAX_SIZE)
    assert report.metadata.org_name == "Microsoft"
    assert report.metadata.report_id == "msft-report-0002"
    assert len(report.records) == 2

    ok_rec, bad_rec = report.records
    assert ok_rec.source_ip == "192.0.2.20"
    assert ok_rec.policy_evaluated.dkim == "pass"

    assert bad_rec.source_ip == "192.0.2.99"
    assert bad_rec.policy_evaluated.spf == "fail"
    assert bad_rec.policy_evaluated.dkim == "fail"
    assert bad_rec.policy_evaluated.disposition == "quarantine"


def test_unknown_ip_report_parses():
    report = parse_aggregate_report(_load("unknown_ip.xml"), MAX_SIZE)
    assert report.records[0].source_ip == "203.0.113.9"


def test_foreign_domain_report_parses_but_is_not_filtered_here():
    # Die Domainprüfung passiert beim Ingest (store.py), nicht im Parser.
    report = parse_aggregate_report(_load("foreign_domain.xml"), MAX_SIZE)
    assert report.policy_published.domain == "example.org"


def test_injection_field_values_are_parsed_as_plain_text():
    report = parse_aggregate_report(_load("injection_field.xml"), MAX_SIZE)
    assert "|" in report.metadata.org_name
    assert "bash=" in report.records[0].identifiers.header_from


def test_xxe_attack_is_rejected():
    with pytest.raises(ReportParseError):
        parse_aggregate_report(_load("xxe_attack.xml"), MAX_SIZE)


def test_billion_laughs_is_rejected():
    with pytest.raises(ReportParseError):
        parse_aggregate_report(_load("billion_laughs.xml"), MAX_SIZE)


def test_truncated_xml_is_rejected():
    with pytest.raises(ReportParseError):
        parse_aggregate_report(_load("truncated.xml"), MAX_SIZE)


def test_oversized_xml_is_rejected():
    data = _load("ses_single_pass.xml")
    with pytest.raises(ReportParseError):
        parse_aggregate_report(data, max_size_bytes=10)


def test_empty_bytes_rejected():
    with pytest.raises(ReportParseError):
        parse_aggregate_report(b"", MAX_SIZE)


def test_invalid_ip_in_record_is_skipped_not_fatal():
    xml = _load("ses_single_pass.xml").decode("utf-8").replace(
        "192.0.2.12", "not-an-ip"
    ).encode("utf-8")
    with pytest.raises(ReportParseError):
        # Nach dem Entfernen der einzigen gültigen IP bleibt kein Record übrig.
        parse_aggregate_report(xml, MAX_SIZE)


def test_implausible_timestamp_rejected():
    xml = _load("ses_single_pass.xml").decode("utf-8").replace(
        "1700000000", "99999999999999"
    ).encode("utf-8")
    with pytest.raises(ReportParseError):
        parse_aggregate_report(xml, MAX_SIZE)


def _build_report_with_n_records(n: int) -> bytes:
    record_tpl = (
        "<record><row><source_ip>192.0.2.{i}</source_ip><count>1</count>"
        "<policy_evaluated><disposition>none</disposition><dkim>pass</dkim>"
        "<spf>pass</spf></policy_evaluated></row>"
        "<identifiers><header_from>example.com</header_from></identifiers></record>"
    )
    records = "".join(record_tpl.format(i=i % 255) for i in range(n))
    return (
        '<?xml version="1.0"?><feedback>'
        "<report_metadata><org_name>test</org_name><report_id>r-1</report_id>"
        "<date_range><begin>1700000000</begin><end>1700086399</end></date_range>"
        "</report_metadata>"
        "<policy_published><domain>example.com</domain><p>none</p></policy_published>"
        + records
        + "</feedback>"
    ).encode()


def test_report_at_record_limit_is_accepted():
    xml = _build_report_with_n_records(10000)
    report = parse_aggregate_report(xml, max_size_bytes=50 * 1024 * 1024, max_records=10000)
    assert len(report.records) == 10000


def test_report_over_record_limit_is_rejected_wholesale():
    xml = _build_report_with_n_records(10001)
    with pytest.raises(ReportParseError, match="10001"):
        parse_aggregate_report(xml, max_size_bytes=50 * 1024 * 1024, max_records=10000)
