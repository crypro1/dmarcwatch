"""Tests für den SMTP-TLS-RPT-Parser (RFC 8460)."""
import json

import pytest

from dmarcwatch.tls_parser import TLSReportParseError, parse_tls_report

MAX_SIZE = 2 * 1024 * 1024


def _sample(**overrides) -> dict:
    report = {
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
                "summary": {
                    "total-successful-session-count": 42,
                    "total-failure-session-count": 1,
                },
                "failure-details": [
                    {
                        "result-type": "certificate-expired",
                        "sending-mta-ip": "198.51.100.1",
                        "receiving-mx-hostname": "mx1.example.com",
                        "failed-session-count": 1,
                    }
                ],
            }
        ],
    }
    report.update(overrides)
    return report


def _bytes(d: dict) -> bytes:
    return json.dumps(d).encode("utf-8")


def test_valid_report_parses():
    report = parse_tls_report(_bytes(_sample()), MAX_SIZE)
    assert report.metadata.organization_name == "Mail Provider"
    assert report.metadata.report_id == "report-id-12345"
    assert report.metadata.contact_info == "tls-reports@provider.example"
    assert report.metadata.date_begin < report.metadata.date_end

    assert len(report.policy_results) == 1
    pr = report.policy_results[0]
    assert pr.policy.policy_type == "sts"
    assert pr.policy.policy_domain == "example.com"
    assert pr.policy.policy_strings == ("version: STSv1", "mode: testing")
    assert pr.policy.mx_host == ("mx1.example.com",)
    assert pr.successful_session_count == 42
    assert pr.failure_count == 1
    assert len(pr.failure_details) == 1
    fd = pr.failure_details[0]
    assert fd.result_type == "certificate-expired"
    assert fd.sending_mta_ip == "198.51.100.1"
    assert fd.failed_session_count == 1


def test_multiple_policies_for_different_domains():
    sample = _sample()
    second = json.loads(_bytes(_sample()))["policies"][0]
    second["policy"]["policy-domain"] = "other.example"
    sample["policies"].append(second)
    report = parse_tls_report(_bytes(sample), MAX_SIZE)
    assert {pr.policy.policy_domain for pr in report.policy_results} == {"example.com", "other.example"}


def test_no_policy_found_type_without_policy_string():
    sample = _sample()
    sample["policies"][0]["policy"]["policy-type"] = "no-policy-found"
    del sample["policies"][0]["policy"]["policy-string"]
    sample["policies"][0]["failure-details"] = []
    report = parse_tls_report(_bytes(sample), MAX_SIZE)
    assert report.policy_results[0].policy.policy_type == "no-policy-found"
    assert report.policy_results[0].policy.policy_strings == ()
    assert report.policy_results[0].failure_details == ()


def test_missing_organization_name_rejected():
    sample = _sample()
    del sample["organization-name"]
    with pytest.raises(TLSReportParseError):
        parse_tls_report(_bytes(sample), MAX_SIZE)


def test_missing_date_range_rejected():
    sample = _sample()
    del sample["date-range"]
    with pytest.raises(TLSReportParseError):
        parse_tls_report(_bytes(sample), MAX_SIZE)


def test_invalid_datetime_rejected():
    sample = _sample()
    sample["date-range"]["start-datetime"] = "not-a-date"
    with pytest.raises(TLSReportParseError):
        parse_tls_report(_bytes(sample), MAX_SIZE)


def test_empty_policies_list_rejected():
    sample = _sample()
    sample["policies"] = []
    with pytest.raises(TLSReportParseError):
        parse_tls_report(_bytes(sample), MAX_SIZE)


def test_missing_policies_field_rejected():
    sample = _sample()
    del sample["policies"]
    with pytest.raises(TLSReportParseError):
        parse_tls_report(_bytes(sample), MAX_SIZE)


def test_one_bad_policy_entry_does_not_reject_whole_report():
    sample = _sample()
    sample["policies"].append({"policy": {"policy-type": "sts"}})  # fehlt policy-domain, summary
    report = parse_tls_report(_bytes(sample), MAX_SIZE)
    assert len(report.policy_results) == 1


def test_one_bad_failure_detail_does_not_reject_policy():
    sample = _sample()
    sample["policies"][0]["failure-details"].append({"sending-mta-ip": "198.51.100.2"})  # kein result-type
    report = parse_tls_report(_bytes(sample), MAX_SIZE)
    assert len(report.policy_results[0].failure_details) == 1


def test_not_a_json_object_rejected():
    with pytest.raises(TLSReportParseError):
        parse_tls_report(b"[1, 2, 3]", MAX_SIZE)


def test_invalid_json_rejected():
    with pytest.raises(TLSReportParseError):
        parse_tls_report(b"{not valid json", MAX_SIZE)


def test_empty_bytes_rejected():
    with pytest.raises(TLSReportParseError):
        parse_tls_report(b"", MAX_SIZE)


def test_oversized_json_rejected():
    huge = _bytes(_sample())
    with pytest.raises(TLSReportParseError):
        parse_tls_report(huge, max_size_bytes=10)


def test_too_many_policies_rejected():
    sample = _sample()
    single_policy = sample["policies"][0]
    sample["policies"] = [dict(single_policy) for _ in range(5)]
    with pytest.raises(TLSReportParseError):
        parse_tls_report(_bytes(sample), MAX_SIZE, max_policies=3)


def test_too_many_failure_details_rejected():
    sample = _sample()
    single_fd = sample["policies"][0]["failure-details"][0]
    sample["policies"][0]["failure-details"] = [dict(single_fd) for _ in range(5)]
    with pytest.raises(TLSReportParseError):
        parse_tls_report(_bytes(sample), MAX_SIZE, max_failure_details_per_policy=3)


def test_negative_counts_default_to_zero():
    sample = _sample()
    sample["policies"][0]["summary"]["total-failure-session-count"] = -5
    report = parse_tls_report(_bytes(sample), MAX_SIZE)
    assert report.policy_results[0].failure_count == 0


def test_rfc8460_appendix_b_example_report_parses_completely():
    """Der Beispielreport aus RFC 8460 Appendix B, wortwörtlich übernommen
    (nur Domainnamen/IPs unverändert aus dem RFC, die sind schon
    Beispiel-Werte). Deckt zwei reale Eigenheiten ab, die beim Nachlesen
    des Original-RFC-Texts auffielen (nicht nur aus einer Zusammenfassung
    übernommen):
    1. "mx-host" ist im RFC-eigenen Beispiel ein reiner String
       (`"*.mail.company-y.example"`), nicht die im Schema-Abschnitt (4.4)
       beschriebene JSON-Liste - siehe _parse_string_list.
    2. failure-details-Einträge lassen optionale Felder
       (receiving-ip, additional-information, failure-reason-code) je nach
       Eintrag ganz weg, nicht nur leer."""
    rfc_example = {
        "organization-name": "Company-X",
        "date-range": {
            "start-datetime": "2016-04-01T00:00:00Z",
            "end-datetime": "2016-04-01T23:59:59Z",
        },
        "contact-info": "sts-reporting@company-x.example",
        "report-id": "5065427c-23d3-47ca-b6e0-946ea0e8c4be",
        "policies": [
            {
                "policy": {
                    "policy-type": "sts",
                    "policy-string": [
                        "version: STSv1",
                        "mode: testing",
                        "mx: *.mail.company-y.example",
                        "max_age: 86400",
                    ],
                    "policy-domain": "company-y.example",
                    "mx-host": "*.mail.company-y.example",
                },
                "summary": {
                    "total-successful-session-count": 5326,
                    "total-failure-session-count": 303,
                },
                "failure-details": [
                    {
                        "result-type": "certificate-expired",
                        "sending-mta-ip": "2001:db8:abcd:0012::1",
                        "receiving-mx-hostname": "mx1.mail.company-y.example",
                        "failed-session-count": 100,
                    },
                    {
                        "result-type": "starttls-not-supported",
                        "sending-mta-ip": "2001:db8:abcd:0013::1",
                        "receiving-mx-hostname": "mx2.mail.company-y.example",
                        "receiving-ip": "203.0.113.56",
                        "failed-session-count": 200,
                        "additional-information": "https://reports.company-x.example/report_info",
                    },
                    {
                        "result-type": "validation-failure",
                        "sending-mta-ip": "198.51.100.62",
                        "receiving-ip": "203.0.113.58",
                        "receiving-mx-hostname": "mx-backup.mail.company-y.example",
                        "failed-session-count": 3,
                        "failure-reason-code": "X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED",
                    },
                ],
            }
        ],
    }
    report = parse_tls_report(_bytes(rfc_example), MAX_SIZE)
    assert len(report.policy_results) == 1
    pr = report.policy_results[0]
    assert pr.policy.mx_host == ("*.mail.company-y.example",)  # String, nicht Liste, trotzdem geparst
    assert pr.successful_session_count == 5326
    assert pr.failure_count == 303
    assert len(pr.failure_details) == 3
    assert pr.failure_details[0].failed_session_count == 100
    assert pr.failure_details[1].additional_information == "https://reports.company-x.example/report_info"
    assert pr.failure_details[2].failure_reason_code == "X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED"


def test_mx_host_as_plain_string_accepted():
    sample = _sample()
    sample["policies"][0]["policy"]["mx-host"] = "*.example.com"
    report = parse_tls_report(_bytes(sample), MAX_SIZE)
    assert report.policy_results[0].policy.mx_host == ("*.example.com",)


def test_real_world_google_report_shape_is_parsed_correctly():
    """Regressionstest für einen echten Bug: das RFC-8460-Feld heißt
    `total-failure-session-count`, nicht `total-failure-count` - der Parser
    hatte ursprünglich den falschen Schlüssel gesucht und dadurch jeden
    echten Fehlschlag-Zähler still auf 0 gesetzt (kein Parse-Fehler, weil
    der Wert einfach als "nicht vorhanden" durchging). Aufgefallen erst an
    einem echten, von Google verschickten Beispielreport, nicht in eigenen
    Test-Fixtures, die denselben (falschen) Feldnamen benutzt hatten. Struktur
    hier 1:1 wie im echten Report, nur die Domain durch einen Platzhalter
    ersetzt."""
    real_shape = {
        "organization-name": "Google Inc.",
        "date-range": {
            "start-datetime": "2026-02-08T00:00:00Z",
            "end-datetime": "2026-02-09T00:00:00Z",
        },
        "contact-info": "smtp-tls-reporting@google.com",
        "report-id": "2026-02-08T00:00:00Z_example.com",
        "policies": [
            {
                "policy": {
                    "policy-type": "sts",
                    "policy-string": [
                        "version: STSv1",
                        "mode: enforce",
                        "mx: mail.example.com",
                        "max_age: 604800",
                    ],
                    "policy-domain": "example.com",
                },
                "summary": {
                    "total-successful-session-count": 4523,
                    "total-failure-session-count": 2,
                },
                "failure-details": [
                    {
                        "result-type": "certificate-expired",
                        "sending-mta-ip": "192.0.2.1",
                        "receiving-mx-hostname": "mail.example.com",
                        "failed-session-count": 2,
                    }
                ],
            }
        ],
    }
    report = parse_tls_report(_bytes(real_shape), MAX_SIZE)
    pr = report.policy_results[0]
    assert pr.successful_session_count == 4523
    assert pr.failure_count == 2  # vor dem Fix: fälschlich 0
    assert pr.failure_details[0].failed_session_count == 2
