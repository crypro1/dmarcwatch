"""Tests gegen strukturell realistische Dialekt-Fixtures (siehe
Spezifikation Abschnitt 8: "gegen echte Reports testen").

Diese Fixtures wurden ursprünglich aus echten, empfangenen DMARC-Reports
abgeleitet und behalten deren strukturelle Eigenheiten bei (Feldreihenfolge,
Einrückung, Namespaces, Zeilenenden), enthalten aber ausschließlich
fiktive Domains/IPs/Report-IDs - keine echten Absende- oder Empfangsdaten.

- google_dialect_sample.zip: Google liefert als ZIP (nicht .gz), Report
  ohne envelope_to, policy_published mit dem neueren np-Feld, IPv6-Absender.
- microsoft_outlook_dialect_sample.xml: Root-Element mit xmlns:xsd/xmlns:xsi-
  Attributen, envelope_to und envelope_from beide gesetzt, zusätzliches
  <fo>-Feld.
- amazon_ses_dialect_sample.xml.gz: Tab-eingerücktes XML, dkim-Feldreihenfolge
  (domain, result, selector) anders als in den handgeschriebenen Fixtures,
  envelope_to fehlt.
- mimecast_dialect_sample.xml: leeres selbstschließendes <human_result/>-
  Element innerhalb von <dkim> (gültiges, aber selten genutztes
  RFC-7489-Feld), sehr lange hexadezimale report_id.
"""
from pathlib import Path

from dmarcwatch.archive import extract_report_xml
from dmarcwatch.config import Config
from dmarcwatch.parser import parse_aggregate_report
from dmarcwatch.store import IngestStatus, connect, ingest_report

FIXTURES = Path(__file__).parent / "fixtures"
MAX_ATTACHMENT = 5 * 1024 * 1024
MAX_XML = 10 * 1024 * 1024


def _config() -> Config:
    return Config.from_dict(
        {
            "own_domains": ["example.com"],
            "own_ip_networks": ["192.0.2.0/24", "2001:db8:1::/48"],
        }
    )


def _load_via_archive(filename: str) -> bytes:
    data = (FIXTURES / filename).read_bytes()
    return extract_report_xml(filename, data, MAX_ATTACHMENT, MAX_XML)


def test_google_dialect_zip_with_np_field_and_no_envelope_to():
    xml_bytes = _load_via_archive("google_dialect_sample.zip")
    report = parse_aggregate_report(xml_bytes, MAX_XML)

    assert report.metadata.org_name == "google.com"
    assert report.policy_published.p == "reject"
    assert report.policy_published.sp == "reject"
    assert report.policy_published.np == "reject"

    rec = report.records[0]
    assert rec.source_ip == "2001:db8:1:0:465::201"  # von ipaddress kanonisiert
    assert rec.identifiers.envelope_to == ""

    config = _config()
    assert config.is_own_ip(rec.source_ip)


def test_ipv6_source_matches_own_network_regardless_of_notation():
    config = _config()
    # Dieselbe Adresse wie im Fixture, aber in unterschiedlichen,
    # gleichwertigen Schreibweisen - ein Zeichenketten-Präfixvergleich würde
    # das nicht zuverlässig erkennen, ipaddress-Netzzugehörigkeit schon.
    assert config.is_own_ip("2001:db8:1:0:465::201")
    assert config.is_own_ip("2001:DB8:1:0:465:0:0:201")  # Großschreibung, unkomprimiert
    assert config.is_own_ip("2001:db8:1::1")  # anderer Host im selben /48
    # Eine Adresse außerhalb des /48 darf nicht fälschlich als eigen gelten,
    # obwohl sie als Zeichenkette denselben Anfang hätte wie ein Präfix "2001:db8:1".
    assert not config.is_own_ip("2001:db8:2::1")


def test_microsoft_outlook_dialect_with_namespace_attributes():
    xml_bytes = (FIXTURES / "microsoft_outlook_dialect_sample.xml").read_bytes()
    report = parse_aggregate_report(xml_bytes, MAX_XML)

    assert report.metadata.org_name == "Enterprise Outlook"
    rec = report.records[0]
    assert rec.source_ip == "192.0.2.171"
    assert rec.identifiers.envelope_to == "example.net"
    assert rec.identifiers.envelope_from == "example.com"
    assert rec.auth_results.dkim[0].selector == "MBO0001"


def test_amazon_ses_dialect_gz_tab_indented_and_no_envelope_to():
    xml_bytes = _load_via_archive("amazon_ses_dialect_sample.xml.gz")
    report = parse_aggregate_report(xml_bytes, MAX_XML)

    assert report.metadata.org_name == "AMAZON-SES"
    rec = report.records[0]
    assert rec.source_ip == "192.0.2.161"
    assert rec.identifiers.envelope_to == ""
    # dkim-Feldreihenfolge in diesem Dialekt ist domain/result/selector,
    # nicht domain/selector/result wie in den handgeschriebenen Fixtures.
    assert rec.auth_results.dkim[0].selector == "MBO0001"
    assert rec.auth_results.dkim[0].result == "pass"


def test_mimecast_dialect_with_empty_human_result_element():
    xml_bytes = (FIXTURES / "mimecast_dialect_sample.xml").read_bytes()
    report = parse_aggregate_report(xml_bytes, MAX_XML)

    assert report.metadata.org_name == "Mimecast"
    rec = report.records[0]
    assert rec.source_ip == "192.0.2.172"
    assert rec.policy_evaluated.disposition == "none"
    # Das leere <human_result/>-Element wird einfach ignoriert (kein
    # gelesenes Feld), genau wie Googles <np> oder Microsofts <fo> in den
    # anderen Dialekt-Fixtures - kein Absturz, kein Sonderfall nötig.
    assert rec.auth_results.dkim[0].result == "pass"
    assert rec.auth_results.spf[0].result == "pass"


def test_all_four_dialect_samples_ingest_cleanly_and_are_not_flagged(tmp_path):
    conn = connect(tmp_path / "dmarc.sqlite")
    config = _config()

    for filename in ("google_dialect_sample.zip", "amazon_ses_dialect_sample.xml.gz"):
        xml_bytes = _load_via_archive(filename)
        report = parse_aggregate_report(xml_bytes, MAX_XML)
        result = ingest_report(conn, report, config)
        assert result.status == IngestStatus.INSERTED, filename
        assert result.flagged_count == 0, filename

    for filename in ("microsoft_outlook_dialect_sample.xml", "mimecast_dialect_sample.xml"):
        xml_bytes = (FIXTURES / filename).read_bytes()
        report = parse_aggregate_report(xml_bytes, MAX_XML)
        result = ingest_report(conn, report, config)
        assert result.status == IngestStatus.INSERTED, filename
        assert result.flagged_count == 0, filename
