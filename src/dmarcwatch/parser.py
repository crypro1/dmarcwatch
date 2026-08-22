"""Parser für DMARC Aggregate Reports (RFC 7489).

Sicherheitsanforderungen (siehe Spezifikation Abschnitt 4.3):
- defusedxml statt xml.etree
- externe Entitäten, DTDs und Netzwerkzugriffe beim Parsen abgeschaltet
- Obergrenze für die XML-Größe
- fehlerhafte Dateien werden übersprungen, nicht der ganze Lauf abgebrochen

Die Eingabedaten kommen von außen (jeder kann eine Mail an die rua-Adresse
schicken) und werden hier grundsätzlich als unvertrauenswürdig behandelt.
"""
from __future__ import annotations

import ipaddress
from xml.etree.ElementTree import Element

from defusedxml.common import DefusedXmlException
from defusedxml.ElementTree import fromstring as defused_fromstring

from .models import (
    AggregateReport,
    AuthResults,
    DKIMAuthResult,
    Identifiers,
    PolicyEvaluated,
    PolicyPublished,
    Record,
    ReportMetadata,
    SPFAuthResult,
)

# Plausibilitätsgrenzen für Unix-Zeitstempel: 2000-01-01 .. 2100-01-01
_MIN_TS = 946684800
_MAX_TS = 4102444800


class ReportParseError(ValueError):
    """Ein Report konnte nicht sicher geparst werden und wird übersprungen."""


def _local_name(tag: str) -> str:
    # Manche Absender (selten) verwenden XML-Namespaces. Wir vergleichen nur
    # auf den lokalen Namen, unabhängig vom Namespace-Präfix.
    if "}" in tag:
        return tag.rsplit("}", 1)[1]
    return tag


def _child(elem: Element, tag: str) -> Element | None:
    for c in elem:
        if _local_name(c.tag) == tag:
            return c
    return None


def _children(elem: Element, tag: str) -> list[Element]:
    return [c for c in elem if _local_name(c.tag) == tag]


def _text(elem: Element, tag: str, default: str | None = None) -> str | None:
    c = _child(elem, tag)
    if c is None or c.text is None:
        return default
    return c.text.strip()


def _require_text(elem: Element, tag: str) -> str:
    val = _text(elem, tag)
    if val is None or val == "":
        raise ReportParseError(f"Pflichtfeld <{tag}> fehlt oder ist leer")
    return val


def _parse_int(value: str, field_name: str) -> int:
    try:
        return int(value.strip())
    except (ValueError, AttributeError) as exc:
        raise ReportParseError(f"Feld {field_name!r} ist keine gültige Ganzzahl: {value!r}") from exc


def _parse_timestamp(value: str, field_name: str) -> int:
    ts = _parse_int(value, field_name)
    if not (_MIN_TS <= ts <= _MAX_TS):
        raise ReportParseError(f"Zeitstempel {field_name}={ts} ist unplausibel")
    return ts


def _parse_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except (ValueError, AttributeError) as exc:
        raise ReportParseError(f"Ungültige IP-Adresse: {value!r}") from exc


def _parse_metadata(root: Element) -> ReportMetadata:
    md = _child(root, "report_metadata")
    if md is None:
        raise ReportParseError("<report_metadata> fehlt")
    date_range = _child(md, "date_range")
    if date_range is None:
        raise ReportParseError("<date_range> fehlt")
    return ReportMetadata(
        org_name=_require_text(md, "org_name"),
        report_id=_require_text(md, "report_id"),
        email=_text(md, "email", default="") or "",
        date_begin=_parse_timestamp(_require_text(date_range, "begin"), "date_range/begin"),
        date_end=_parse_timestamp(_require_text(date_range, "end"), "date_range/end"),
    )


def _parse_policy_published(root: Element) -> PolicyPublished:
    pp = _child(root, "policy_published")
    if pp is None:
        raise ReportParseError("<policy_published> fehlt")
    pct_raw = _text(pp, "pct", default="100") or "100"
    return PolicyPublished(
        domain=_require_text(pp, "domain"),
        p=_require_text(pp, "p"),
        sp=_text(pp, "sp", default="") or "",
        pct=_parse_int(pct_raw, "policy_published/pct"),
        adkim=_text(pp, "adkim", default="r") or "r",
        aspf=_text(pp, "aspf", default="r") or "r",
        np=_text(pp, "np", default="") or "",
    )


def _parse_auth_results(record: Element) -> AuthResults:
    ar = _child(record, "auth_results")
    if ar is None:
        return AuthResults()
    dkim_results = []
    for d in _children(ar, "dkim"):
        dkim_results.append(
            DKIMAuthResult(
                domain=_text(d, "domain", default="") or "",
                selector=_text(d, "selector", default="") or "",
                result=_text(d, "result", default="") or "",
            )
        )
    spf_results = []
    for s in _children(ar, "spf"):
        spf_results.append(
            SPFAuthResult(
                domain=_text(s, "domain", default="") or "",
                result=_text(s, "result", default="") or "",
            )
        )
    return AuthResults(dkim=tuple(dkim_results), spf=tuple(spf_results))


def _parse_record(record: Element) -> Record:
    row = _child(record, "row")
    if row is None:
        raise ReportParseError("<row> fehlt in <record>")
    pe = _child(row, "policy_evaluated")
    if pe is None:
        raise ReportParseError("<policy_evaluated> fehlt")
    identifiers_elem = _child(record, "identifiers")
    if identifiers_elem is None:
        raise ReportParseError("<identifiers> fehlt")

    count_raw = _require_text(row, "count")
    count = _parse_int(count_raw, "row/count")
    if count < 0:
        raise ReportParseError(f"row/count ist negativ: {count}")

    return Record(
        source_ip=_parse_ip(_require_text(row, "source_ip")),
        count=count,
        policy_evaluated=PolicyEvaluated(
            disposition=_text(pe, "disposition", default="none") or "none",
            dkim=_text(pe, "dkim", default="fail") or "fail",
            spf=_text(pe, "spf", default="fail") or "fail",
        ),
        identifiers=Identifiers(
            header_from=_require_text(identifiers_elem, "header_from"),
            envelope_to=_text(identifiers_elem, "envelope_to", default="") or "",
            envelope_from=_text(identifiers_elem, "envelope_from", default="") or "",
        ),
        auth_results=_parse_auth_results(record),
    )


def parse_aggregate_report(
    xml_bytes: bytes, max_size_bytes: int, max_records: int = 10000
) -> AggregateReport:
    """Parst einen DMARC Aggregate Report aus rohen XML-Bytes.

    Wirft ReportParseError bei jedem Problem (fehlerhaftes XML, fehlende
    Pflichtfelder, unplausible Werte, XXE/Billion-Laughs-Versuche,
    Größenüberschreitung, zu viele Records). Der Aufrufer fängt das ab,
    protokolliert es und macht mit dem nächsten Report weiter (fail closed,
    kein Laufabbruch).
    """
    if not isinstance(xml_bytes, (bytes, bytearray)):
        raise ReportParseError("Eingabe ist kein bytes-Objekt")
    if len(xml_bytes) == 0:
        raise ReportParseError("XML ist leer")
    if len(xml_bytes) > max_size_bytes:
        raise ReportParseError(
            f"XML-Größe {len(xml_bytes)} überschreitet Obergrenze {max_size_bytes}"
        )

    try:
        root = defused_fromstring(xml_bytes)
    except DefusedXmlException as exc:
        # XXE, Billion Laughs, externe Entitäten, DTDs etc.
        raise ReportParseError(f"XML als unsicher abgelehnt: {exc}") from exc
    except Exception as exc:  # noqa: BLE001 - Eingabe ist unvertrauenswürdig
        raise ReportParseError(f"XML konnte nicht geparst werden: {exc}") from exc

    if _local_name(root.tag) != "feedback":
        raise ReportParseError(f"Unerwartetes Wurzelelement: {root.tag!r}")

    metadata = _parse_metadata(root)
    policy_published = _parse_policy_published(root)

    record_elems = _children(root, "record")
    if len(record_elems) > max_records:
        # Ganzer Report wird verworfen statt stillschweigend gekürzt - im
        # Zweifel nicht verarbeiten (4.9), nicht raten, welche Records
        # wichtiger wären. Die 10-MB-Größengrenze und der CPU-Zeit-Backstop
        # des LaunchAgents bounden das ohnehin schon empirisch auf < 1s pro
        # Report; dieses Limit macht das zusätzlich deterministisch.
        raise ReportParseError(
            f"Report hat {len(record_elems)} Records, über Obergrenze {max_records}"
        )

    records = []
    for record_elem in record_elems:
        try:
            records.append(_parse_record(record_elem))
        except ReportParseError:
            # Ein einzelner kaputter Record verwirft nur diesen Record,
            # nicht den ganzen Report.
            continue

    if not records:
        raise ReportParseError("Report enthält keine verwertbaren <record>-Einträge")

    return AggregateReport(
        metadata=metadata,
        policy_published=policy_published,
        records=tuple(records),
    )
