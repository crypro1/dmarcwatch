"""Parser für SMTP TLS-RPT Reports (RFC 8460).

Sicherheitsanforderungen analog zu parser.py (DMARC): die Eingabe kommt von
außen (jeder kann eine Mail an die rua-Adresse schicken) und wird
grundsätzlich als unvertrauenswürdig behandelt - Obergrenze für die
JSON-Größe, Obergrenzen für die Anzahl der Policy- und
Failure-Details-Einträge, fehlerhafte Reports/Einträge werden übersprungen
statt den ganzen Lauf abzubrechen. json.loads() ist von sich aus schon
gegen XXE/externe Entitäten immun (JSON kennt sowas nicht), eine sehr tief
verschachtelte Struktur kann aber einen RecursionError auslösen - wird
ebenfalls abgefangen.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from .models import TLSFailureDetail, TLSPolicy, TLSPolicyResult, TLSReport, TLSReportMetadata

_MIN_TS = 946684800
_MAX_TS = 4102444800


class TLSReportParseError(ValueError):
    """Ein TLS-RPT-Report konnte nicht sicher geparst werden und wird übersprungen."""


def _parse_datetime(value: object, field_name: str) -> int:
    if not isinstance(value, str) or not value.strip():
        raise TLSReportParseError(f"Feld {field_name!r} fehlt oder ist kein String")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError as exc:
        raise TLSReportParseError(f"Feld {field_name!r} ist kein gültiges Datum: {value!r}") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    ts = int(dt.timestamp())
    if not (_MIN_TS <= ts <= _MAX_TS):
        raise TLSReportParseError(f"Zeitstempel {field_name}={ts} ist unplausibel")
    return ts


def _require_str(d: dict, key: str) -> str:
    val = d.get(key)
    if not isinstance(val, str) or not val.strip():
        raise TLSReportParseError(f"Pflichtfeld {key!r} fehlt oder ist leer")
    return val.strip()


def _optional_str(d: dict, key: str, default: str = "") -> str:
    val = d.get(key, default)
    if not isinstance(val, str):
        return default
    return val


def _optional_int(d: dict, key: str, default: int = 0) -> int:
    val = d.get(key, default)
    if isinstance(val, bool) or not isinstance(val, int) or val < 0:
        return default
    return val


def _parse_string_list(value: object, field_name: str) -> tuple[str, ...]:
    """`mx-host`/`policy-string` sollen laut RFC-8460-Schema (4.4) eine
    JSON-Liste aus Strings sein - das eigene Beispiel im RFC (Appendix B)
    kodiert `mx-host` aber selbst als reinen String
    (`"mx-host": "*.mail.company-y.example"`), nicht als Liste. Diese
    Uneinigkeit zwischen Schema-Text und Beispiel im RFC selbst spiegelt
    sich in echten Reports wider - deshalb wird hier absichtlich beides
    akzeptiert, statt einen sonst gültigen Report allein wegen dieser
    Formatabweichung zu verwerfen."""
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if not isinstance(value, list):
        raise TLSReportParseError(f"Feld {field_name!r} ist weder String noch Liste")
    return tuple(item for item in value if isinstance(item, str))


def _parse_metadata(data: dict) -> TLSReportMetadata:
    date_range = data.get("date-range")
    if not isinstance(date_range, dict):
        raise TLSReportParseError("<date-range> fehlt")
    return TLSReportMetadata(
        organization_name=_require_str(data, "organization-name"),
        report_id=_require_str(data, "report-id"),
        date_begin=_parse_datetime(date_range.get("start-datetime"), "date-range/start-datetime"),
        date_end=_parse_datetime(date_range.get("end-datetime"), "date-range/end-datetime"),
        contact_info=_optional_str(data, "contact-info"),
    )


def _parse_failure_detail(d: object) -> TLSFailureDetail:
    if not isinstance(d, dict):
        raise TLSReportParseError("Fehlerhafter failure-details-Eintrag")
    return TLSFailureDetail(
        result_type=_require_str(d, "result-type"),
        sending_mta_ip=_optional_str(d, "sending-mta-ip"),
        receiving_mx_hostname=_optional_str(d, "receiving-mx-hostname"),
        receiving_mx_helo=_optional_str(d, "receiving-mx-helo"),
        receiving_ip=_optional_str(d, "receiving-ip"),
        failed_session_count=_optional_int(d, "failed-session-count"),
        additional_information=_optional_str(d, "additional-information"),
        failure_reason_code=_optional_str(d, "failure-reason-code"),
    )


def _parse_policy_result(entry: object, max_failure_details: int) -> TLSPolicyResult:
    if not isinstance(entry, dict):
        raise TLSReportParseError("Fehlerhafter policies-Eintrag")
    policy = entry.get("policy")
    if not isinstance(policy, dict):
        raise TLSReportParseError("<policy> fehlt")
    summary = entry.get("summary")
    if not isinstance(summary, dict):
        raise TLSReportParseError("<summary> fehlt")

    failure_entries = entry.get("failure-details", []) or []
    if not isinstance(failure_entries, list):
        raise TLSReportParseError("<failure-details> ist keine Liste")
    if len(failure_entries) > max_failure_details:
        raise TLSReportParseError(
            f"{len(failure_entries)} failure-details, über Obergrenze {max_failure_details}"
        )
    failure_details = []
    for fd in failure_entries:
        try:
            failure_details.append(_parse_failure_detail(fd))
        except TLSReportParseError:
            # Ein einzelner kaputter Eintrag verwirft nur diesen Eintrag,
            # nicht die ganze Policy (analog zu _parse_record in parser.py).
            continue

    return TLSPolicyResult(
        policy=TLSPolicy(
            policy_type=_require_str(policy, "policy-type"),
            policy_domain=_require_str(policy, "policy-domain"),
            policy_strings=_parse_string_list(policy.get("policy-string"), "policy/policy-string"),
            mx_host=_parse_string_list(policy.get("mx-host"), "policy/mx-host"),
        ),
        successful_session_count=_optional_int(summary, "total-successful-session-count"),
        failure_count=_optional_int(summary, "total-failure-session-count"),
        failure_details=tuple(failure_details),
    )


def parse_tls_report(
    json_bytes: bytes,
    max_size_bytes: int,
    max_policies: int = 1000,
    max_failure_details_per_policy: int = 10000,
) -> TLSReport:
    """Parst einen SMTP-TLS-RPT-Report (RFC 8460) aus rohen JSON-Bytes.

    Wirft TLSReportParseError bei jedem Problem - der Aufrufer fängt das ab,
    protokolliert es und macht mit dem nächsten Report weiter (fail closed,
    kein Laufabbruch), analog zu parse_aggregate_report in parser.py.
    """
    if not isinstance(json_bytes, (bytes, bytearray)):
        raise TLSReportParseError("Eingabe ist kein bytes-Objekt")
    if len(json_bytes) == 0:
        raise TLSReportParseError("JSON ist leer")
    if len(json_bytes) > max_size_bytes:
        raise TLSReportParseError(f"JSON-Größe {len(json_bytes)} überschreitet Obergrenze {max_size_bytes}")

    try:
        data = json.loads(json_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise TLSReportParseError(f"JSON konnte nicht geparst werden: {exc}") from exc

    if not isinstance(data, dict):
        raise TLSReportParseError("Wurzelelement ist kein JSON-Objekt")

    metadata = _parse_metadata(data)

    policies_raw = data.get("policies")
    if not isinstance(policies_raw, list):
        raise TLSReportParseError("<policies> fehlt oder ist keine Liste")
    if len(policies_raw) > max_policies:
        raise TLSReportParseError(f"Report hat {len(policies_raw)} Policies, über Obergrenze {max_policies}")

    policy_results = []
    for entry in policies_raw:
        try:
            policy_results.append(_parse_policy_result(entry, max_failure_details_per_policy))
        except TLSReportParseError:
            continue

    if not policy_results:
        raise TLSReportParseError("Report enthält keine verwertbaren <policies>-Einträge")

    return TLSReport(metadata=metadata, policy_results=tuple(policy_results))
