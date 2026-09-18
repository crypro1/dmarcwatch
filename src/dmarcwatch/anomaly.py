"""Auffälligkeits-Erkennung (Spezifikation Abschnitt 2).

Ein Record gilt als auffällig, wenn mindestens einer zutrifft:
1. source_ip gehört nicht zu den konfigurierten eigenen IP-Präfixen
2. source_ip ist eigen, aber SPF und DKIM scheitern beide
3. disposition ist ungleich "none"
4. identifiers/header_from gehört weder zur im selben Report
   veröffentlichten Domain noch zu einer ihrer Subdomains
"""
from __future__ import annotations

from .config import Config
from .models import Record

REASON_UNKNOWN_IP = "unknown_ip"
REASON_OWN_IP_AUTH_FAIL = "own_ip_auth_fail"
REASON_DISPOSITION = "disposition_not_none"
REASON_FOREIGN_HEADER_FROM = "foreign_header_from"


def _is_domain_or_subdomain(candidate: str, parent: str) -> bool:
    candidate = candidate.strip().lower().rstrip(".")
    parent = parent.strip().lower().rstrip(".")
    return bool(parent) and (candidate == parent or candidate.endswith("." + parent))


def evaluate_record(record: Record, config: Config, report_domain: str) -> list[str]:
    reasons: list[str] = []
    is_own = config.is_own_ip(record.source_ip)

    if not is_own:
        reasons.append(REASON_UNKNOWN_IP)

    if is_own and record.policy_evaluated.dkim == "fail" and record.policy_evaluated.spf == "fail":
        reasons.append(REASON_OWN_IP_AUTH_FAIL)

    if record.policy_evaluated.disposition != "none":
        reasons.append(REASON_DISPOSITION)

    # Jeder kann eine Mail an die rua-Adresse schicken (siehe
    # Sicherheitsentscheidungen in der README) - ein gefälschter Report
    # könnte innerhalb einer sonst passenden policy_published/domain
    # beliebige header_from-Werte in einzelnen Records unterbringen.
    # Bewusst hier als Auffälligkeit markiert statt beim Parsen verworfen:
    # header_from ist ein informatives Feld wie org_name, das laut
    # bestehender Konvention (siehe test_store.py/test_parser.py)
    # unverändert gespeichert und erst bei der Anzeige über
    # sanitize_field() entschärft wird, nicht am Parser abgelehnt.
    if not _is_domain_or_subdomain(record.identifiers.header_from, report_domain):
        reasons.append(REASON_FOREIGN_HEADER_FROM)

    return reasons


REASON_LABELS_DE = {
    REASON_UNKNOWN_IP: "unbekannte IP",
    REASON_OWN_IP_AUTH_FAIL: "SPF+DKIM fehlgeschlagen (eigene IP)",
    REASON_DISPOSITION: "Disposition ≠ none",
    REASON_FOREIGN_HEADER_FROM: "header_from gehört nicht zur Report-Domain",
}
