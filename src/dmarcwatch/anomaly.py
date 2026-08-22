"""Auffälligkeits-Erkennung (Spezifikation Abschnitt 2).

Ein Record gilt als auffällig, wenn mindestens einer zutrifft:
1. source_ip gehört nicht zu den konfigurierten eigenen IP-Präfixen
2. source_ip ist eigen, aber SPF und DKIM scheitern beide
3. disposition ist ungleich "none"
"""
from __future__ import annotations

from .config import Config
from .models import Record

REASON_UNKNOWN_IP = "unknown_ip"
REASON_OWN_IP_AUTH_FAIL = "own_ip_auth_fail"
REASON_DISPOSITION = "disposition_not_none"


def evaluate_record(record: Record, config: Config) -> list[str]:
    reasons: list[str] = []
    is_own = config.is_own_ip(record.source_ip)

    if not is_own:
        reasons.append(REASON_UNKNOWN_IP)

    if is_own and record.policy_evaluated.dkim == "fail" and record.policy_evaluated.spf == "fail":
        reasons.append(REASON_OWN_IP_AUTH_FAIL)

    if record.policy_evaluated.disposition != "none":
        reasons.append(REASON_DISPOSITION)

    return reasons


REASON_LABELS_DE = {
    REASON_UNKNOWN_IP: "unbekannte IP",
    REASON_OWN_IP_AUTH_FAIL: "SPF+DKIM fehlgeschlagen (eigene IP)",
    REASON_DISPOSITION: "Disposition ≠ none",
}
