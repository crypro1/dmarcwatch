"""SwiftBar-kompatible Menüleisten-Ausgabe.

SwiftBar-Format: Zeilen aus Text und optionalen "|"-getrennten Parametern
(z. B. "color=red"). Ein Parameter wie "bash=..." führt beim Klick einen
Befehl aus. Da alle hier verwendeten Report-Daten von außen kommen und
unvertrauenswürdig sind, läuft jeder eingebettete Wert durch
sanitize_field(), das u. a. "|" entfernt - eine Zeile kann dadurch nie
ungewollt zusätzliche Parameter erzeugen.
"""
from __future__ import annotations

import time

from .anomaly import REASON_LABELS_DE
from .report import ReportRow

_MAX_FIELD_LEN = 60
_MAX_DETAIL_LEN = 160


def _line(text: str, prefix: str = "", max_len: int = _MAX_FIELD_LEN, **params: str) -> str:
    from .sanitize import sanitize_field

    safe_text = sanitize_field(text, max_len=max_len)
    out = f"{prefix}{safe_text}"
    if params:
        parts = []
        for key, value in params.items():
            safe_value = sanitize_field(str(value), max_len=_MAX_FIELD_LEN)
            parts.append(f"{key}={safe_value}")
        out += " | " + " ".join(parts)
    return out


def render_swiftbar(rows: list[ReportRow], days: int) -> str:
    flagged = [r for r in rows if r.is_flagged]

    if flagged:
        header = _line(f"DMARC ⚠︎ {len(flagged)}", color="red", sfimage="exclamationmark.triangle")
    else:
        header = _line(f"DMARC ✓ {len(rows)}", color="green", sfimage="checkmark.shield")

    lines = [header, "---"]
    lines.append(_line(f"Zeitraum: letzte {days} Tag(e), {len(rows)} Einträge, {len(flagged)} auffällig"))
    lines.append("---")

    if not rows:
        lines.append(_line("Keine Reports im Zeitraum"))
        return "\n".join(lines) + "\n"

    by_day: dict[str, list[ReportRow]] = {}
    for r in rows:
        day = time.strftime("%Y-%m-%d", time.gmtime(r.date_begin))
        by_day.setdefault(day, []).append(r)

    for day in sorted(by_day.keys(), reverse=True):
        day_rows = by_day[day]
        day_flagged = sum(1 for r in day_rows if r.is_flagged)
        suffix = f" ⚠︎{day_flagged}" if day_flagged else ""
        lines.append(_line(f"{day}{suffix}", prefix="-- "))
        for r in day_rows:
            summary = f"{r.source_ip}  n={r.count}  disp={r.disposition}  dkim={r.dkim}  spf={r.spf}"
            if r.is_flagged:
                labels = [REASON_LABELS_DE.get(x, x) for x in r.flag_reasons]
                summary += "  ⚠︎ " + ", ".join(labels)
                lines.append(_line(summary, prefix="---- ", max_len=_MAX_DETAIL_LEN, color="red"))
            else:
                lines.append(_line(summary, prefix="---- ", max_len=_MAX_DETAIL_LEN))

    return "\n".join(lines) + "\n"
