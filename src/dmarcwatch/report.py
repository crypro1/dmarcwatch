"""Tabellarische Zusammenfassung für die CLI (`dmarcwatch report`)."""
from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass

from .anomaly import REASON_LABELS_DE
from .sanitize import sanitize_field
from .store import query_records

_MAX_JSON_FIELD_LEN = 120


def day_range_to_ts(days: int) -> tuple[int, int]:
    now = int(time.time())
    return now - days * 86400, now


@dataclass
class ReportRow:
    date_begin: int
    org_name: str
    source_ip: str
    count: int
    disposition: str
    dkim: str
    spf: str
    envelope_to: str
    is_flagged: bool
    flag_reasons: list[str]


def collect_rows(conn: sqlite3.Connection, since_ts: int, until_ts: int) -> list[ReportRow]:
    rows = query_records(conn, since_ts, until_ts)
    result = []
    for r in rows:
        reasons = [x for x in (r["flag_reasons"] or "").split(",") if x]
        result.append(
            ReportRow(
                date_begin=r["date_begin"],
                org_name=r["org_name"],
                source_ip=r["source_ip"],
                count=r["count"],
                disposition=r["disposition"],
                dkim=r["dkim_result"],
                spf=r["spf_result"],
                envelope_to=r["envelope_to"] or "",
                is_flagged=bool(r["is_flagged"]),
                flag_reasons=reasons,
            )
        )
    return result


def format_table(rows: list[ReportRow]) -> str:
    if not rows:
        return "Keine Reports im gewählten Zeitraum."

    headers = ["Datum", "Absender", "Quell-IP", "Anzahl", "Disposition", "DKIM", "SPF", "Auffällig"]
    lines_data = []
    for r in rows:
        # org_name, disposition, dkim und spf stammen unverändert aus dem
        # geparsten Report (unvertrauenswürdige Eingabe) und könnten z. B.
        # ANSI-Escape-Sequenzen enthalten - vor der Terminal-Ausgabe bereinigen.
        date_str = time.strftime("%Y-%m-%d", time.gmtime(r.date_begin))
        org_name = sanitize_field(r.org_name, max_len=45)
        source_ip = sanitize_field(r.source_ip, max_len=45)
        disposition = sanitize_field(r.disposition, max_len=15)
        dkim = sanitize_field(r.dkim, max_len=10)
        spf = sanitize_field(r.spf, max_len=10)
        flag_str = ""
        if r.is_flagged:
            labels = [REASON_LABELS_DE.get(x, x) for x in r.flag_reasons]
            flag_str = "⚠︎ " + ", ".join(labels)
        lines_data.append(
            [date_str, org_name, source_ip, str(r.count), disposition, dkim, spf, flag_str]
        )

    widths = [len(h) for h in headers]
    for row in lines_data:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    def fmt_row(cells: list[str]) -> str:
        return "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(cells))

    out = [fmt_row(headers), fmt_row(["-" * w for w in widths])]
    out.extend(fmt_row(row) for row in lines_data)
    return "\n".join(out)


def has_findings(rows: list[ReportRow]) -> bool:
    return any(r.is_flagged for r in rows)


def to_json_dict(rows: list[ReportRow], days: int, whois_by_ip: dict[str, str] | None = None) -> dict:
    """Strukturierte, nach Tag gruppierte Sicht für native Konsumenten
    (z. B. die Swift-Menüleisten-App). Anders als format_table()/render_swiftbar()
    gibt es hier kein Trennzeichen-Format zu schützen - JSON-Encoding
    escaped Werte automatisch korrekt. sanitize_field() wird trotzdem
    angewendet, für sinnvolle Anzeigelängen und um Steuerzeichen aus
    unvertrauenswürdigen Report-Feldern fernzuhalten, bevor sie in einem
    nativen Menü landen.

    whois_by_ip ist der bereits lokal gespeicherte Cache aus `dmarcwatch
    inspect --whois` (siehe store.get_all_cached_whois) - hier wird NIE
    selbst nachgeschlagen, nur was schon vorliegt, wird mit ausgegeben.
    """
    whois_by_ip = whois_by_ip or {}
    flagged = [r for r in rows if r.is_flagged]

    by_day: dict[str, list[ReportRow]] = {}
    for r in rows:
        day = time.strftime("%Y-%m-%d", time.gmtime(r.date_begin))
        by_day.setdefault(day, []).append(r)

    days_out = []
    for day in sorted(by_day.keys(), reverse=True):
        day_rows = by_day[day]
        records = []
        for r in day_rows:
            records.append(
                {
                    "org_name": sanitize_field(r.org_name, max_len=_MAX_JSON_FIELD_LEN),
                    "source_ip": sanitize_field(r.source_ip, max_len=_MAX_JSON_FIELD_LEN),
                    "count": r.count,
                    "disposition": sanitize_field(r.disposition, max_len=_MAX_JSON_FIELD_LEN),
                    "dkim": sanitize_field(r.dkim, max_len=_MAX_JSON_FIELD_LEN),
                    "spf": sanitize_field(r.spf, max_len=_MAX_JSON_FIELD_LEN),
                    "envelope_to": sanitize_field(r.envelope_to, max_len=_MAX_JSON_FIELD_LEN),
                    "is_flagged": r.is_flagged,
                    "flag_labels": [REASON_LABELS_DE.get(x, x) for x in r.flag_reasons],
                    "whois_organization": sanitize_field(whois_by_ip[r.source_ip], max_len=_MAX_JSON_FIELD_LEN)
                    if r.source_ip in whois_by_ip
                    else None,
                }
            )
        days_out.append(
            {
                "date": day,
                "flagged_count": sum(1 for r in day_rows if r.is_flagged),
                "records": records,
            }
        )

    return {
        "days": days,
        "total_count": len(rows),
        "flagged_count": len(flagged),
        "days_grouped": days_out,
    }
