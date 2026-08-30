"""Tabellarische Zusammenfassung für die CLI (`dmarcwatch report`)."""
from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass

from .anomaly import REASON_LABELS_DE, REASON_OWN_IP_AUTH_FAIL, REASON_UNKNOWN_IP
from .sanitize import sanitize_field
from .store import query_records, query_tls_failure_details, query_tls_policies

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
    # Defaults statt Pflichtfelder, damit bestehende Test-Fixtures ohne
    # DMARC-Policy-Kontext (die meisten) unverändert weiterlaufen - nur
    # für die Verschärfungs-Einschätzung in stats.py gebraucht.
    domain: str = ""
    policy_p: str = ""
    policy_pct: int = 100


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
                domain=r["domain"],
                policy_p=r["policy_p"],
                policy_pct=r["policy_pct"],
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


def to_json_dict(
    rows: list[ReportRow],
    days: int,
    whois_by_ip: dict[str, str] | None = None,
    skipped_items: list[str] | None = None,
    dns_check: dict | None = None,
    blacklist_by_ip: dict[str, tuple[bool, list[str]]] | None = None,
) -> dict:
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
    blacklist_by_ip = blacklist_by_ip or {}
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
                    "blacklist_listed": blacklist_by_ip[r.source_ip][0] if r.source_ip in blacklist_by_ip else None,
                    "blacklist_reasons": [
                        sanitize_field(reason, max_len=_MAX_JSON_FIELD_LEN)
                        for reason in blacklist_by_ip[r.source_ip][1]
                    ]
                    if r.source_ip in blacklist_by_ip
                    else [],
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
        # Gründe für Nachrichten/Anhänge, die im letzten `fetch`-Lauf
        # übersprungen wurden (z. B. eine abgelehnte Dekompressionsbombe) -
        # kommt bereits sanitisiert aus config.read_skipped_items() (siehe
        # cmd_fetch), hier zusätzlich erneut durch sanitize_field(), gleiche
        # defensive Konvention wie bei whois_organization oben.
        "skipped_items": [sanitize_field(x, max_len=_MAX_JSON_FIELD_LEN) for x in (skipped_items or [])],
        # Ergebnis der letzten verify-dns-Prüfung (egal ob per Klick auf
        # "DNS prüfen…" oder durch den periodischen automatischen Check
        # ausgelöst) - kommt bereits fertig strukturiert aus
        # config.read_dns_check_result(), hier unverändert durchgereicht
        # (eigene Domain-DNS-Inhalte, nicht dieselbe Bedrohungsklasse wie
        # E-Mail-Anhänge, deshalb keine erneute sanitize_field-Behandlung
        # wie bei skipped_items/whois_organization). None, wenn noch nie
        # geprüft wurde.
        "dns_check": dns_check,
    }


@dataclass
class TLSPolicyRow:
    tls_policy_id: int
    date_begin: int
    org_name: str
    policy_domain: str
    policy_type: str
    successful_session_count: int
    failure_count: int
    failure_result_types: list[str]


def collect_tls_rows(conn: sqlite3.Connection, since_ts: int, until_ts: int) -> list[TLSPolicyRow]:
    rows = query_tls_policies(conn, since_ts, until_ts)
    result = []
    for r in rows:
        failure_result_types: list[str] = []
        if r["failure_count"] > 0:
            failure_result_types = [
                fd["result_type"] for fd in query_tls_failure_details(conn, r["id"])
            ]
        result.append(
            TLSPolicyRow(
                tls_policy_id=r["id"],
                date_begin=r["date_begin"],
                org_name=r["organization_name"],
                policy_domain=r["policy_domain"],
                policy_type=r["policy_type"],
                successful_session_count=r["successful_session_count"],
                failure_count=r["failure_count"],
                failure_result_types=failure_result_types,
            )
        )
    return result


def format_tls_table(rows: list[TLSPolicyRow]) -> str:
    if not rows:
        return "Keine TLS-RPT-Reports im gewählten Zeitraum."

    headers = ["Datum", "Organisation", "Domain", "Policy", "Erfolge", "Fehlschläge", "Fehlertyp(en)"]
    lines_data = []
    for r in rows:
        # org_name/policy_domain/policy_type/result_types stammen aus dem
        # geparsten Report (unvertrauenswürdige Eingabe) - vor der
        # Terminal-Ausgabe bereinigen, analog zu format_table() für DMARC.
        date_str = time.strftime("%Y-%m-%d", time.gmtime(r.date_begin))
        org_name = sanitize_field(r.org_name, max_len=30)
        domain = sanitize_field(r.policy_domain, max_len=30)
        policy_type = sanitize_field(r.policy_type, max_len=15)
        failure_types = sanitize_field(", ".join(sorted(set(r.failure_result_types))), max_len=40)
        lines_data.append(
            [date_str, org_name, domain, policy_type, str(r.successful_session_count), str(r.failure_count), failure_types]
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


def has_tls_failures(rows: list[TLSPolicyRow]) -> bool:
    return any(r.failure_count > 0 for r in rows)


def to_tls_json_dict(rows: list[TLSPolicyRow], days: int) -> dict:
    """Strukturierte Sicht für native Konsumenten (Menüleisten-App), analog
    zu to_json_dict() für DMARC. Eine flache Liste statt nach Tagen
    gruppiert - TLS-RPT-Reports sind bereits Policy-Zusammenfassungen pro
    Zeitraum, keine Einzel-Records wie bei DMARC."""
    policies = []
    for r in rows:
        policies.append(
            {
                "date": time.strftime("%Y-%m-%d", time.gmtime(r.date_begin)),
                "organization_name": sanitize_field(r.org_name, max_len=_MAX_JSON_FIELD_LEN),
                "policy_domain": sanitize_field(r.policy_domain, max_len=_MAX_JSON_FIELD_LEN),
                "policy_type": sanitize_field(r.policy_type, max_len=_MAX_JSON_FIELD_LEN),
                "successful_session_count": r.successful_session_count,
                "failure_count": r.failure_count,
                "failure_result_types": [
                    sanitize_field(t, max_len=_MAX_JSON_FIELD_LEN) for t in r.failure_result_types
                ],
            }
        )
    return {
        "days": days,
        "total_failure_count": sum(r.failure_count for r in rows),
        "policies": policies,
    }


@dataclass
class DayStat:
    date: str
    clean_count: int
    flagged_count: int


def collect_daily_stats(rows: list[ReportRow]) -> list[DayStat]:
    """Pro Tag saubere/auffällige Zahl, chronologisch aufsteigend (älteste
    zuerst) statt wie collect_rows() rückwärts - für eine Trendlinie von
    links nach rechts statt einer Liste mit dem neuesten Eintrag oben."""
    by_day: dict[str, list[ReportRow]] = {}
    for r in rows:
        day = time.strftime("%Y-%m-%d", time.gmtime(r.date_begin))
        by_day.setdefault(day, []).append(r)

    result = []
    for day in sorted(by_day.keys()):
        day_rows = by_day[day]
        flagged = sum(1 for r in day_rows if r.is_flagged)
        result.append(DayStat(date=day, clean_count=len(day_rows) - flagged, flagged_count=flagged))
    return result


@dataclass
class TLSDayStat:
    date: str
    successful_count: int
    failure_count: int


def collect_tls_daily_stats(tls_rows: list[TLSPolicyRow]) -> list[TLSDayStat]:
    """Pro Tag erfolgreiche/fehlgeschlagene TLS-Sitzungen, chronologisch
    aufsteigend - Pendant zu collect_daily_stats() für TLS-RPT statt DMARC."""
    by_day: dict[str, list[TLSPolicyRow]] = {}
    for r in tls_rows:
        day = time.strftime("%Y-%m-%d", time.gmtime(r.date_begin))
        by_day.setdefault(day, []).append(r)

    result = []
    for day in sorted(by_day.keys()):
        day_rows = by_day[day]
        result.append(
            TLSDayStat(
                date=day,
                successful_count=sum(r.successful_session_count for r in day_rows),
                failure_count=sum(r.failure_count for r in day_rows),
            )
        )
    return result


@dataclass
class DMARCReadiness:
    """Einschätzung pro Domain, ob eine Verschärfung der DMARC-Policy
    (Richtung reject) im Beobachtungszeitraum sicher gewesen wäre - keine
    Empfehlung, nur ein Blick auf bereits vorhandene Reports, nichts wird
    automatisch geändert.

    ready_for_reject prüft bewusst NICHT auf unbekannte IPs (unknown_ip) -
    das sind potenzielle Spoofing-Versuche, genau die soll eine schärfere
    Policy ja blockieren. Blockierend ist own_ip_auth_failures: bekannte,
    eigene Sende-IPs, die an SPF/DKIM scheitern - die würde eine
    schärfere Policy zusätzlich zu den eigentlichen Spoofing-Versuchen mit
    ausblenden. Zusätzlich muss der Beobachtungszeitraum zum tatsächlichen
    Sendevolumen passen (siehe _recommended_observation_days) - bei sehr
    wenig Sendevolumen tauchen seltene, aber echte eigene Absender
    (monatliche Rechnungen, Newsletter, ...) in einem kurzen Fenster u. U.
    gar nicht auf, ein "0 Fehlschläge"-Ergebnis wäre dann nicht wirklich
    aussagekräftig, auch wenn es technisch stimmt.

    observed_days ist bewusst NICHT das angefragte --days-Fenster selbst,
    sondern das tatsächliche Alter des ältesten Reports darin (bis
    until_ts) - sonst würde ein einfaches `stats --days 90` sofort "90
    Tage beobachtet" behaupten, selbst wenn die Domain real erst seit
    wenigen Tagen überhaupt Reports liefert."""

    domain: str
    current_policy: str | None
    current_pct: int | None
    total_count: int
    unknown_ip_failures: int
    own_ip_auth_failures: int
    avg_daily_volume: float
    recommended_observation_days: int
    observed_days: int
    ready_for_reject: bool


def _recommended_observation_days(avg_daily_volume: float) -> int:
    """Grobe, aber nach Sendevolumen gestaffelte Richtwerte für die nötige
    Mindestbeobachtungsdauer vor einer Verschärfung (DMARC Richtung
    reject, MTA-STS Richtung enforce) - kein fester Wert für alle, ein
    Postfach mit wenigen Mails pro Tag braucht deutlich länger, um
    Vertrauen zu rechtfertigen, als eines mit hohem täglichem Volumen."""
    if avg_daily_volume < 1:
        return 60
    if avg_daily_volume < 5:
        return 30
    return 14


def compute_dmarc_readiness(rows: list[ReportRow], days: int, until_ts: int) -> list[DMARCReadiness]:
    by_domain: dict[str, list[ReportRow]] = {}
    for r in rows:
        if r.domain:
            by_domain.setdefault(r.domain, []).append(r)

    result = []
    for domain, domain_rows in by_domain.items():
        latest = max(domain_rows, key=lambda r: r.date_begin)
        earliest = min(domain_rows, key=lambda r: r.date_begin)
        unknown_ip = sum(1 for r in domain_rows if REASON_UNKNOWN_IP in r.flag_reasons)
        own_ip_fail = sum(1 for r in domain_rows if REASON_OWN_IP_AUTH_FAIL in r.flag_reasons)
        # Tatsächlich beobachteter Zeitraum = Alter des ältesten Reports
        # innerhalb des Fensters, NICHT das angefragte --days selbst - sonst
        # würde ein einfaches "stats --days 90" sofort "90 Tage beobachtet"
        # behaupten, selbst wenn das Postfach real erst seit 10 Tagen
        # überhaupt Reports liefert.
        observed_days = max(1, (until_ts - earliest.date_begin) // 86400)
        avg_daily = len(domain_rows) / observed_days
        recommended_days = _recommended_observation_days(avg_daily)
        result.append(
            DMARCReadiness(
                domain=domain,
                current_policy=latest.policy_p or None,
                current_pct=latest.policy_pct,
                total_count=len(domain_rows),
                unknown_ip_failures=unknown_ip,
                own_ip_auth_failures=own_ip_fail,
                avg_daily_volume=avg_daily,
                recommended_observation_days=recommended_days,
                observed_days=observed_days,
                ready_for_reject=(
                    own_ip_fail == 0 and latest.policy_p != "reject" and observed_days >= recommended_days
                ),
            )
        )
    return result


@dataclass
class MTASTSReadiness:
    """Einschätzung, ob eine Verschärfung von MTA-STS (mode=testing auf
    mode=enforce) im Beobachtungszeitraum sicher gewesen wäre, basierend
    auf bereits gespeicherten TLS-RPT-Reports - keine Live-DNS-/HTTPS-
    Abfrage, `stats` bleibt dadurch ein reiner, lokaler Lesebefehl wie
    `report`/`tls-report`. has_data ist False, wenn im Zeitraum gar keine
    TLS-RPT-Reports vorliegen (z. B. enable_tls_rpt aus) - dann lässt sich
    nichts einschätzen, das ist kein "bereit". Gleiche
    Sendevolumen-Staffelung wie bei DMARC (siehe
    _recommended_observation_days) - wenige TLS-Sitzungen pro Tag
    bedeuten, dass ein kurzes "0 Fehlschläge"-Fenster noch nicht viele
    verschiedene empfangende Mailserver tatsächlich durchlaufen hat.
    observed_days ist wie bei DMARCReadiness das tatsächliche Alter des
    ältesten TLS-RPT-Reports, nicht das angefragte --days-Fenster."""

    total_failure_count: int
    has_data: bool
    avg_daily_volume: float
    recommended_observation_days: int
    observed_days: int
    ready_for_enforce: bool


def compute_mta_sts_readiness(tls_rows: list[TLSPolicyRow], days: int, until_ts: int) -> MTASTSReadiness:
    if not tls_rows:
        recommended_days = _recommended_observation_days(0.0)
        return MTASTSReadiness(
            total_failure_count=0, has_data=False, avg_daily_volume=0.0,
            recommended_observation_days=recommended_days, observed_days=0, ready_for_enforce=False,
        )
    # Siehe compute_dmarc_readiness oben: tatsächlich beobachteter Zeitraum
    # statt des bloß angefragten --days.
    earliest_ts = min(r.date_begin for r in tls_rows)
    observed_days = max(1, (until_ts - earliest_ts) // 86400)
    total_failures = sum(r.failure_count for r in tls_rows)
    total_sessions = sum(r.successful_session_count + r.failure_count for r in tls_rows)
    avg_daily = total_sessions / observed_days
    recommended_days = _recommended_observation_days(avg_daily)
    return MTASTSReadiness(
        total_failure_count=total_failures,
        has_data=True,
        avg_daily_volume=avg_daily,
        recommended_observation_days=recommended_days,
        observed_days=observed_days,
        ready_for_enforce=total_failures == 0 and observed_days >= recommended_days,
    )


def to_stats_json_dict(
    days: int,
    daily: list[DayStat],
    dmarc_readiness: list[DMARCReadiness],
    mta_sts_readiness: MTASTSReadiness,
    tls_daily: list[TLSDayStat] | None = None,
) -> dict:
    return {
        "days": days,
        "daily": [{"date": d.date, "clean_count": d.clean_count, "flagged_count": d.flagged_count} for d in daily],
        "tls_daily": [
            {"date": d.date, "successful_count": d.successful_count, "failure_count": d.failure_count}
            for d in (tls_daily or [])
        ],
        "dmarc_readiness": [
            {
                "domain": sanitize_field(r.domain, max_len=_MAX_JSON_FIELD_LEN),
                "current_policy": r.current_policy,
                "current_pct": r.current_pct,
                "total_count": r.total_count,
                "unknown_ip_failures": r.unknown_ip_failures,
                "own_ip_auth_failures": r.own_ip_auth_failures,
                "avg_daily_volume": r.avg_daily_volume,
                "recommended_observation_days": r.recommended_observation_days,
                "observed_days": r.observed_days,
                "ready_for_reject": r.ready_for_reject,
            }
            for r in dmarc_readiness
        ],
        "mta_sts_readiness": {
            "total_failure_count": mta_sts_readiness.total_failure_count,
            "has_data": mta_sts_readiness.has_data,
            "avg_daily_volume": mta_sts_readiness.avg_daily_volume,
            "recommended_observation_days": mta_sts_readiness.recommended_observation_days,
            "observed_days": mta_sts_readiness.observed_days,
            "ready_for_enforce": mta_sts_readiness.ready_for_enforce,
        },
    }
