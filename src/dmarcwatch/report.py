"""Tabellarische Zusammenfassung für die CLI (`dmarcwatch report`)."""
from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass, field

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
    # Nach Fehlertyp gewichtet mit failed_session_count (nicht einfach die
    # Anzahl der failure-details-Einträge) - ein einzelner Eintrag kann
    # hunderte Sitzungen abdecken, siehe compute_mta_sts_readiness.
    failure_type_counts: dict[str, int] = field(default_factory=dict)


def collect_tls_rows(conn: sqlite3.Connection, since_ts: int, until_ts: int) -> list[TLSPolicyRow]:
    rows = query_tls_policies(conn, since_ts, until_ts)
    result = []
    for r in rows:
        failure_result_types: list[str] = []
        failure_type_counts: dict[str, int] = {}
        if r["failure_count"] > 0:
            details = query_tls_failure_details(conn, r["id"])
            failure_result_types = [fd["result_type"] for fd in details]
            for fd in details:
                failure_type_counts[fd["result_type"]] = (
                    failure_type_counts.get(fd["result_type"], 0) + fd["failed_session_count"]
                )
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
                failure_type_counts=failure_type_counts,
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


MIN_SAMPLE_SIZE = 10
_RECENT_VOLUME_WINDOW_DAYS = 30
_REPORTING_GAP_MIN_DAYS = 7
_REPORTING_GAP_RATIO = 4


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


def _detect_reporting_gap(day_indices: list[int]) -> tuple[bool, int]:
    """Erkennt eine auffällig große Lücke ZWISCHEN Tagen mit mindestens
    einem Report - keine Reports bedeutet nicht dasselbe wie "geprüft und
    sauber", es kann genauso gut heißen, dass `fetch` zwischenzeitlich
    ausgefallen ist (abgelaufene IMAP-Zugangsdaten, kaputte Filterregel,
    ...) und schlicht nichts abgerufen wurde.

    Bewusst NUR Lücken zwischen tatsächlich vorhandenen Report-Tagen,
    nicht die Zeit vom letzten Report bis "jetzt" - reine Funkstille bis
    heute kann genauso gut bedeuten, dass eine Domain aktuell einfach
    wenig oder nichts verschickt (kein Alarmsignal, passiert nach einer
    Migration oder bei geringem Volumen ständig), während eine Lücke
    MITTEN in einer sonst regelmäßigen Historie (Reports davor und danach
    vorhanden) ein deutlich eindeutigeres Anzeichen für einen
    zwischenzeitlich ausgefallenen fetch ist.

    Kein fester Schwellenwert wie "7 Tage ohne Report", weil das bei
    ohnehin seltenem, aber völlig normalem Sendevolumen ständig falsch
    anschlagen würde - stattdessen relativ zum MEDIAN der sonst üblichen
    Lücken dieser Domain. Median statt Mittelwert ist hier wichtig: der
    Mittelwert wird durch genau die Ausreißer-Lücke verzerrt, die erkannt
    werden soll (eine einzelne 40-Tage-Lücke neben mehreren 1-Tage-Lücken
    hebt den Mittelwert schon so stark an, dass sie sich selbst
    unauffällig macht - der Median bleibt davon unbeeinflusst)."""
    unique_days = sorted(set(day_indices))
    if len(unique_days) < 3:
        return False, 0
    gaps = sorted(b - a for a, b in zip(unique_days, unique_days[1:]))
    mid = len(gaps) // 2
    median_gap = gaps[mid] if len(gaps) % 2 else (gaps[mid - 1] + gaps[mid]) / 2
    max_gap = gaps[-1]
    if max_gap >= max(_REPORTING_GAP_MIN_DAYS, median_gap * _REPORTING_GAP_RATIO):
        return True, max_gap
    return False, 0


def _next_dmarc_rollout_step(current_policy: str | None, current_pct: int | None) -> tuple[str, int] | None:
    """Nächster Schritt einer vorsichtigen, gestaffelten DMARC-Verschärfung
    in 25%-Schritten (p=none -> quarantine 25/50/75/100 -> reject
    25/50/75/100) statt eines einzigen Sprungs direkt auf p=reject;
    pct=100 - dem in der Praxis üblichen, empfohlenen Rollout-Ablauf.
    None, wenn bereits am Ziel (p=reject, pct=100) - current_pct zählt
    dafür genauso wie current_policy, ein Eintrag mit p=reject; pct=10
    ist NICHT fertig, auch wenn die Policy schon "reject" heißt."""
    policy = current_policy or "none"
    pct = current_pct if current_pct is not None else 0
    if policy not in ("quarantine", "reject"):
        return "quarantine", 25
    if policy == "quarantine":
        if pct < 100:
            return "quarantine", min(100, pct + 25)
        return "reject", 25
    if pct < 100:
        return "reject", min(100, pct + 25)
    return None


@dataclass
class DMARCReadiness:
    """Einschätzung pro Domain, ob der nächste Schritt einer gestaffelten
    DMARC-Verschärfung (siehe _next_dmarc_rollout_step) im
    Beobachtungszeitraum sicher gewesen wäre - keine automatische
    Änderung, nur ein Blick auf bereits vorhandene Reports.

    own_ip_auth_failures (bekannte, eigene Sende-IPs, die an SPF/DKIM
    scheitern) blockiert den nächsten Schritt, unknown_ip_failures
    (potenzielle Spoofing-Versuche) bewusst nicht - genau die soll eine
    schärfere Policy ja abfangen.

    Statt "keine einzige own_ip_auth_fail irgendwo im gewählten Fenster"
    zählt die Zeit seit dem JÜNGSTEN own_ip_auth_fail (clean_days) - ein
    einzelner alter Vorfall blockiert nicht unbegrenzt, sobald seitdem
    genug Zeit und Volumen vergangen sind (= observed_days, wenn nie
    einer auftrat). avg_daily_volume und damit
    recommended_observation_days basieren auf einem jüngeren Teilfenster
    (_RECENT_VOLUME_WINDOW_DAYS) statt dem gesamten beobachteten
    Zeitraum - sonst würde eine frühere, ruhigere Phase die nötige
    Wartezeit für eine Domain verzerren, die inzwischen deutlich mehr
    Post verschickt.

    total_count/unknown_ip_failures/own_ip_auth_failures zählen echte
    Nachrichten (Summe von ReportRow.count), nicht Report-Zeilen - eine
    Zeile kann hunderte Nachrichten derselben IP zusammenfassen.

    ready_for_next_step verlangt zusätzlich eine Mindest-Stichprobengröße
    (MIN_SAMPLE_SIZE echte Nachrichten) und keine auffällige
    Report-Lücke (has_reporting_gap) - viele verstrichene Tage mit kaum
    echten Nachrichten, oder eine Lücke, in der `fetch` vermutlich
    ausgefallen war, rechtfertigen kein "bereit".

    needs_recheck warnt unabhängig davon, wenn eine Domain BEREITS bei
    p=reject steht, aber ein own_ip_auth_fail jünger ist als
    recommended_observation_days - typischerweise ein Zeichen für einen
    neuen, noch nicht erfassten legitimen Absender oder ein kaputtes
    SPF/DKIM-Setup. own_ip_networks nachträglich anzupassen ändert nichts
    an bereits gespeicherten alten Reports, das zählt erst ab neuen.

    Wichtige Grenze, die dieses Feld NICHT auflöst: DMARC-Aggregate-
    Reporting ist branchenweit lückenhaft - nicht jeder Empfänger sendet
    Reports, manche nur stichprobenartig. "0 Fehlschläge" heißt immer nur
    "0 Fehlschläge unter dem, was uns gemeldet wurde", nie eine Garantie."""

    domain: str
    current_policy: str | None
    current_pct: int | None
    total_count: int
    unknown_ip_failures: int
    own_ip_auth_failures: int
    avg_daily_volume: float
    recommended_observation_days: int
    observed_days: int
    clean_days: int
    last_failure_date: str | None
    has_reporting_gap: bool
    reporting_gap_days: int
    next_recommended_policy: str | None
    next_recommended_pct: int | None
    fully_enforced: bool
    ready_for_next_step: bool
    needs_recheck: bool


def compute_dmarc_readiness(rows: list[ReportRow], days: int, until_ts: int) -> list[DMARCReadiness]:
    by_domain: dict[str, list[ReportRow]] = {}
    for r in rows:
        if r.domain:
            by_domain.setdefault(r.domain, []).append(r)

    result = []
    for domain, domain_rows in by_domain.items():
        latest = max(domain_rows, key=lambda r: r.date_begin)
        earliest = min(domain_rows, key=lambda r: r.date_begin)
        total_count = sum(r.count for r in domain_rows)
        unknown_ip = sum(r.count for r in domain_rows if REASON_UNKNOWN_IP in r.flag_reasons)
        own_ip_fail_rows = [r for r in domain_rows if REASON_OWN_IP_AUTH_FAIL in r.flag_reasons]
        own_ip_fail = sum(r.count for r in own_ip_fail_rows)

        # Tatsächlich beobachteter Zeitraum = Alter des ältesten Reports
        # innerhalb des Fensters, NICHT das angefragte --days selbst - sonst
        # würde ein einfaches "stats --days 90" sofort "90 Tage beobachtet"
        # behaupten, selbst wenn das Postfach real erst seit 10 Tagen
        # überhaupt Reports liefert.
        observed_days = max(1, (until_ts - earliest.date_begin) // 86400)

        if own_ip_fail_rows:
            last_failure_ts = max(r.date_begin for r in own_ip_fail_rows)
            clean_days = max(0, (until_ts - last_failure_ts) // 86400)
            last_failure_date = time.strftime("%Y-%m-%d", time.gmtime(last_failure_ts))
        else:
            clean_days = observed_days
            last_failure_date = None

        recent_window = min(observed_days, _RECENT_VOLUME_WINDOW_DAYS)
        recent_since = until_ts - recent_window * 86400
        recent_count = sum(r.count for r in domain_rows if r.date_begin >= recent_since)
        avg_daily = recent_count / recent_window
        recommended_days = _recommended_observation_days(avg_daily)

        has_gap, gap_days = _detect_reporting_gap([r.date_begin // 86400 for r in domain_rows])

        next_policy, next_pct = _next_dmarc_rollout_step(latest.policy_p or None, latest.policy_pct) or (None, None)
        fully_enforced = next_policy is None

        ready_for_next_step = (
            not fully_enforced
            and clean_days >= recommended_days
            and total_count >= MIN_SAMPLE_SIZE
            and not has_gap
        )
        needs_recheck = bool(
            (latest.policy_p or None) == "reject" and own_ip_fail and clean_days < recommended_days
        )

        result.append(
            DMARCReadiness(
                domain=domain,
                current_policy=latest.policy_p or None,
                current_pct=latest.policy_pct,
                total_count=total_count,
                unknown_ip_failures=unknown_ip,
                own_ip_auth_failures=own_ip_fail,
                avg_daily_volume=avg_daily,
                recommended_observation_days=recommended_days,
                observed_days=observed_days,
                clean_days=clean_days,
                last_failure_date=last_failure_date,
                has_reporting_gap=has_gap,
                reporting_gap_days=gap_days,
                next_recommended_policy=next_policy,
                next_recommended_pct=next_pct,
                fully_enforced=fully_enforced,
                ready_for_next_step=ready_for_next_step,
                needs_recheck=needs_recheck,
            )
        )
    return result


@dataclass
class MTASTSReadiness:
    """Pendant zu DMARCReadiness für MTA-STS (mode=testing auf
    mode=enforce), jetzt pro Domain statt über alle konfigurierten
    Domains hinweg zu einer einzigen Einschätzung zusammengefasst - sonst
    hätte eine zweite, komplett unabhängige Domain mit eigenen
    TLS-RPT-Reports die Einschätzung der ersten verwässert oder
    verfälscht.

    Basiert ausschließlich auf bereits gespeicherten TLS-RPT-Reports -
    keine Live-DNS-/HTTPS-Abfrage, `stats` bleibt dadurch ein reiner,
    lokaler Lesebefehl. Kann deshalb NICHT wissen, ob mode=enforce in der
    Zone bereits tatsächlich aktiv ist (das weiß nur der Live-Check in
    `verify-dns`) - anders als bei DMARC (policy_published in jedem
    Report) gibt es hier also kein fully_enforced/needs_recheck-Pendant.

    clean_days/observed_days/avg_daily_volume/has_reporting_gap folgen
    denselben Prinzipien wie bei DMARCReadiness (siehe dort): Zeit seit
    dem letzten TLS-Fehlschlag statt "keiner irgendwo im Fenster",
    Sendevolumen aus einem jüngeren Teilfenster, Report-Lücken-Erkennung,
    dieselbe Mindest-Stichprobengröße (jetzt auf echte TLS-Sitzungen
    bezogen). failure_types schlüsselt die gemeldeten Fehlschläge nach
    RFC-8460-Ergebnistyp auf, gewichtet mit den tatsächlich
    fehlgeschlagenen Sitzungen pro Eintrag (nicht nach Anzahl der
    failure-details-Einträge) - nicht jeder Typ bedeutet dasselbe (z. B.
    ein abgelaufenes eigenes Zertifikat vs. ein möglicherweise nur beim
    Empfänger aufgetretener Abrieffehler der Policy-Datei); eine
    automatische Bewertung wäre hier zu unsicher, deshalb nur die
    Aufschlüsselung statt einer eigenen Einstufung.

    Gleiche Grenze wie bei DMARC: TLS-RPT-Reporting ist ebenfalls
    branchenweit lückenhaft, "0 Fehlschläge" ist keine Garantie."""

    domain: str
    total_sessions: int
    total_failure_count: int
    failure_types: dict[str, int]
    avg_daily_volume: float
    recommended_observation_days: int
    observed_days: int
    clean_days: int
    last_failure_date: str | None
    has_reporting_gap: bool
    reporting_gap_days: int
    ready_for_enforce: bool


def compute_mta_sts_readiness(tls_rows: list[TLSPolicyRow], days: int, until_ts: int) -> list[MTASTSReadiness]:
    by_domain: dict[str, list[TLSPolicyRow]] = {}
    for r in tls_rows:
        if r.policy_domain:
            by_domain.setdefault(r.policy_domain, []).append(r)

    result = []
    for domain, domain_rows in by_domain.items():
        earliest_ts = min(r.date_begin for r in domain_rows)
        observed_days = max(1, (until_ts - earliest_ts) // 86400)

        failing_rows = [r for r in domain_rows if r.failure_count > 0]
        total_failures = sum(r.failure_count for r in domain_rows)
        failure_types: dict[str, int] = {}
        for r in domain_rows:
            for ftype, count in r.failure_type_counts.items():
                failure_types[ftype] = failure_types.get(ftype, 0) + count

        if failing_rows:
            last_failure_ts = max(r.date_begin for r in failing_rows)
            clean_days = max(0, (until_ts - last_failure_ts) // 86400)
            last_failure_date = time.strftime("%Y-%m-%d", time.gmtime(last_failure_ts))
        else:
            clean_days = observed_days
            last_failure_date = None

        recent_window = min(observed_days, _RECENT_VOLUME_WINDOW_DAYS)
        recent_since = until_ts - recent_window * 86400
        recent_sessions = sum(
            r.successful_session_count + r.failure_count for r in domain_rows if r.date_begin >= recent_since
        )
        avg_daily = recent_sessions / recent_window
        recommended_days = _recommended_observation_days(avg_daily)

        has_gap, gap_days = _detect_reporting_gap([r.date_begin // 86400 for r in domain_rows])

        total_sessions = sum(r.successful_session_count + r.failure_count for r in domain_rows)
        ready_for_enforce = clean_days >= recommended_days and total_sessions >= MIN_SAMPLE_SIZE and not has_gap

        result.append(
            MTASTSReadiness(
                domain=domain,
                total_sessions=total_sessions,
                total_failure_count=total_failures,
                failure_types=failure_types,
                avg_daily_volume=avg_daily,
                recommended_observation_days=recommended_days,
                observed_days=observed_days,
                clean_days=clean_days,
                last_failure_date=last_failure_date,
                has_reporting_gap=has_gap,
                reporting_gap_days=gap_days,
                ready_for_enforce=ready_for_enforce,
            )
        )
    return result


def to_stats_json_dict(
    days: int,
    daily: list[DayStat],
    dmarc_readiness: list[DMARCReadiness],
    mta_sts_readiness: list[MTASTSReadiness],
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
                "clean_days": r.clean_days,
                "last_failure_date": r.last_failure_date,
                "has_reporting_gap": r.has_reporting_gap,
                "reporting_gap_days": r.reporting_gap_days,
                "next_recommended_policy": r.next_recommended_policy,
                "next_recommended_pct": r.next_recommended_pct,
                "fully_enforced": r.fully_enforced,
                "ready_for_next_step": r.ready_for_next_step,
                "needs_recheck": r.needs_recheck,
            }
            for r in dmarc_readiness
        ],
        "mta_sts_readiness": [
            {
                "domain": sanitize_field(r.domain, max_len=_MAX_JSON_FIELD_LEN),
                "total_sessions": r.total_sessions,
                "total_failure_count": r.total_failure_count,
                "failure_types": {
                    sanitize_field(k, max_len=_MAX_JSON_FIELD_LEN): v for k, v in r.failure_types.items()
                },
                "avg_daily_volume": r.avg_daily_volume,
                "recommended_observation_days": r.recommended_observation_days,
                "observed_days": r.observed_days,
                "clean_days": r.clean_days,
                "last_failure_date": r.last_failure_date,
                "has_reporting_gap": r.has_reporting_gap,
                "reporting_gap_days": r.reporting_gap_days,
                "ready_for_enforce": r.ready_for_enforce,
            }
            for r in mta_sts_readiness
        ],
    }
