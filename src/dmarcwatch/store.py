"""SQLite-Speicher für DMARC Reports.

- Deduplizierung über (org_name, report_id) als Unique Constraint
- Ausschließlich parametrisierte SQL-Statements, keine String-Verkettung
- Schema versioniert über PRAGMA user_version, Migrationen vorgesehen
- Reports fremder Domains werden verworfen
"""
from __future__ import annotations

import json
import os
import sqlite3
import stat
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from .anomaly import evaluate_record
from .config import Config
from .models import AggregateReport

SCHEMA_VERSION = 2


def _migrate_v1(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_name TEXT NOT NULL,
            report_id TEXT NOT NULL,
            email TEXT NOT NULL DEFAULT '',
            domain TEXT NOT NULL,
            policy_p TEXT NOT NULL,
            policy_sp TEXT NOT NULL DEFAULT '',
            policy_np TEXT NOT NULL DEFAULT '',
            policy_pct INTEGER NOT NULL DEFAULT 100,
            policy_adkim TEXT NOT NULL DEFAULT 'r',
            policy_aspf TEXT NOT NULL DEFAULT 'r',
            date_begin INTEGER NOT NULL,
            date_end INTEGER NOT NULL,
            ingested_at INTEGER NOT NULL,
            UNIQUE(org_name, report_id)
        );

        CREATE TABLE records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id INTEGER NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
            source_ip TEXT NOT NULL,
            count INTEGER NOT NULL,
            disposition TEXT NOT NULL,
            dkim_result TEXT NOT NULL,
            spf_result TEXT NOT NULL,
            header_from TEXT NOT NULL,
            envelope_to TEXT NOT NULL DEFAULT '',
            envelope_from TEXT NOT NULL DEFAULT '',
            auth_results_json TEXT NOT NULL DEFAULT '[]',
            is_own_ip INTEGER NOT NULL,
            is_flagged INTEGER NOT NULL,
            flag_reasons TEXT NOT NULL DEFAULT ''
        );

        CREATE INDEX idx_records_report ON records(report_id);
        CREATE INDEX idx_reports_date_end ON reports(date_end);
        CREATE INDEX idx_records_flagged ON records(is_flagged);
        """
    )


def _migrate_v2(conn: sqlite3.Connection) -> None:
    # Lokaler Cache für explizit angefragte WHOIS/RDAP-Ergebnisse
    # (`dmarcwatch inspect --whois`). Rein informativ, siehe whois.py - wird
    # nie automatisch befüllt, nur wenn die Person das Flag selbst setzt.
    # Die Menüleisten-App liest diese Tabelle nur, ruft aber selbst nie
    # rdap.org auf (kein Netzverkehr aus dem dauerhaft laufenden Prozess).
    conn.executescript(
        """
        CREATE TABLE whois_cache (
            source_ip TEXT PRIMARY KEY,
            organization TEXT NOT NULL,
            looked_up_at INTEGER NOT NULL
        );
        """
    )


MIGRATIONS = {1: _migrate_v1, 2: _migrate_v2}


def get_cached_whois(conn: sqlite3.Connection, source_ip: str) -> tuple[str, int] | None:
    row = conn.execute(
        "SELECT organization, looked_up_at FROM whois_cache WHERE source_ip = ?", (source_ip,)
    ).fetchone()
    if row is None:
        return None
    return row[0], row[1]


def set_cached_whois(conn: sqlite3.Connection, source_ip: str, organization: str) -> None:
    with conn:
        conn.execute(
            """
            INSERT INTO whois_cache (source_ip, organization, looked_up_at)
            VALUES (?, ?, ?)
            ON CONFLICT(source_ip) DO UPDATE SET
                organization = excluded.organization,
                looked_up_at = excluded.looked_up_at
            """,
            (source_ip, organization, int(time.time())),
        )
    secure_wal_sidecar_files(conn)


def get_all_cached_whois(conn: sqlite3.Connection) -> dict[str, str]:
    """Für die Menüleisten-App: alle bereits per `inspect --whois`
    nachgeschlagenen IPs in einem Rutsch, ohne selbst irgendeinen
    Netzzugriff zu machen - reines Lesen aus der lokalen Datenbank."""
    rows = conn.execute("SELECT source_ip, organization FROM whois_cache").fetchall()
    return {row[0]: row[1] for row in rows}


def get_known_dkim_selectors(conn: sqlite3.Connection, domain: str) -> list[str]:
    """DKIM-Selektoren, die in echten, bereits abgerufenen Reports für
    `domain` tatsächlich beobachtet wurden - für `dmarcwatch verify-dns`
    (dns_verify.py). Reines Lesen aus der lokalen DB, kein Netzzugriff.

    Bewusst nicht gegen eine feste Liste "üblicher" Selektor-Namen raten
    (was andere Tools i. d. R. tun) - reale, aus eigenen Reports bekannte
    Selektoren sind zuverlässiger als eine geratene, zwangsläufig
    unvollständige Liste."""
    rows = conn.execute(
        """
        SELECT records.auth_results_json
        FROM records
        JOIN reports ON reports.id = records.report_id
        WHERE reports.domain = ?
        """,
        (domain,),
    ).fetchall()

    domain_lower = domain.strip().lower()
    selectors: set[str] = set()
    for (auth_results_raw,) in rows:
        try:
            auth_results = json.loads(auth_results_raw)
        except (TypeError, ValueError):
            continue
        for dkim_entry in auth_results.get("dkim", []):
            # Ein Record kann mehrere <dkim>-Einträge haben (z. B. bei
            # Weiterleitung über eine andere Domain) - nur Selektoren
            # übernehmen, deren DKIM-Signatur tatsächlich für `domain`
            # selbst war, nicht für eine fremde Domain im selben Record.
            if dkim_entry.get("domain", "").strip().lower() != domain_lower:
                continue
            selector = dkim_entry.get("selector", "")
            if selector:
                selectors.add(selector)
    return sorted(selectors)


def _ensure_secure_file(path: Path) -> None:
    if path.exists():
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0600


def secure_wal_sidecar_files(conn: sqlite3.Connection) -> None:
    """Sichert die WAL-Begleitdateien (-wal, -shm) auf 0600.

    Anders als die klassische Rollback-Journal-Datei erben sie NICHT
    automatisch die Rechte der Hauptdatenbank (empirisch geprüft), sondern
    kommen mit dem Standard-umask (i. d. R. 0644, world-readable) - und
    enthalten echte Report-Inhalte. Sie entstehen teils erst beim ersten
    echten Schreibzugriff, nicht zwingend schon bei connect() - deshalb
    wird das nicht nur einmal, sondern nach jedem Schreibvorgang
    durchgesetzt (gleiches Prinzip wie bei config.py: immer durchsetzen,
    nicht nur bei Neuanlage). Der Datenbankpfad wird aus der Verbindung
    selbst gelesen (PRAGMA database_list), damit das von überall aus
    aufrufbar ist, ohne den Pfad separat mitschleppen zu müssen.
    """
    row = conn.execute("PRAGMA database_list").fetchone()
    db_file = row[2] if row else None
    if not db_file:
        return
    base = Path(db_file)
    for suffix in ("-wal", "-shm"):
        sidecar = base.with_name(base.name + suffix)
        if sidecar.exists():
            os.chmod(sidecar, stat.S_IRUSR | stat.S_IWUSR)  # 0600


def connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(db_path.parent, stat.S_IRWXU)  # 0700
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA foreign_keys = ON")
    # WAL statt des Standard-Rollback-Journals: echtes nicht-blockierendes
    # Nebeneinander von Lesen (Menüleisten-App, alle paar Minuten) und
    # Schreiben (täglicher fetch-Lauf, Bruchteile einer Sekunde) - mit dem
    # Standard-Journal würde ein Schreibzugriff Leser kurz blockieren statt
    # umgekehrt. journal_mode=WAL gibt den tatsächlich aktiven Modus zurück;
    # auf sehr seltenen Dateisystemen (z. B. Netzwerkfreigaben) kann WAL
    # nicht greifen, dann bleibt SQLite beim Standard-Journal - kein Fehler,
    # nur weniger Nebenläufigkeit.
    conn.execute("PRAGMA journal_mode = WAL")
    _migrate(conn)
    _ensure_secure_file(db_path)
    secure_wal_sidecar_files(conn)
    return conn


def _migrate(conn: sqlite3.Connection) -> None:
    current = conn.execute("PRAGMA user_version").fetchone()[0]
    for version in range(current + 1, SCHEMA_VERSION + 1):
        migrate_fn = MIGRATIONS[version]
        with conn:
            migrate_fn(conn)
            conn.execute(f"PRAGMA user_version = {int(version)}")


class IngestStatus(str, Enum):
    INSERTED = "inserted"
    DUPLICATE = "duplicate"
    REJECTED_FOREIGN_DOMAIN = "rejected_foreign_domain"


@dataclass
class IngestResult:
    status: IngestStatus
    report_row_id: int | None = None
    flagged_count: int = 0
    total_records: int = 0


def ingest_report(conn: sqlite3.Connection, report: AggregateReport, config: Config) -> IngestResult:
    if not config.is_own_domain(report.policy_published.domain):
        return IngestResult(status=IngestStatus.REJECTED_FOREIGN_DOMAIN)

    try:
        return _ingest_report_inner(conn, report, config)
    finally:
        # Nach jedem Schreibversuch (auch bei DUPLICATE, das ist trotzdem
        # eine Transaktion), nicht nur einmal bei connect() - die
        # WAL-Begleitdateien können erst hier entstehen.
        secure_wal_sidecar_files(conn)


def _ingest_report_inner(conn: sqlite3.Connection, report: AggregateReport, config: Config) -> IngestResult:
    with conn:
        cur = conn.execute(
            """
            INSERT OR IGNORE INTO reports
                (org_name, report_id, email, domain, policy_p, policy_sp, policy_np,
                 policy_pct, policy_adkim, policy_aspf, date_begin, date_end, ingested_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                report.metadata.org_name,
                report.metadata.report_id,
                report.metadata.email,
                report.policy_published.domain,
                report.policy_published.p,
                report.policy_published.sp,
                report.policy_published.np,
                report.policy_published.pct,
                report.policy_published.adkim,
                report.policy_published.aspf,
                report.metadata.date_begin,
                report.metadata.date_end,
                int(time.time()),
            ),
        )
        if cur.rowcount == 0:
            # UNIQUE(org_name, report_id) hat zugeschlagen: bereits vorhanden.
            return IngestResult(status=IngestStatus.DUPLICATE)

        report_row_id = cur.lastrowid
        flagged_count = 0
        for record in report.records:
            reasons = evaluate_record(record, config)
            is_flagged = len(reasons) > 0
            if is_flagged:
                flagged_count += 1
            auth_results_json = json.dumps(
                {
                    "dkim": [
                        {"domain": d.domain, "selector": d.selector, "result": d.result}
                        for d in record.auth_results.dkim
                    ],
                    "spf": [
                        {"domain": s.domain, "result": s.result}
                        for s in record.auth_results.spf
                    ],
                },
                ensure_ascii=False,
            )
            conn.execute(
                """
                INSERT INTO records
                    (report_id, source_ip, count, disposition, dkim_result, spf_result,
                     header_from, envelope_to, envelope_from, auth_results_json,
                     is_own_ip, is_flagged, flag_reasons)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    report_row_id,
                    record.source_ip,
                    record.count,
                    record.policy_evaluated.disposition,
                    record.policy_evaluated.dkim,
                    record.policy_evaluated.spf,
                    record.identifiers.header_from,
                    record.identifiers.envelope_to,
                    record.identifiers.envelope_from,
                    auth_results_json,
                    1 if config.is_own_ip(record.source_ip) else 0,
                    1 if is_flagged else 0,
                    ",".join(reasons),
                ),
            )

        return IngestResult(
            status=IngestStatus.INSERTED,
            report_row_id=report_row_id,
            flagged_count=flagged_count,
            total_records=len(report.records),
        )


def query_records(
    conn: sqlite3.Connection,
    since_ts: int,
    until_ts: int,
    only_flagged: bool = False,
) -> list[sqlite3.Row]:
    conn.row_factory = sqlite3.Row
    sql = """
        SELECT r.id, r.source_ip, r.count, r.disposition, r.dkim_result, r.spf_result,
               r.header_from, r.envelope_to, r.envelope_from, r.is_own_ip, r.is_flagged,
               r.flag_reasons, rep.org_name, rep.report_id, rep.domain, rep.date_begin,
               rep.date_end
        FROM records r
        JOIN reports rep ON rep.id = r.report_id
        WHERE rep.date_end >= ? AND rep.date_begin <= ?
    """
    params: list[object] = [since_ts, until_ts]
    if only_flagged:
        sql += " AND r.is_flagged = 1"
    sql += " ORDER BY rep.date_begin ASC, r.source_ip ASC"
    return conn.execute(sql, params).fetchall()
