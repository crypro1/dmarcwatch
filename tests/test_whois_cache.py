"""Lokaler WHOIS-Cache (dmarcwatch inspect --whois -> store.py -> Menüleiste).

Wichtig: get_all_cached_whois() macht selbst NIE eine Netzwerkanfrage - sie
liest nur, was `inspect --whois` vorher explizit dort abgelegt hat. Die
Menüleisten-App bekommt diesen Cache nur über menubar-json, nie direkten
DB-Zugriff auf Nachschlage-Logik.
"""
import sqlite3

from dmarcwatch.report import ReportRow, to_json_dict
from dmarcwatch.store import (
    SCHEMA_VERSION,
    connect,
    get_all_cached_whois,
    get_cached_whois,
    set_cached_whois,
)


def test_set_and_get_cached_whois_roundtrip(tmp_path):
    conn = connect(tmp_path / "dmarc.sqlite")
    assert get_cached_whois(conn, "209.85.208.69") is None

    set_cached_whois(conn, "209.85.208.69", "Google LLC")
    result = get_cached_whois(conn, "209.85.208.69")
    assert result is not None
    org, looked_up_at = result
    assert org == "Google LLC"
    assert looked_up_at > 0


def test_set_cached_whois_overwrites_previous_value(tmp_path):
    conn = connect(tmp_path / "dmarc.sqlite")
    set_cached_whois(conn, "209.85.208.69", "Old Name Inc")
    set_cached_whois(conn, "209.85.208.69", "Google LLC")
    org, _ = get_cached_whois(conn, "209.85.208.69")
    assert org == "Google LLC"


def test_get_all_cached_whois_returns_everything(tmp_path):
    conn = connect(tmp_path / "dmarc.sqlite")
    set_cached_whois(conn, "209.85.208.69", "Google LLC")
    set_cached_whois(conn, "2a01:111:f403:c200::5", "Microsoft Corporation")
    result = get_all_cached_whois(conn)
    assert result == {
        "209.85.208.69": "Google LLC",
        "2a01:111:f403:c200::5": "Microsoft Corporation",
    }


def test_v1_database_migrates_to_v2_without_data_loss(tmp_path):
    """Die reale Produktions-DB existierender Installationen liegt noch auf
    Schema v1 mit echten Daten - die Migration nach v2 (whois_cache-Tabelle)
    darf daran nichts verändern oder verlieren."""
    db_file = tmp_path / "dmarc.sqlite"

    # Schema v1 von Hand nachbauen, wie es vor dieser Änderung ausgeliefert wurde.
    raw_conn = sqlite3.connect(str(db_file))
    raw_conn.executescript(
        """
        CREATE TABLE reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_name TEXT NOT NULL, report_id TEXT NOT NULL, email TEXT NOT NULL DEFAULT '',
            domain TEXT NOT NULL, policy_p TEXT NOT NULL, policy_sp TEXT NOT NULL DEFAULT '',
            policy_np TEXT NOT NULL DEFAULT '', policy_pct INTEGER NOT NULL DEFAULT 100,
            policy_adkim TEXT NOT NULL DEFAULT 'r', policy_aspf TEXT NOT NULL DEFAULT 'r',
            date_begin INTEGER NOT NULL, date_end INTEGER NOT NULL, ingested_at INTEGER NOT NULL,
            UNIQUE(org_name, report_id)
        );
        CREATE TABLE records (
            id INTEGER PRIMARY KEY AUTOINCREMENT, report_id INTEGER NOT NULL REFERENCES reports(id),
            source_ip TEXT NOT NULL, count INTEGER NOT NULL, disposition TEXT NOT NULL,
            dkim_result TEXT NOT NULL, spf_result TEXT NOT NULL, header_from TEXT NOT NULL,
            envelope_to TEXT NOT NULL DEFAULT '', envelope_from TEXT NOT NULL DEFAULT '',
            auth_results_json TEXT NOT NULL DEFAULT '[]', is_own_ip INTEGER NOT NULL,
            is_flagged INTEGER NOT NULL, flag_reasons TEXT NOT NULL DEFAULT ''
        );
        """
    )
    raw_conn.execute(
        "INSERT INTO reports (org_name, report_id, domain, policy_p, date_begin, date_end, ingested_at) "
        "VALUES ('real-org', 'real-report-id', 'example.com', 'reject', 1700000000, 1700086399, 1700000000)"
    )
    raw_conn.execute("PRAGMA user_version = 1")
    raw_conn.commit()
    raw_conn.close()

    # Jetzt über den normalen connect() öffnen - muss automatisch auf v2 migrieren.
    conn = connect(db_file)
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    assert version == SCHEMA_VERSION

    # Alte Daten müssen unangetastet da sein.
    row = conn.execute("SELECT org_name, report_id FROM reports").fetchone()
    assert row == ("real-org", "real-report-id")

    # Neue Tabelle muss nutzbar sein.
    set_cached_whois(conn, "203.0.113.1", "Test Org")
    assert get_cached_whois(conn, "203.0.113.1")[0] == "Test Org"


def test_to_json_dict_includes_cached_whois_organization():
    rows = [
        ReportRow(
            date_begin=1700000000, org_name="google.com", source_ip="209.85.208.69",
            count=1, disposition="none", dkim="pass", spf="fail", envelope_to="",
            is_flagged=True, flag_reasons=["unknown_ip"],
        ),
        ReportRow(
            date_begin=1700000000, org_name="AMAZON-SES", source_ip="192.0.2.1",
            count=1, disposition="none", dkim="pass", spf="pass", envelope_to="",
            is_flagged=False, flag_reasons=[],
        ),
    ]
    data = to_json_dict(rows, days=7, whois_by_ip={"209.85.208.69": "Google LLC"})
    records = data["days_grouped"][0]["records"]
    by_ip = {r["source_ip"]: r for r in records}
    assert by_ip["209.85.208.69"]["whois_organization"] == "Google LLC"
    assert by_ip["192.0.2.1"]["whois_organization"] is None


def test_to_json_dict_without_whois_cache_defaults_to_none():
    rows = [
        ReportRow(
            date_begin=1700000000, org_name="google.com", source_ip="209.85.208.69",
            count=1, disposition="none", dkim="pass", spf="fail", envelope_to="",
            is_flagged=True, flag_reasons=["unknown_ip"],
        ),
    ]
    data = to_json_dict(rows, days=7)
    assert data["days_grouped"][0]["records"][0]["whois_organization"] is None
