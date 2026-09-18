"""Schema-Migrationen (store.py:_migrate) - Atomarität und der
Downgrade-Guard. Reine DB-Mechanik, unabhängig vom DMARC-/TLS-RPT-Ingest,
der bereits in test_store.py geprüft wird.
"""
import sqlite3

import pytest

from dmarcwatch.store import SCHEMA_VERSION, _migrate, connect


def test_fresh_database_migrates_to_current_schema_version(tmp_path):
    conn = connect(tmp_path / "fresh.db")
    assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    assert {"reports", "records", "whois_cache", "tls_reports", "tls_policies", "blacklist_cache"} <= tables
    conn.close()


def test_reconnect_is_a_no_op(tmp_path):
    path = tmp_path / "reconnect.db"
    connect(path).close()
    conn = connect(path)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    conn.close()


def test_migration_interrupted_partway_leaves_no_trace(tmp_path):
    """Kernregression: conn.executescript() committet laut sqlite3-Doku
    eine offene Transaktion sofort implizit und führt sonst KEINE eigene
    Transaktionskontrolle aus - ein umgebendes `with conn:` ist dadurch für
    das Script selbst wirkungslos. Ohne ein eigenes BEGIN/COMMIT INNERHALB
    jeder _migrate_vN-Funktion bliebe ein mitten im Script abgebrochenes
    CREATE TABLE (Stromausfall, volle Platte, ...) dauerhaft halb
    angewendet, während PRAGMA user_version noch die alte Version zeigt -
    jeder künftige Start würde dieselbe Migration erneut versuchen und an
    "table already exists" scheitern (Boot-Loop, empirisch nachgestellt
    und bestätigt).

    Testet die ECHTEN _migrate_v1..v4-Funktionen aus store.py (kein
    Ersatz-Script) - der Fehler wird über eine vorab angelegte, kollidierende
    Tabelle ausgelöst: _migrate_v3 legt tls_reports, tls_policies und erst
    danach tls_failure_details an; eine vorab existierende
    tls_failure_details lässt das Script mitten drin scheitern, genau wie
    ein echter Absturz zwischen zwei CREATE TABLE-Anweisungen."""
    path = tmp_path / "interrupted.db"
    conn = sqlite3.connect(str(path))
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA user_version = 2")  # v1+v2 bereits "angewendet"
    conn.execute("CREATE TABLE tls_failure_details (already_here INTEGER)")
    conn.commit()

    with pytest.raises(sqlite3.OperationalError, match="already exists"):
        _migrate(conn)

    # v3 muss beim CREATE TABLE tls_failure_details scheitern - tls_reports
    # und tls_policies (davor im selben Script) dürfen dann NICHT übrig
    # bleiben, sonst genau der Boot-Loop aus der Beschreibung oben.
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 2
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    assert "tls_reports" not in tables
    assert "tls_policies" not in tables
    conn.close()

    # Neustart mit frischer Connection simulieren (wie nach einem Absturz) -
    # nichts davon darf durable persistiert worden sein.
    conn2 = sqlite3.connect(str(path))
    tables_after_restart = {r[0] for r in conn2.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    assert "tls_reports" not in tables_after_restart
    assert "tls_policies" not in tables_after_restart
    conn2.close()


def test_migration_retry_after_interruption_succeeds(tmp_path):
    """Fortsetzung des Szenarios oben: entfernt man die kollidierende
    Tabelle (in der Realität: der eigentliche Grund für den Absturz ist
    behoben, z. B. genug Plattenplatz frei), muss ein erneuter Lauf mit
    einer frischen Connection sauber durchlaufen - genau das, was ein
    Neustart der App nach einem Absturz real täte. Kein "table already
    exists" mehr, weil v3 beim ersten Versuch keine Spur hinterlassen hat."""
    path = tmp_path / "retry.db"
    conn = sqlite3.connect(str(path))
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA user_version = 2")
    conn.execute("CREATE TABLE tls_failure_details (already_here INTEGER)")
    conn.commit()
    with pytest.raises(sqlite3.OperationalError):
        _migrate(conn)
    conn.close()

    # Kollidierende Tabelle "beheben" und mit frischer Connection neu
    # versuchen - simuliert einen App-Neustart nach einem Absturz.
    conn2 = sqlite3.connect(str(path))
    conn2.execute("DROP TABLE tls_failure_details")
    conn2.commit()
    _migrate(conn2)
    assert conn2.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    tables = {r[0] for r in conn2.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    assert {"tls_reports", "tls_policies", "tls_failure_details", "blacklist_cache"} <= tables
    conn2.close()


def test_schema_newer_than_supported_raises(tmp_path):
    """Downgrade-Guard: eine Datenbank, die zuvor von einer neueren
    dmarcwatch-Version geöffnet wurde, darf nicht stillschweigend auf
    einem Schema weiterarbeiten, das diese Version nicht kennt."""
    path = tmp_path / "future.db"
    connect(path).close()
    conn = sqlite3.connect(str(path))
    conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 1}")
    conn.commit()
    conn.close()

    with pytest.raises(RuntimeError, match="neuer als die unterstützte Version"):
        connect(path)
