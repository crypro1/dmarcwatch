"""Dateirechte (Spezifikation 4.7): Verzeichnis 0700, DB und Logs 0600."""
import os
import stat

from dmarcwatch.config import write_default_config_if_missing
from dmarcwatch.logging_setup import setup_logging
from dmarcwatch.parser import parse_aggregate_report
from dmarcwatch.store import connect, ingest_report
from dmarcwatch.config import Config
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"


def _mode(path: Path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


def test_app_support_dir_is_0700(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    config_path = write_default_config_if_missing(tmp_path / "cfg" / "config.json")
    assert _mode(config_path.parent) == 0o700


def test_config_file_is_0600_on_creation(tmp_path):
    config_path = write_default_config_if_missing(tmp_path / "cfg" / "config.json")
    assert _mode(config_path) == 0o600


def test_config_file_permissions_are_re_tightened_if_already_loose(tmp_path):
    target = tmp_path / "cfg" / "config.json"
    target.parent.mkdir(parents=True)
    target.write_text("{}")
    os.chmod(target, 0o644)  # simuliert eine alte/laxe Datei
    assert _mode(target) == 0o644

    write_default_config_if_missing(target)
    assert _mode(target) == 0o600


def test_database_file_is_0600(tmp_path):
    db_file = tmp_path / "dmarc.sqlite"
    conn = connect(db_file)
    assert _mode(db_file) == 0o600

    config = Config.from_dict({"own_domains": ["example.com"], "own_ip_networks": ["192.0.2.0/24", "2001:db8:1::/48"]})
    xml = (FIXTURES / "ses_single_pass.xml").read_bytes()
    report = parse_aggregate_report(xml, config.max_xml_size_bytes)
    ingest_report(conn, report, config)
    assert _mode(db_file) == 0o600

    journal = db_file.with_name(db_file.name + "-journal")
    if journal.exists():
        assert _mode(journal) == 0o600

    conn.close()


def test_wal_mode_active_and_sidecar_files_secured(tmp_path):
    """Anders als die klassische Rollback-Journal-Datei erben die
    WAL-Begleitdateien (-wal, -shm) NICHT automatisch die 0600-Rechte der
    Hauptdatenbank (empirisch geprüft) - sie kommen sonst mit dem
    Standard-umask (0644, world-readable) und enthalten echte
    Report-Inhalte."""
    db_file = tmp_path / "dmarc.sqlite"
    conn = connect(db_file)

    mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
    assert mode == "wal"

    config = Config.from_dict({"own_domains": ["example.com"], "own_ip_networks": ["192.0.2.0/24"]})
    xml = (FIXTURES / "ses_single_pass.xml").read_bytes()
    report = parse_aggregate_report(xml, config.max_xml_size_bytes)
    ingest_report(conn, report, config)

    wal_file = db_file.with_name(db_file.name + "-wal")
    shm_file = db_file.with_name(db_file.name + "-shm")
    assert wal_file.exists() or shm_file.exists(), "WAL-Begleitdateien wurden nie angelegt"
    for sidecar in (wal_file, shm_file):
        if sidecar.exists():
            assert _mode(sidecar) == 0o600, f"{sidecar} ist nicht 0600"

    conn.close()


def test_log_file_is_0600(tmp_path):
    log_file = tmp_path / "logs" / "dmarcwatch.log"
    setup_logging(log_file)
    assert _mode(log_file) == 0o600
