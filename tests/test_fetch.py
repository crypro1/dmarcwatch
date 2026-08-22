"""Tests für die Verarbeitungslogik in fetch.py mit einem IMAP-Fake.

Ein echter IMAP-Server lässt sich hier nicht sinnvoll simulieren (siehe
Spezifikation Abschnitt 8); getestet wird die Verdrahtung: Anhänge
extrahieren, parsen, in die DB einspeisen, kaputte Nachrichten überspringen
ohne den Lauf abzubrechen, Nachrichten als verarbeitet markieren.
"""
from __future__ import annotations

import gzip
import logging
from email.message import EmailMessage
from pathlib import Path

import pytest

from dmarcwatch.config import Config
from dmarcwatch.fetch import FetchError, fetch_and_ingest
from dmarcwatch.store import connect, query_records

FIXTURES = Path(__file__).parent / "fixtures"


class FakeImap:
    """Minimaler Stand-in für imaplib.IMAP4_SSL, nur die genutzten Methoden."""

    def __init__(
        self,
        messages: dict[bytes, bytes],
        fake_sizes: dict[bytes, int] | None = None,
        select_status: str = "OK",
        list_response: list[bytes] | None = None,
    ):
        self._messages = messages
        # fake_sizes erlaubt es, eine vom tatsächlichen Inhalt abweichende
        # (oder unbestimmbare) RFC822.SIZE-Antwort zu simulieren.
        self._fake_sizes = fake_sizes or {}
        self._select_status = select_status
        self._list_response = list_response or []
        self.stored_flags: dict[bytes, str] = {}
        self.copied_to: list[tuple[bytes, str]] = []
        self.expunged = False
        self.created_folders: list[str] = []
        self.full_body_fetched: list[bytes] = []

    def select(self, folder):
        return self._select_status, [b""]

    def list(self):
        return "OK", self._list_response

    def search(self, charset, criteria):
        ids = b" ".join(sorted(self._messages.keys()))
        return "OK", [ids]

    def fetch(self, msg_id, spec):
        if "RFC822.SIZE" in spec:
            if msg_id in self._fake_sizes and self._fake_sizes[msg_id] is None:
                return "NO", []  # simuliert einen Server, der die Größe nicht liefert
            size = self._fake_sizes.get(msg_id, len(self._messages[msg_id]))
            return "OK", [b"%d (RFC822.SIZE %d)" % (int(msg_id), size)]
        self.full_body_fetched.append(msg_id)
        return "OK", [(b"1 (RFC822 {n})", self._messages[msg_id])]

    def store(self, msg_id, flags_cmd, flags):
        self.stored_flags[msg_id] = flags

    def copy(self, msg_id, folder):
        self.copied_to.append((msg_id, folder))
        return "OK", [b""]

    def expunge(self):
        self.expunged = True

    def create(self, folder):
        self.created_folders.append(folder)
        return "OK", [b""]


def _config() -> Config:
    return Config.from_dict(
        {
            "own_domains": ["example.com"],
            "own_ip_networks": ["192.0.2.0/24", "2001:db8:1::/48"],
            "imap_folder": "DMARC",
        }
    )


def _make_message(attachment_name: str, attachment_bytes: bytes) -> bytes:
    msg = EmailMessage()
    msg["From"] = "dmarc-noreply@google.com"
    msg["To"] = "dmarc@example.com"
    msg["Subject"] = "Report Domain: example.com"
    msg.set_content("DMARC aggregate report attached.")
    msg.add_attachment(
        attachment_bytes, maintype="application", subtype="gzip", filename=attachment_name
    )
    return bytes(msg)


def test_fetch_and_ingest_processes_valid_report_and_skips_broken_one(tmp_path):
    good_xml = (FIXTURES / "ses_single_pass.xml").read_bytes()
    good_attachment = gzip.compress(good_xml)
    good_msg = _make_message("report.xml.gz", good_attachment)

    broken_msg = _make_message("report.xml.gz", b"this is not valid gzip data")

    fake_imap = FakeImap({b"1": good_msg, b"2": broken_msg})
    db_conn = connect(tmp_path / "dmarc.sqlite")
    logger = logging.getLogger("dmarcwatch-test")
    logger.addHandler(logging.NullHandler())

    summary = fetch_and_ingest(_config(), fake_imap, db_conn, logger)

    assert summary.messages_seen == 2
    assert summary.reports_inserted == 1
    assert summary.attachments_skipped == 1
    assert len(summary.errors) == 1

    rows = query_records(db_conn, since_ts=0, until_ts=2_000_000_000)
    assert len(rows) == 1

    # Beide Nachrichten wurden als gelesen markiert, auch die kaputte -
    # sonst würde sie jeden Tag erneut versucht und ewig in UNSEEN bleiben.
    assert fake_imap.stored_flags[b"1"] == "(\\Seen)"
    assert fake_imap.stored_flags[b"2"] == "(\\Seen)"
    assert not fake_imap.expunged


def test_move_to_processed_folder_when_enabled(tmp_path):
    good_xml = (FIXTURES / "ses_single_pass.xml").read_bytes()
    good_msg = _make_message("report.xml.gz", gzip.compress(good_xml))
    fake_imap = FakeImap({b"1": good_msg})
    db_conn = connect(tmp_path / "dmarc.sqlite")
    logger = logging.getLogger("dmarcwatch-test")
    logger.addHandler(logging.NullHandler())

    config = Config.from_dict(
        {
            "own_domains": ["example.com"],
            "own_ip_networks": ["192.0.2.0/24", "2001:db8:1::/48"],
            "move_to_processed_folder": True,
            "processed_folder": "DMARC/verarbeitet",
        }
    )
    fetch_and_ingest(config, fake_imap, db_conn, logger)

    assert fake_imap.created_folders == ["DMARC/verarbeitet"]
    assert fake_imap.copied_to == [(b"1", "DMARC/verarbeitet")]
    assert fake_imap.expunged is True


def test_oversized_message_is_skipped_without_fetching_full_body(tmp_path):
    """Spezifikation 4.2/4.9: die Nachricht selbst ist unvertrauenswürdig,
    nicht nur ihre Anhänge. Eine zu große Nachricht darf nie mit RFC822 voll
    abgerufen werden, nur die Größe wird vorher geprüft."""
    good_xml = (FIXTURES / "ses_single_pass.xml").read_bytes()
    good_msg = _make_message("report.xml.gz", gzip.compress(good_xml))

    config = _config()
    huge_size = config.max_message_size_bytes + 1
    fake_imap = FakeImap({b"1": good_msg}, fake_sizes={b"1": huge_size})
    db_conn = connect(tmp_path / "dmarc.sqlite")
    logger = logging.getLogger("dmarcwatch-test")
    logger.addHandler(logging.NullHandler())

    summary = fetch_and_ingest(config, fake_imap, db_conn, logger)

    assert summary.messages_skipped_too_large == 1
    assert summary.reports_inserted == 0
    assert fake_imap.full_body_fetched == []  # RFC822 wurde nie abgerufen
    assert fake_imap.stored_flags[b"1"] == "(\\Seen)"  # trotzdem markiert, kein ewiges Retry

    rows = query_records(db_conn, since_ts=0, until_ts=2_000_000_000)
    assert len(rows) == 0


def test_message_with_unknown_size_is_skipped_fail_closed(tmp_path):
    """Wenn der Server RFC822.SIZE nicht sauber beantwortet, im Zweifel
    nicht verarbeiten (Spezifikation 4.9), nicht großzügig durchwinken."""
    good_xml = (FIXTURES / "ses_single_pass.xml").read_bytes()
    good_msg = _make_message("report.xml.gz", gzip.compress(good_xml))

    fake_imap = FakeImap({b"1": good_msg}, fake_sizes={b"1": None})
    db_conn = connect(tmp_path / "dmarc.sqlite")
    logger = logging.getLogger("dmarcwatch-test")
    logger.addHandler(logging.NullHandler())

    summary = fetch_and_ingest(_config(), fake_imap, db_conn, logger)

    assert summary.messages_skipped_too_large == 1
    assert fake_imap.full_body_fetched == []
    assert fake_imap.stored_flags[b"1"] == "(\\Seen)"


def test_folder_not_found_error_lists_available_folders(tmp_path):
    """Wenn imap_folder nicht stimmt (z. B. weil der Ordner server-seitig
    unter INBOX/... statt als Top-Level-Ordner liegt), soll die
    Fehlermeldung die tatsächlichen Ordnernamen zeigen statt nur
    'konnte nicht geöffnet werden' - das war für den echten mailbox.org-
    Account genau das Problem (DMARC lag unter Eingang/DMARC)."""
    fake_imap = FakeImap(
        {},
        select_status="NO",
        list_response=[
            b'(\\HasNoChildren) "/" INBOX',
            b'(\\HasChildren) "/" "INBOX/DMARC"',
            b'(\\HasNoChildren) "/" "INBOX/Sent"',
        ],
    )
    db_conn = connect(tmp_path / "dmarc.sqlite")
    logger = logging.getLogger("dmarcwatch-test")
    logger.addHandler(logging.NullHandler())

    with pytest.raises(FetchError) as exc_info:
        fetch_and_ingest(_config(), fake_imap, db_conn, logger)

    message = str(exc_info.value)
    assert "DMARC" in message
    assert "INBOX/DMARC" in message
