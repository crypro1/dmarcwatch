"""IMAP-Abruf von DMARC Aggregate Reports.

Sicherheitsanforderungen (Spezifikation Abschnitt 4.2):
- imaplib.IMAP4_SSL mit ssl.create_default_context(), Zertifikats- und
  Hostname-Prüfung aktiv, keine Option zum Abschalten
- mindestens TLS 1.2
- ausschließlich Verbindungen zum konfigurierten IMAP-Host, sonst kein
  Netzverkehr

Netzwerkfehler (Verbindungsaufbau, Login, IMAP-Protokollfehler) werden NICHT
abgefangen und laufen bis zum Aufrufer durch (4.9: Abbruch mit Exit-Code
ungleich 0, kein stilles Verschlucken). Fehler bei einzelnen Nachrichten
oder Anhängen (kaputtes Archiv, kaputtes XML) werden dagegen abgefangen,
protokolliert und übersprungen, damit ein einzelner böswilliger oder
defekter Report den Lauf nicht abbricht.
"""
from __future__ import annotations

import email
import imaplib
import logging
import re
import ssl
from dataclasses import dataclass, field
from email.message import Message

from .archive import ArchiveError, extract_report_xml
from .config import Config
from .parser import ReportParseError, parse_aggregate_report
from .sanitize import mask_email
from .store import IngestStatus, ingest_report

_ATTACHMENT_EXTENSIONS = (".gz", ".zip", ".xml")
_SIZE_RE = re.compile(rb"RFC822\.SIZE\s+(\d+)")
# IMAP LIST-Antwortzeile: (flags) "delimiter" name - name kann in
# Anführungszeichen stehen oder nicht.
_LIST_RE = re.compile(r'^\(.*?\)\s+"(?:[^"\\]|\\.)*"\s+(.*)$')


class FetchError(RuntimeError):
    """Netzwerk-/Protokollfehler, die den Lauf abbrechen sollen."""


@dataclass
class FetchSummary:
    messages_seen: int = 0
    messages_skipped_too_large: int = 0
    attachments_processed: int = 0
    attachments_skipped: int = 0
    reports_inserted: int = 0
    reports_duplicate: int = 0
    reports_rejected_foreign: int = 0
    flagged_count: int = 0
    errors: list[str] = field(default_factory=list)


def build_ssl_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    # create_default_context() aktiviert bereits check_hostname und
    # CERT_REQUIRED. Wird hier nicht verändert - es gibt bewusst keine
    # Konfigurationsoption, das abzuschalten.
    return context


def connect_imap(config: Config, password: str) -> imaplib.IMAP4_SSL:
    context = build_ssl_context()
    try:
        conn = imaplib.IMAP4_SSL(config.imap_host, config.imap_port, ssl_context=context)
        conn.login(config.imap_user, password)
    except (OSError, imaplib.IMAP4.error, ssl.SSLError) as exc:
        raise FetchError(f"IMAP-Verbindung zu {config.imap_host} fehlgeschlagen: {exc}") from exc
    return conn


def _iter_attachments(msg: Message):
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if not filename:
            continue
        if not filename.lower().endswith(_ATTACHMENT_EXTENSIONS):
            continue
        payload = part.get_payload(decode=True)
        if payload is None:
            continue
        yield filename, payload


def _get_message_size(conn: imaplib.IMAP4_SSL, msg_id: bytes) -> int | None:
    """Fragt die Nachrichtengröße über IMAP ab, ohne den Body zu laden.

    Jeder kann eine Mail an die rua-Adresse schicken (Spezifikation
    Abschnitt 4), die Nachricht selbst ist also unvertrauenswürdig - nicht
    nur ihre Anhänge. RFC822.SIZE lässt sich abfragen, ohne den Body über
    die Leitung zu holen, und erlaubt damit eine Obergrenze VOR dem
    eigentlichen Abruf.
    """
    try:
        status, data = conn.fetch(msg_id, "(RFC822.SIZE)")
    except imaplib.IMAP4.error:
        return None
    if status != "OK" or not data or not isinstance(data[0], bytes):
        return None
    match = _SIZE_RE.search(data[0])
    if not match:
        return None
    return int(match.group(1))


def _ensure_processed_folder(conn: imaplib.IMAP4_SSL, folder: str, logger: logging.Logger) -> None:
    status, _ = conn.create(folder)
    # status ist "NO", wenn der Ordner schon existiert - das ist kein Fehler.
    if status not in ("OK", "NO"):
        logger.warning("Konnte Ordner %r nicht anlegen (status=%s)", folder, status)


def _list_folders(conn: imaplib.IMAP4_SSL) -> list[str]:
    """Listet die tatsächlichen IMAP-Ordnernamen für eine bessere
    Fehlermeldung, wenn imap_folder nicht stimmt (z. B. weil der Ordner
    server-seitig unter INBOX/... statt als Top-Level-Ordner liegt)."""
    try:
        status, data = conn.list()
    except imaplib.IMAP4.error:
        return []
    if status != "OK" or not data:
        return []
    names = []
    for entry in data:
        if not isinstance(entry, bytes):
            continue
        text = entry.decode("utf-8", errors="replace")
        match = _LIST_RE.match(text)
        if not match:
            continue
        name = match.group(1).strip()
        if name.startswith('"') and name.endswith('"'):
            name = name[1:-1]
        names.append(name)
    return names


def fetch_and_ingest(
    config: Config,
    imap_conn: imaplib.IMAP4_SSL,
    db_conn,
    logger: logging.Logger,
) -> FetchSummary:
    summary = FetchSummary()

    status, _ = imap_conn.select(config.imap_folder)
    if status != "OK":
        available = _list_folders(imap_conn)
        hint = f" Verfügbare Ordner: {', '.join(available)}" if available else ""
        raise FetchError(f"Ordner {config.imap_folder!r} konnte nicht geöffnet werden.{hint}")

    if config.move_to_processed_folder:
        _ensure_processed_folder(imap_conn, config.processed_folder, logger)

    status, data = imap_conn.search(None, "UNSEEN")
    if status != "OK":
        raise FetchError("IMAP-Suche nach ungelesenen Nachrichten fehlgeschlagen")

    message_ids = data[0].split() if data and data[0] else []
    logger.info("%d ungelesene Nachricht(en) im Ordner %r", len(message_ids), config.imap_folder)

    for msg_id in message_ids:
        summary.messages_seen += 1

        size = _get_message_size(imap_conn, msg_id)
        if size is None or size > config.max_message_size_bytes:
            logger.warning(
                "Nachricht %r übersprungen: Größe %s über Obergrenze %d Bytes oder nicht bestimmbar",
                msg_id,
                size,
                config.max_message_size_bytes,
            )
            summary.messages_skipped_too_large += 1
            summary.errors.append(f"message {msg_id!r}: zu groß oder Größe nicht bestimmbar ({size})")
            _mark_processed(imap_conn, msg_id, config, logger)
            continue

        try:
            status, msg_data = imap_conn.fetch(msg_id, "(RFC822)")
        except imaplib.IMAP4.error as exc:
            raise FetchError(f"Abruf von Nachricht {msg_id!r} fehlgeschlagen: {exc}") from exc
        if status != "OK" or not msg_data or not isinstance(msg_data[0], tuple):
            logger.warning("Nachricht %r konnte nicht gelesen werden, übersprungen", msg_id)
            summary.errors.append(f"message {msg_id!r}: fetch fehlgeschlagen")
            continue

        raw_bytes = msg_data[0][1]
        msg = email.message_from_bytes(raw_bytes)
        logger.debug("Verarbeite Nachricht %r von %s", msg_id, mask_email(msg.get("From", "")))

        found_attachment = False
        for filename, payload in _iter_attachments(msg):
            found_attachment = True
            try:
                xml_bytes = extract_report_xml(
                    filename, payload, config.max_attachment_size_bytes, config.max_xml_size_bytes
                )
                report = parse_aggregate_report(
                    xml_bytes, config.max_xml_size_bytes, config.max_records_per_report
                )
                result = ingest_report(db_conn, report, config)
            except (ArchiveError, ReportParseError) as exc:
                logger.warning("Anhang %r in Nachricht %r übersprungen: %s", filename, msg_id, exc)
                summary.attachments_skipped += 1
                summary.errors.append(f"{filename}: {exc}")
                continue

            summary.attachments_processed += 1
            if result.status == IngestStatus.INSERTED:
                summary.reports_inserted += 1
                summary.flagged_count += result.flagged_count
            elif result.status == IngestStatus.DUPLICATE:
                summary.reports_duplicate += 1
            elif result.status == IngestStatus.REJECTED_FOREIGN_DOMAIN:
                summary.reports_rejected_foreign += 1
                logger.warning(
                    "Report in Anhang %r für fremde Domain verworfen (Nachricht %r)", filename, msg_id
                )

        if not found_attachment:
            logger.info("Nachricht %r hat keine verwertbaren Anhänge (.gz/.zip/.xml)", msg_id)

        _mark_processed(imap_conn, msg_id, config, logger)

    return summary


def _mark_processed(
    conn: imaplib.IMAP4_SSL, msg_id: bytes, config: Config, logger: logging.Logger
) -> None:
    try:
        if config.move_to_processed_folder:
            status, _ = conn.copy(msg_id, config.processed_folder)
            if status != "OK":
                logger.warning("Nachricht %r konnte nicht nach %r kopiert werden", msg_id, config.processed_folder)
                return
            conn.store(msg_id, "+FLAGS", "(\\Seen \\Deleted)")
            conn.expunge()
        else:
            conn.store(msg_id, "+FLAGS", "(\\Seen)")
    except imaplib.IMAP4.error as exc:
        logger.warning("Nachricht %r konnte nicht als verarbeitet markiert werden: %s", msg_id, exc)
