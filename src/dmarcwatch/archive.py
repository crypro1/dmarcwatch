"""Sicheres Entpacken von DMARC-Report-Anhängen (.gz, .zip, .xml).

Bedrohungsmodell: Jeder kann eine Mail an die rua-Adresse schicken, also
sind Anhänge grundsätzlich böswillig gestaltet. Alles hier passiert
ausschließlich im Speicher (kein Schreiben archivinterner Dateinamen auf
die Festplatte) und mit harten Obergrenzen gegen Dekompressionsbomben.
"""
from __future__ import annotations

import gzip
import io
import zipfile

_CHUNK_SIZE = 64 * 1024


class ArchiveError(ValueError):
    """Anhang konnte nicht sicher entpackt werden und wird übersprungen."""


def _read_bounded(fileobj, max_size_bytes: int) -> bytes:
    """Liest aus fileobj, bricht ab sobald max_size_bytes überschritten wird.

    Schützt gegen Dekompressionsbomben unabhängig davon, was Header-Felder
    (z. B. das unkomprimierte Größenfeld im ZIP) behaupten.
    """
    buf = io.BytesIO()
    total = 0
    while True:
        chunk = fileobj.read(_CHUNK_SIZE)
        if not chunk:
            break
        total += len(chunk)
        if total > max_size_bytes:
            raise ArchiveError(
                f"Entpackte Größe überschreitet Obergrenze von {max_size_bytes} Bytes"
            )
        buf.write(chunk)
    return buf.getvalue()


def _extract_gz(data: bytes, max_size_bytes: int) -> bytes:
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
            return _read_bounded(gz, max_size_bytes)
    except ArchiveError:
        raise
    except OSError as exc:
        raise ArchiveError(f"Ungültiges gzip-Archiv: {exc}") from exc


def _extract_zip(data: bytes, max_size_bytes: int) -> bytes:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise ArchiveError(f"Ungültiges ZIP-Archiv: {exc}") from exc

    infos = zf.infolist()
    if not infos:
        raise ArchiveError("ZIP-Archiv ist leer")

    # Nur der erste Eintrag wird gelesen, nie verschachtelte Archive, und der
    # im Archiv enthaltene Dateiname wird nirgends zum Schreiben verwendet.
    first = infos[0]
    if first.file_size > max_size_bytes:
        raise ArchiveError(
            f"ZIP-Eintrag behauptet {first.file_size} Bytes, über Obergrenze {max_size_bytes}"
        )
    try:
        with zf.open(first, "r") as member:
            return _read_bounded(member, max_size_bytes)
    except ArchiveError:
        raise
    except (zipfile.BadZipFile, OSError, RuntimeError) as exc:
        raise ArchiveError(f"ZIP-Eintrag konnte nicht gelesen werden: {exc}") from exc


def extract_report_xml(filename_hint: str, data: bytes, max_attachment_size_bytes: int, max_xml_size_bytes: int) -> bytes:
    """Extrahiert die XML-Nutzdaten aus einem Anhang.

    filename_hint dient nur zur Formaterkennung (Endung), niemals zum
    Schreiben von Dateien. Wirft ArchiveError bei jedem Problem.
    """
    if len(data) == 0:
        raise ArchiveError("Anhang ist leer")
    if len(data) > max_attachment_size_bytes:
        raise ArchiveError(
            f"Anhang ist {len(data)} Bytes groß, über Obergrenze {max_attachment_size_bytes}"
        )

    name = (filename_hint or "").lower()
    if name.endswith(".gz"):
        return _extract_gz(data, max_xml_size_bytes)
    if name.endswith(".zip"):
        return _extract_zip(data, max_xml_size_bytes)
    if name.endswith(".xml"):
        if len(data) > max_xml_size_bytes:
            raise ArchiveError(
                f"XML ist {len(data)} Bytes groß, über Obergrenze {max_xml_size_bytes}"
            )
        return data

    raise ArchiveError(f"Unbekannter Anhangstyp: {filename_hint!r}")


def extract_report_json(
    filename_hint: str, data: bytes, max_attachment_size_bytes: int, max_json_size_bytes: int
) -> bytes:
    """Extrahiert die JSON-Nutzdaten eines SMTP-TLS-RPT-Anhangs (RFC 8460).

    Analog zu extract_report_xml, nur für .json statt .xml als Klartext-
    Endung. TLS-RPT-Reports landen in einem separaten, eigens dafür
    eingerichteten Postfachordner (siehe fetch.py) statt per
    Inhalts-Sniffing von DMARC-Anhängen unterschieden zu werden - beide
    Formate können als .gz vorliegen, die Endung allein ist nicht
    eindeutig.
    """
    if len(data) == 0:
        raise ArchiveError("Anhang ist leer")
    if len(data) > max_attachment_size_bytes:
        raise ArchiveError(
            f"Anhang ist {len(data)} Bytes groß, über Obergrenze {max_attachment_size_bytes}"
        )

    name = (filename_hint or "").lower()
    if name.endswith(".gz"):
        return _extract_gz(data, max_json_size_bytes)
    if name.endswith(".zip"):
        return _extract_zip(data, max_json_size_bytes)
    if name.endswith(".json"):
        if len(data) > max_json_size_bytes:
            raise ArchiveError(
                f"JSON ist {len(data)} Bytes groß, über Obergrenze {max_json_size_bytes}"
            )
        return data

    raise ArchiveError(f"Unbekannter Anhangstyp: {filename_hint!r}")
