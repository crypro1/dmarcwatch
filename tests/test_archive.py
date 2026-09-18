"""Sicherheitstests für das Entpacken von Anhängen (Spezifikation Abschnitt 5).

XXE, Billion-Laughs, fremde Domain und abgeschnittenes XML werden bereits in
test_parser.py und test_store.py geprüft. Hier: Archiv-spezifische Angriffe.
"""
import gzip
import io
import os
import zipfile
import zlib

import pytest

from dmarcwatch.archive import ArchiveError, extract_report_json, extract_report_xml

MAX_ATTACHMENT = 5 * 1024 * 1024
MAX_XML = 10 * 1024 * 1024
MAX_JSON = 2 * 1024 * 1024


def test_plain_xml_passthrough():
    data = b"<feedback></feedback>"
    assert extract_report_xml("report.xml", data, MAX_ATTACHMENT, MAX_XML) == data


def test_gz_roundtrip():
    payload = b"<feedback><record>hello</record></feedback>"
    compressed = gzip.compress(payload)
    result = extract_report_xml("report.xml.gz", compressed, MAX_ATTACHMENT, MAX_XML)
    assert result == payload


def test_zip_roundtrip_first_entry_only():
    payload = b"<feedback>real report</feedback>"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("report.xml", payload)
        zf.writestr("second.xml", b"<feedback>should be ignored</feedback>")
    result = extract_report_xml("report.zip", buf.getvalue(), MAX_ATTACHMENT, MAX_XML)
    assert result == payload


def test_gzip_bomb_rejected_at_size_limit():
    # 50 MB Nullen komprimieren extrem gut, wir erlauben aber nur 10 MB.
    huge = b"\x00" * (50 * 1024 * 1024)
    compressed = gzip.compress(huge)
    assert len(compressed) < MAX_ATTACHMENT  # der Anhang selbst ist klein
    with pytest.raises(ArchiveError):
        extract_report_xml("bomb.xml.gz", compressed, MAX_ATTACHMENT, max_xml_size_bytes=10 * 1024 * 1024)


def test_zip_path_traversal_never_written_to_disk(tmp_path):
    payload = b"<feedback>evil payload</feedback>"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../evil.txt", payload)

    before = set(tmp_path.rglob("*"))
    result = extract_report_xml("evil.zip", buf.getvalue(), MAX_ATTACHMENT, MAX_XML)
    after = set(tmp_path.rglob("*"))

    # Die Bytes werden zurückgegeben (zur weiteren Verarbeitung im Speicher),
    # aber der im Archiv enthaltene Name wurde nirgends als Dateiname benutzt.
    assert result == payload
    assert before == after
    assert not (tmp_path.parent / "evil.txt").exists()
    assert not os.path.exists(os.path.join(os.path.dirname(str(tmp_path)), "evil.txt"))


def test_zip_declared_size_lie_still_capped():
    # ZipInfo.file_size wird vor dem Lesen geprüft, aber wir verlassen uns
    # nicht ausschließlich darauf - _read_bounded greift zusätzlich.
    huge = b"\x00" * (50 * 1024 * 1024)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("report.xml", huge)
    with pytest.raises(ArchiveError):
        extract_report_xml("bomb.zip", buf.getvalue(), MAX_ATTACHMENT, max_xml_size_bytes=10 * 1024 * 1024)


def test_attachment_over_size_limit_rejected():
    data = b"x" * (6 * 1024 * 1024)
    with pytest.raises(ArchiveError):
        extract_report_xml("big.xml", data, max_attachment_size_bytes=5 * 1024 * 1024, max_xml_size_bytes=MAX_XML)


def test_empty_attachment_rejected():
    with pytest.raises(ArchiveError):
        extract_report_xml("empty.xml", b"", MAX_ATTACHMENT, MAX_XML)


def test_unknown_extension_rejected():
    with pytest.raises(ArchiveError):
        extract_report_xml("report.exe", b"whatever", MAX_ATTACHMENT, MAX_XML)


def test_bad_zip_rejected():
    with pytest.raises(ArchiveError):
        extract_report_xml("broken.zip", b"not a real zip", MAX_ATTACHMENT, MAX_XML)


def test_bad_gz_rejected():
    with pytest.raises(ArchiveError):
        extract_report_xml("broken.xml.gz", b"not gzip data", MAX_ATTACHMENT, MAX_XML)


def test_truncated_gz_rejected():
    """Ein an beliebiger Stelle abgeschnittener (aber am Anfang gültiger)
    gzip-Stream wirft empirisch EOFError statt OSError
    ("Compressed file ended before the end-of-stream marker was reached") -
    kein OSError-Subtyp, würde also am `except OSError` in _extract_gz
    vorbei nach oben durchschlagen, wenn der nicht auch EOFError fängt.
    Für einen Angreifer (jeder kann eine Mail an die rua-Adresse schicken,
    siehe Sicherheitsentscheidungen) ist ein abgeschnittener Anhang
    trivial zu erzeugen."""
    payload = b"<feedback><record>hello world</record></feedback>" * 50
    compressed = gzip.compress(payload)
    for frac in (0.1, 0.5, 0.9, 0.99):
        truncated = compressed[: int(len(compressed) * frac)]
        with pytest.raises(ArchiveError):
            extract_report_xml("broken.xml.gz", truncated, MAX_ATTACHMENT, MAX_XML)


def test_corrupted_gz_zlib_error_rejected(monkeypatch):
    """Bitweise Beschädigung mitten im komprimierten Datenteil kann direkt
    aus zlib ein zlib.error werfen (z. B. "invalid code lengths set"),
    nicht das von gzip gekapselte OSError/BadGzipFile - ebenfalls kein
    OSError-Subtyp, empirisch mit echt korrumpierten Bytes nachgewiesen.
    Hier wird GzipFile.read() direkt gepatcht statt eines echt
    korrumpierten Streams, weil der exakte Byte-Offset, an dem zlib
    tatsächlich zlib.error statt z. B. eines CRC-Fehlers wirft, von der
    zlib-Version abhängt - für diesen Test zählt nur, dass _extract_gz
    den Exception-Typ überhaupt behandelt, nicht die exakte Bytefolge."""
    def raise_zlib_error(self, *args, **kwargs):
        raise zlib.error("Error -3 while decompressing data: invalid code lengths set")

    monkeypatch.setattr(gzip.GzipFile, "read", raise_zlib_error)
    with pytest.raises(ArchiveError):
        extract_report_xml("broken.xml.gz", gzip.compress(b"anything"), MAX_ATTACHMENT, MAX_XML)


def test_json_plain_passthrough():
    data = b'{"organization-name": "x"}'
    assert extract_report_json("report.json", data, MAX_ATTACHMENT, MAX_JSON) == data


def test_json_gz_roundtrip():
    payload = b'{"organization-name": "x", "policies": []}'
    compressed = gzip.compress(payload)
    result = extract_report_json("report.json.gz", compressed, MAX_ATTACHMENT, MAX_JSON)
    assert result == payload


def test_json_gzip_bomb_rejected_at_size_limit():
    huge = b"\x00" * (50 * 1024 * 1024)
    compressed = gzip.compress(huge)
    assert len(compressed) < MAX_ATTACHMENT
    with pytest.raises(ArchiveError):
        extract_report_json("bomb.json.gz", compressed, MAX_ATTACHMENT, max_json_size_bytes=2 * 1024 * 1024)


def test_json_unknown_extension_rejected():
    with pytest.raises(ArchiveError):
        extract_report_json("report.exe", b"whatever", MAX_ATTACHMENT, MAX_JSON)


def test_json_empty_attachment_rejected():
    with pytest.raises(ArchiveError):
        extract_report_json("empty.json", b"", MAX_ATTACHMENT, MAX_JSON)
