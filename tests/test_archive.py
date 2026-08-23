"""Sicherheitstests für das Entpacken von Anhängen (Spezifikation Abschnitt 5).

XXE, Billion-Laughs, fremde Domain und abgeschnittenes XML werden bereits in
test_parser.py und test_store.py geprüft. Hier: Archiv-spezifische Angriffe.
"""
import gzip
import io
import os
import zipfile

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
