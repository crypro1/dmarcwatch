"""Sicherheitstest: SwiftBar nutzt '|' als Parameter-Trenner, 'bash=' fuehrt
Befehle aus. Report-Daten mit '|' und 'bash=' duerfen in der Menuleisten-
Ausgabe nicht als zusaetzlicher Parameter interpretierbar werden
(Spezifikation Abschnitt 4.6 / 5)."""
from pathlib import Path

from dmarcwatch.config import Config
from dmarcwatch.menubar import render_swiftbar
from dmarcwatch.parser import parse_aggregate_report
from dmarcwatch.report import collect_rows
from dmarcwatch.store import connect, ingest_report

FIXTURES = Path(__file__).parent / "fixtures"


def _config() -> Config:
    return Config.from_dict(
        {"own_domains": ["example.com"], "own_ip_networks": ["192.0.2.0/24", "2001:db8:1::/48"]}
    )


def test_injection_payload_never_produces_a_bash_parameter(tmp_path):
    conn = connect(tmp_path / "dmarc.sqlite")
    config = _config()
    xml = (FIXTURES / "injection_field.xml").read_bytes()
    report = parse_aggregate_report(xml, config.max_xml_size_bytes)
    ingest_report(conn, report, config)

    rows = collect_rows(conn, since_ts=0, until_ts=2_000_000_000)
    output = render_swiftbar(rows, days=3650)

    # Der org_name-Wert im Fixture enthaelt "|bash=/bin/rm ...". Nach dem
    # Sanitizing darf kein "|" mehr auftauchen, das SwiftBar als Trenner vor
    # einem echten "bash="-Parameter lesen koennte.
    assert "bash=" not in output
    assert "/bin/rm" not in output
    # Jede Zeile mit einem "|" darf nur unsere eigenen, kontrollierten
    # Parameter (z.B. color=..., sfimage=...) danach stehen haben.
    for line in output.splitlines():
        if "|" in line:
            _, _, params = line.partition("|")
            for token in params.strip().split():
                key = token.split("=", 1)[0]
                assert key in {"color", "sfimage"}, f"unerwarteter Parameter: {token!r}"


def test_pipe_and_control_chars_stripped_from_every_field():
    from dmarcwatch.sanitize import sanitize_field

    evil = "a|b\x1b[31mred\x1b[0m\x00c\nnewline"
    safe = sanitize_field(evil, max_len=100)
    assert "|" not in safe
    assert "\x1b" not in safe
    assert "\x00" not in safe
    assert "\n" not in safe


def test_long_field_is_truncated():
    from dmarcwatch.sanitize import sanitize_field

    safe = sanitize_field("x" * 500, max_len=80)
    assert len(safe) == 80
    assert safe.endswith("…")
