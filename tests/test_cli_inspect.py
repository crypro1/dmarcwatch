"""dmarcwatch inspect <ip|cidr>: vollständige Detailansicht ohne Hand-SQL."""
import argparse

from dmarcwatch.cli import cmd_inspect
from dmarcwatch.config import Config
from dmarcwatch.parser import parse_aggregate_report
from dmarcwatch.store import connect, ingest_report

XML = """<?xml version="1.0"?>
<feedback>
<report_metadata><org_name>Enterprise Outlook</org_name><report_id>inspect-test-1</report_id>
<date_range><begin>1700000000</begin><end>1700086399</end></date_range></report_metadata>
<policy_published><domain>example.com</domain><p>reject</p></policy_published>
<record>
<row><source_ip>2a01:111:f403:c200::5</source_ip><count>1</count>
<policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>fail</spf></policy_evaluated></row>
<identifiers><envelope_to>thirdparty.example</envelope_to><envelope_from>relay.example</envelope_from>
<header_from>example.com</header_from></identifiers>
</record>
<record>
<row><source_ip>192.0.2.1</source_ip><count>3</count>
<policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
<identifiers><header_from>example.com</header_from></identifiers>
</record>
</feedback>"""


def _args(**overrides):
    # Fixture-Zeitstempel liegen fest in der Vergangenheit (2023), days
    # entsprechend groß wählen, damit sie im Abfragefenster liegen.
    defaults = dict(query="", days=999999, whois=False, blacklist=False)
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def _seed(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    config = Config.from_dict({"own_domains": ["example.com"], "own_ip_networks": ["192.0.2.0/24"]})
    conn = connect(tmp_path / "Library" / "Application Support" / "dmarcwatch" / "dmarc.sqlite")
    report = parse_aggregate_report(XML.encode(), config.max_xml_size_bytes)
    ingest_report(conn, report, config)
    conn.close()


def test_inspect_exact_ip_shows_full_detail(tmp_path, monkeypatch, capsys):
    _seed(tmp_path, monkeypatch)
    result = cmd_inspect(_args(query="2a01:111:f403:c200::5"))
    out = capsys.readouterr().out
    assert result == 0
    assert "thirdparty.example" in out
    assert "relay.example" in out
    assert "Enterprise Outlook" in out
    assert "SPF" in out and "fail" in out


def test_inspect_by_network_matches_containing_ip(tmp_path, monkeypatch, capsys):
    _seed(tmp_path, monkeypatch)
    result = cmd_inspect(_args(query="2a01:111::/32"))
    out = capsys.readouterr().out
    assert result == 0
    assert "2a01:111:f403:c200::5" in out
    assert "192.0.2.1" not in out  # anderes Netz, kein Treffer


def test_inspect_no_match_returns_exit_1(tmp_path, monkeypatch, capsys):
    _seed(tmp_path, monkeypatch)
    result = cmd_inspect(_args(query="203.0.113.99"))
    out = capsys.readouterr().out
    assert result == 1
    assert "Keine Treffer" in out


def test_inspect_invalid_query_returns_exit_2(tmp_path, monkeypatch, capsys):
    _seed(tmp_path, monkeypatch)
    result = cmd_inspect(_args(query="not-an-ip-or-network"))
    err = capsys.readouterr().err
    assert result == 2
    assert "weder eine gültige IP" in err


def test_inspect_without_whois_flag_never_calls_lookup(tmp_path, monkeypatch, capsys):
    from unittest.mock import patch

    _seed(tmp_path, monkeypatch)
    with patch("dmarcwatch.cli.lookup_ip_organization") as mock_lookup:
        cmd_inspect(_args(query="2a01:111:f403:c200::5", whois=False))
    mock_lookup.assert_not_called()
    out = capsys.readouterr().out
    assert "WHOIS" not in out


def test_inspect_with_whois_flag_shows_organization_and_caches_per_ip(tmp_path, monkeypatch, capsys):
    from unittest.mock import patch

    _seed(tmp_path, monkeypatch)
    with patch("dmarcwatch.cli.lookup_ip_organization", return_value="Example Org") as mock_lookup:
        result = cmd_inspect(_args(query="2a01:111::/32", whois=True))
    out = capsys.readouterr().out
    assert result == 0
    assert "WHOIS-Organisation (nur Hinweis, keine Einstufung): Example Org" in out
    mock_lookup.assert_called_once()  # nur ein Treffer für dieses Netz in der Fixture


def test_inspect_whois_failure_shown_inline_not_fatal(tmp_path, monkeypatch, capsys):
    from unittest.mock import patch

    from dmarcwatch.whois import WhoisLookupError

    _seed(tmp_path, monkeypatch)
    with patch("dmarcwatch.cli.lookup_ip_organization", side_effect=WhoisLookupError("kein Netz")):
        result = cmd_inspect(_args(query="2a01:111:f403:c200::5", whois=True))
    out, err = capsys.readouterr()
    # WHOIS-Fehler darf inspect nicht scheitern lassen (Treffer werden trotzdem
    # angezeigt), aber Exit-Code 3 statt 0 signalisiert der Menüleisten-App den
    # Fehlschlag maschinenlesbar, ohne deutschen stdout-Text durchsuchen zu
    # müssen (siehe DmarcwatchCLI.swift runInspectWhois).
    assert result == 3
    assert "Abfrage fehlgeschlagen" in out
    assert "kein Netz" in err


def test_inspect_without_blacklist_flag_never_calls_check(tmp_path, monkeypatch, capsys):
    from unittest.mock import patch

    _seed(tmp_path, monkeypatch)
    with patch("dmarcwatch.cli.check_ip_blacklist") as mock_check:
        cmd_inspect(_args(query="2a01:111:f403:c200::5", blacklist=False))
    mock_check.assert_not_called()
    out = capsys.readouterr().out
    assert "Spamhaus" not in out


def test_inspect_with_blacklist_flag_shows_status_and_caches_per_ip(tmp_path, monkeypatch, capsys):
    from unittest.mock import patch

    from dmarcwatch.blacklist import BlacklistResult
    from dmarcwatch.config import db_path
    from dmarcwatch.store import connect, get_cached_blacklist

    _seed(tmp_path, monkeypatch)
    with patch(
        "dmarcwatch.cli.check_ip_blacklist",
        return_value=BlacklistResult(ip="192.0.2.1", listed=True, reasons=["SBL - bekannte Spam-Quelle"]),
    ) as mock_check:
        result = cmd_inspect(_args(query="192.0.2.1", blacklist=True))
    out = capsys.readouterr().out
    assert result == 0
    assert "Spamhaus ZEN (nur Hinweis, keine Einstufung): gelistet - SBL - bekannte Spam-Quelle" in out
    mock_check.assert_called_once()

    conn = connect(db_path())
    cached = get_cached_blacklist(conn, "192.0.2.1")
    conn.close()
    assert cached is not None
    assert cached[0] is True


def test_inspect_blacklist_failure_shown_inline_not_fatal(tmp_path, monkeypatch, capsys):
    from unittest.mock import patch

    from dmarcwatch.blacklist import BlacklistCheckError

    _seed(tmp_path, monkeypatch)
    with patch("dmarcwatch.cli.check_ip_blacklist", side_effect=BlacklistCheckError("Zeitüberschreitung")):
        result = cmd_inspect(_args(query="192.0.2.1", blacklist=True))
    out, err = capsys.readouterr()
    # Gleiches Prinzip wie bei WHOIS oben: nicht fatal, aber Exit-Code 3
    # statt 0 als maschinenlesbares Fehlschlag-Signal.
    assert result == 3
    assert "Abfrage fehlgeschlagen" in out
    assert "Zeitüberschreitung" in err
