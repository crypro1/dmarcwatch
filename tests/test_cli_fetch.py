"""cmd_fetch() / --skip-if-already-run-today:

launchd holt einen wegen ausgeschaltetem/schlafendem Mac verpassten
StartCalendarInterval-Termin NICHT von selbst nach - RunAtLoad (siehe
launchd.py) sorgt dafür, dass bei jedem Login/Neustart nachgesehen wird, ob
heute schon erfolgreich abgerufen wurde. Getestet wird hier nur die
Markierungslogik in cmd_fetch, nicht die eigentliche IMAP-Verarbeitung
(siehe test_fetch.py für fetch_and_ingest direkt).
"""
import argparse
import time
from unittest.mock import MagicMock, patch

from dmarcwatch import cli, keychain, notify
from dmarcwatch.config import read_dns_check_result, read_last_fetch_date, read_skipped_items, write_config, write_dns_check_result
from dmarcwatch.dns_verify import (
    DKIMCheckResult,
    DMARCCheckResult,
    DomainVerification,
    MTASTSCheckResult,
    TLSRPTDNSCheckResult,
    WildcardSPFCheckResult,
)
from dmarcwatch.fetch import FetchSummary
from dmarcwatch.spf import SPFCheckResult


def _clean_dns_result(domain: str) -> DomainVerification:
    return DomainVerification(
        domain=domain,
        dmarc=DMARCCheckResult(exists=True, record="v=DMARC1; p=reject", policy="reject"),
        spf=SPFCheckResult(exists=True, record="v=spf1 -all", lookup_count=0, lookup_limit_ok=True),
        dkim=[DKIMCheckResult(selector="default", exists=True, key_type="rsa")],
        mta_sts=MTASTSCheckResult(configured=False),
        tlsrpt_dns=TLSRPTDNSCheckResult(configured=False),
        wildcard_spf=WildcardSPFCheckResult(configured=False),
    )


def _run_fetch_with_dns_mocks(tmp_path, monkeypatch, verify_result):
    monkeypatch.setenv("HOME", str(tmp_path))
    with patch.object(keychain, "get_password", return_value="secret"):
        with patch.object(cli, "connect_imap", return_value=MagicMock()):
            with patch.object(cli, "connect", return_value=MagicMock()):
                with patch.object(cli, "fetch_and_ingest", return_value=_empty_summary()):
                    with patch.object(cli, "verify_domain", return_value=verify_result) as mock_verify:
                        with patch.object(notify, "send_notification") as mock_notify:
                            result = cli.cmd_fetch(_args())
    return result, mock_verify, mock_notify


def _args(**overrides):
    defaults = dict(verbose=False, skip_if_already_run_today=False)
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def _empty_summary():
    return FetchSummary()


def _run_fetch_with_mocks(tmp_path, monkeypatch, args):
    monkeypatch.setenv("HOME", str(tmp_path))
    with patch.object(keychain, "get_password", return_value="secret"):
        with patch.object(cli, "connect_imap", return_value=MagicMock()):
            with patch.object(cli, "connect", return_value=MagicMock()):
                with patch.object(cli, "fetch_and_ingest", return_value=_empty_summary()):
                    return cli.cmd_fetch(args)


def test_skip_flag_without_prior_marker_still_fetches(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    with patch.object(keychain, "get_password", return_value="secret") as mock_password:
        with patch.object(cli, "connect_imap", return_value=MagicMock()):
            with patch.object(cli, "connect", return_value=MagicMock()):
                with patch.object(cli, "fetch_and_ingest", return_value=_empty_summary()):
                    result = cli.cmd_fetch(_args(skip_if_already_run_today=True))

    mock_password.assert_called_once()
    assert result == 0
    assert read_last_fetch_date() == time.strftime("%Y-%m-%d")


def test_skip_flag_with_todays_marker_skips_without_touching_keychain(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    from dmarcwatch.config import write_last_fetch_date

    write_last_fetch_date(time.strftime("%Y-%m-%d"))

    with patch.object(keychain, "get_password") as mock_password:
        result = cli.cmd_fetch(_args(skip_if_already_run_today=True))

    mock_password.assert_not_called()
    assert result == 0


def test_skip_flag_with_stale_marker_fetches_anyway(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    from dmarcwatch.config import write_last_fetch_date

    write_last_fetch_date("2020-01-01")
    result = _run_fetch_with_mocks(tmp_path, monkeypatch, _args(skip_if_already_run_today=True))

    assert result == 0
    assert read_last_fetch_date() == time.strftime("%Y-%m-%d")


def test_without_skip_flag_always_fetches_even_with_todays_marker(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    from dmarcwatch.config import write_last_fetch_date

    write_last_fetch_date(time.strftime("%Y-%m-%d"))

    with patch.object(keychain, "get_password", return_value="secret") as mock_password:
        with patch.object(cli, "connect_imap", return_value=MagicMock()):
            with patch.object(cli, "connect", return_value=MagicMock()):
                with patch.object(cli, "fetch_and_ingest", return_value=_empty_summary()):
                    result = cli.cmd_fetch(_args(skip_if_already_run_today=False))

    # "Jetzt abrufen" / manuelles `dmarcwatch fetch` prüft immer tatsächlich,
    # unabhängig von der Markierung.
    mock_password.assert_called_once()
    assert result == 0


def test_tls_rpt_failures_cause_exit_code_1_and_notification(tmp_path, monkeypatch):
    """TLS-RPT-Fehlschläge sind genauso ein "neuer Befund" wie eine DMARC-
    Auffälligkeit - fetch darf hier nicht still Exit-Code 0 zurückgeben oder
    die Notification unterschlagen, nur weil flagged_count (DMARC) bei 0
    liegt."""
    monkeypatch.setenv("HOME", str(tmp_path))
    write_config({"enable_tls_rpt": True})
    summary = FetchSummary(flagged_count=0, tls_failure_count=3)

    with patch.object(keychain, "get_password", return_value="secret"):
        with patch.object(cli, "connect_imap", return_value=MagicMock()):
            with patch.object(cli, "connect", return_value=MagicMock()):
                with patch.object(cli, "fetch_and_ingest", return_value=summary):
                    with patch.object(notify, "send_notification") as mock_notify:
                        result = cli.cmd_fetch(_args())

    assert result == 1
    titles = [call.kwargs.get("title") or call.args[0] for call in mock_notify.call_args_list]
    assert "TLS-RPT Fehlschläge" in titles


def test_skipped_items_are_persisted_sanitized_and_notified(tmp_path, monkeypatch):
    """Gründe für übersprungene Nachrichten/Anhänge (z. B. eine abgelehnte
    Dekompressionsbombe) sollen nicht nur im Logfile landen, sondern auch
    für die Menüleisten-App sichtbar sein (read_skipped_items) und eine
    Notification auslösen - sonst merkt man von einem abgelehnten
    Angriffsversuch nie etwas, ohne von Hand die Logdatei zu lesen."""
    monkeypatch.setenv("HOME", str(tmp_path))
    # Der Dateiname kommt unverändert aus einem E-Mail-Anhang (unvertrauens-
    # würdig) - enthält hier absichtlich ein Steuerzeichen und ein "|", um
    # zu prüfen, dass sanitize_field() das vor dem Schreiben entfernt.
    malicious_filename = "bomb\x1b[31m.xml.gz|bash=evil"
    summary = FetchSummary(errors=[f"{malicious_filename}: Entpackte Größe überschreitet Obergrenze"])

    with patch.object(keychain, "get_password", return_value="secret"):
        with patch.object(cli, "connect_imap", return_value=MagicMock()):
            with patch.object(cli, "connect", return_value=MagicMock()):
                with patch.object(cli, "fetch_and_ingest", return_value=summary):
                    with patch.object(notify, "send_notification") as mock_notify:
                        cli.cmd_fetch(_args())

    stored = read_skipped_items()
    assert len(stored) == 1
    assert "\x1b" not in stored[0]
    assert "|" not in stored[0]
    assert "Entpackte Größe überschreitet Obergrenze" in stored[0]

    titles = [call.kwargs.get("title") or call.args[0] for call in mock_notify.call_args_list]
    assert "Nachricht/Anhang übersprungen" in titles


def test_skipped_items_marker_cleared_when_run_is_clean(tmp_path, monkeypatch):
    """Ein sauberer Folgelauf muss die Reste eines vorherigen Fehlschlags
    löschen - sonst zeigt die App eine längst nicht mehr aktuelle Warnung
    dauerhaft weiter an (kein anwachsendes/veraltendes Protokoll)."""
    monkeypatch.setenv("HOME", str(tmp_path))
    from dmarcwatch.config import write_skipped_items

    write_skipped_items(["alter Eintrag von einem früheren Lauf"])

    with patch.object(keychain, "get_password", return_value="secret"):
        with patch.object(cli, "connect_imap", return_value=MagicMock()):
            with patch.object(cli, "connect", return_value=MagicMock()):
                with patch.object(cli, "fetch_and_ingest", return_value=_empty_summary()):
                    cli.cmd_fetch(_args())

    assert read_skipped_items() == []


def test_failed_connection_does_not_write_marker(tmp_path, monkeypatch):
    from dmarcwatch.fetch import FetchError

    monkeypatch.setenv("HOME", str(tmp_path))
    with patch.object(keychain, "get_password", return_value="secret"):
        with patch.object(cli, "connect_imap", side_effect=FetchError("nicht erreichbar")):
            result = cli.cmd_fetch(_args())

    assert result == 1
    assert read_last_fetch_date() is None


# --- Automatischer periodischer DNS-Check (enable_auto_dns_check) ---


def test_auto_dns_check_disabled_by_default_never_runs(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    write_config({"own_domains": ["example.com"], "enable_auto_dns_check": False})
    result, mock_verify, _ = _run_fetch_with_dns_mocks(tmp_path, monkeypatch, _clean_dns_result("example.com"))

    assert result == 0
    mock_verify.assert_not_called()
    assert read_dns_check_result() is None


def test_auto_dns_check_runs_when_never_checked_before(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    write_config({"own_domains": ["example.com"], "enable_auto_dns_check": True})
    _, mock_verify, _ = _run_fetch_with_dns_mocks(tmp_path, monkeypatch, _clean_dns_result("example.com"))

    mock_verify.assert_called_once()
    stored = read_dns_check_result()
    assert stored is not None
    assert stored["domains"][0]["domain"] == "example.com"


def test_auto_dns_check_skips_when_recently_checked(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    write_config({
        "own_domains": ["example.com"],
        "enable_auto_dns_check": True,
        "auto_dns_check_interval_days": 7,
    })
    write_dns_check_result({"checked_at": time.strftime("%Y-%m-%d"), "domains": []})

    _, mock_verify, _ = _run_fetch_with_dns_mocks(tmp_path, monkeypatch, _clean_dns_result("example.com"))

    mock_verify.assert_not_called()


def test_auto_dns_check_runs_again_after_interval_elapsed(tmp_path, monkeypatch):
    from datetime import date, timedelta

    monkeypatch.setenv("HOME", str(tmp_path))
    write_config({
        "own_domains": ["example.com"],
        "enable_auto_dns_check": True,
        "auto_dns_check_interval_days": 7,
    })
    stale_date = (date.today() - timedelta(days=10)).isoformat()
    write_dns_check_result({"checked_at": stale_date, "domains": []})

    _, mock_verify, _ = _run_fetch_with_dns_mocks(tmp_path, monkeypatch, _clean_dns_result("example.com"))

    mock_verify.assert_called_once()


def test_auto_dns_check_skips_with_no_own_domains(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    write_config({"own_domains": [], "enable_auto_dns_check": True})
    _, mock_verify, _ = _run_fetch_with_dns_mocks(tmp_path, monkeypatch, _clean_dns_result("example.com"))

    mock_verify.assert_not_called()
    assert read_dns_check_result() is None


def test_auto_dns_check_notifies_on_warnings(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    write_config({"own_domains": ["example.com"], "enable_auto_dns_check": True})
    warned = _clean_dns_result("example.com")
    warned.dmarc.warnings.append("p=none: rein beobachtend")

    _, mock_verify, mock_notify = _run_fetch_with_dns_mocks(tmp_path, monkeypatch, warned)

    mock_verify.assert_called_once()
    titles = [call.kwargs.get("title") or call.args[0] for call in mock_notify.call_args_list]
    assert "DNS-Konfiguration auffällig" in titles


def test_auto_dns_check_does_not_affect_fetch_exit_code(tmp_path, monkeypatch):
    """DNS-Auffälligkeiten sind ein eigenes Signal (Konfigurationszustand),
    kein "neuer Fund in einem Report" - fetch soll dafür nicht mit
    Exit-Code 1 abschließen, sonst vermischt das zwei unabhängige Dinge."""
    monkeypatch.setenv("HOME", str(tmp_path))
    write_config({"own_domains": ["example.com"], "enable_auto_dns_check": True})
    warned = _clean_dns_result("example.com")
    warned.dmarc.warnings.append("p=none: rein beobachtend")

    result, _, _ = _run_fetch_with_dns_mocks(tmp_path, monkeypatch, warned)

    assert result == 0
