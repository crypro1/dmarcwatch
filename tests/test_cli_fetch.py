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

from dmarcwatch import cli, keychain
from dmarcwatch.config import read_last_fetch_date
from dmarcwatch.fetch import FetchSummary


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


def test_failed_connection_does_not_write_marker(tmp_path, monkeypatch):
    from dmarcwatch.fetch import FetchError

    monkeypatch.setenv("HOME", str(tmp_path))
    with patch.object(keychain, "get_password", return_value="secret"):
        with patch.object(cli, "connect_imap", side_effect=FetchError("nicht erreichbar")):
            result = cli.cmd_fetch(_args())

    assert result == 1
    assert read_last_fetch_date() is None
