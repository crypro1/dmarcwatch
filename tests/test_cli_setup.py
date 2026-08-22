"""cmd_setup():
- Passwort-Eingabe nur wenn nötig, nicht bei jedem --install-agent-Aufruf
  erneut abfragen (sonst muss man z. B. für eine reine Zeitplan-Änderung
  jedes Mal das Passwort neu eingeben).
- Konfiguration (IMAP-Server/Login/Domain(s)) wird beim allerersten Lauf
  interaktiv abgefragt statt stillschweigend mit Beispielwerten aus
  DEFAULT_CONFIG belegt zu werden - sonst würde ein frischer Checkout
  unbemerkt mit den Werten einer fremden Installation laufen.
- --from-stdin-json: nicht-interaktiver Pfad für die native Setup-GUI,
  liest Konfiguration + optionales Passwort als ein JSON-Objekt von stdin,
  nie als Kommandozeilenargument.
"""
import argparse
import io
from unittest.mock import patch

from dmarcwatch import cli, keychain
from dmarcwatch.config import config_path, read_raw_config, write_config


def _args(**overrides):
    defaults = dict(
        remove_agent=False,
        install_agent=False,
        hour=None,
        minute=None,
        reset_password=False,
        reconfigure=False,
        remove_menubar_agent=False,
        from_stdin_json=False,
    )
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def _seed_configured_home(tmp_path, monkeypatch):
    """HOME auf tmp_path setzen und eine bereits vollständige Konfiguration
    hinterlegen, damit cmd_setup NICHT in den interaktiven Ersteinrichtungs-
    Dialog läuft (der würde ohne echtes stdin an input() hängenbleiben)."""
    monkeypatch.setenv("HOME", str(tmp_path))
    write_config(
        {
            "imap_host": "imap.example.com",
            "imap_port": 993,
            "imap_user": "user@example.com",
            "imap_folder": "INBOX/DMARC",
            "own_domains": ["example.com"],
            "own_ip_networks": ["203.0.113.0/24"],
        }
    )


def test_skips_password_prompt_when_already_stored(tmp_path, monkeypatch):
    _seed_configured_home(tmp_path, monkeypatch)
    with patch.object(keychain, "get_password", return_value="already-set"):
        with patch.object(keychain, "prompt_and_store") as mock_prompt:
            with patch.object(cli.launchd, "install") as mock_install:
                result = cli.cmd_setup(_args(install_agent=True, hour=7, minute=30))

    mock_prompt.assert_not_called()
    mock_install.assert_called_once_with(hour=7, minute=30)
    assert result == 0


def test_reset_password_forces_prompt_even_if_stored(tmp_path, monkeypatch):
    _seed_configured_home(tmp_path, monkeypatch)
    with patch.object(keychain, "get_password", return_value="already-set"):
        with patch.object(keychain, "prompt_and_store") as mock_prompt:
            result = cli.cmd_setup(_args(reset_password=True))

    mock_prompt.assert_called_once()
    assert result == 0


def test_prompts_when_no_password_stored_yet(tmp_path, monkeypatch):
    _seed_configured_home(tmp_path, monkeypatch)
    with patch.object(keychain, "get_password", return_value=None):
        with patch.object(keychain, "prompt_and_store") as mock_prompt:
            result = cli.cmd_setup(_args())

    mock_prompt.assert_called_once()
    assert result == 0


def test_from_stdin_json_writes_config_and_password_without_prompting(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    payload = (
        '{"imap_host": "imap.example.com", "imap_port": 993, '
        '"imap_user": "user@example.com", "imap_folder": "INBOX/DMARC", '
        '"own_domains": ["example.com"], "password": "s3cret"}'
    )
    monkeypatch.setattr("sys.stdin", io.StringIO(payload))
    with patch.object(keychain, "set_password") as mock_set_password:
        with patch("builtins.input") as mock_input:
            result = cli.cmd_setup(_args(from_stdin_json=True))

    mock_input.assert_not_called()
    mock_set_password.assert_called_once_with("user@example.com", "s3cret")
    assert result == 0
    saved = read_raw_config(config_path())
    assert saved["imap_host"] == "imap.example.com"
    assert saved["own_domains"] == ["example.com"]
    # Das Passwort darf nie in config.json landen, nur im Schlüsselbund.
    assert "password" not in saved


def test_from_stdin_json_without_password_leaves_keychain_untouched(tmp_path, monkeypatch):
    _seed_configured_home(tmp_path, monkeypatch)
    payload = '{"imap_folder": "INBOX/DMARC/neu"}'
    monkeypatch.setattr("sys.stdin", io.StringIO(payload))
    with patch.object(keychain, "set_password") as mock_set_password:
        result = cli.cmd_setup(_args(from_stdin_json=True))

    mock_set_password.assert_not_called()
    assert result == 0
    saved = read_raw_config(config_path())
    assert saved["imap_folder"] == "INBOX/DMARC/neu"
    # Restliche Felder aus der bestehenden Konfiguration bleiben unverändert.
    assert saved["imap_user"] == "user@example.com"


def test_from_stdin_json_rejects_malformed_json(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr("sys.stdin", io.StringIO("not valid json{{{"))
    result = cli.cmd_setup(_args(from_stdin_json=True))
    assert result == 1


def test_remove_menubar_agent_only_removes_menubar_agent(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    with patch.object(cli.launchd, "uninstall") as mock_uninstall_fetch:
        with patch.object(cli.launchd, "uninstall_menubar", return_value=True) as mock_uninstall_menubar:
            result = cli.cmd_setup(_args(remove_menubar_agent=True))

    mock_uninstall_fetch.assert_not_called()
    mock_uninstall_menubar.assert_called_once()
    assert result == 0


def test_hour_minute_explicit_skips_interactive_schedule_prompt(tmp_path, monkeypatch):
    _seed_configured_home(tmp_path, monkeypatch)
    with patch.object(keychain, "get_password", return_value="already-set"):
        with patch("builtins.input") as mock_input:
            with patch.object(cli.launchd, "install") as mock_install:
                result = cli.cmd_setup(_args(install_agent=True, hour=12, minute=0))

    mock_input.assert_not_called()
    mock_install.assert_called_once_with(hour=12, minute=0)
    assert result == 0


def test_hour_minute_missing_prompts_interactively(tmp_path, monkeypatch):
    _seed_configured_home(tmp_path, monkeypatch)
    with patch.object(keychain, "get_password", return_value="already-set"):
        with patch("builtins.input", return_value="09:15"):
            with patch.object(cli.launchd, "install") as mock_install:
                result = cli.cmd_setup(_args(install_agent=True))

    mock_install.assert_called_once_with(hour=9, minute=15)
    assert result == 0


def test_first_run_prompts_for_config_and_saves_it(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    answers = iter(
        [
            "imap.example.com",  # IMAP-Server
            "993",  # IMAP-Port
            "user@example.com",  # IMAP-Login
            "INBOX/DMARC",  # IMAP-Ordner
            "example.com, example.org",  # Domain(s)
        ]
    )
    with patch("builtins.input", side_effect=lambda *_: next(answers)):
        with patch.object(keychain, "get_password", return_value="already-set"):
            result = cli.cmd_setup(_args())

    assert result == 0
    saved = read_raw_config(config_path())
    assert saved["imap_host"] == "imap.example.com"
    assert saved["imap_user"] == "user@example.com"
    assert saved["imap_folder"] == "INBOX/DMARC"
    assert saved["own_domains"] == ["example.com", "example.org"]
    # own_ip_networks wird bewusst NICHT interaktiv abgefragt (siehe
    # cli.py _prompt_config_interactively) - bleibt leer, bis der Nutzer
    # echte Reports gesehen hat.
    assert saved["own_ip_networks"] == []


def test_reconfigure_flag_forces_reprompt_on_existing_config(tmp_path, monkeypatch):
    _seed_configured_home(tmp_path, monkeypatch)
    answers = iter(
        [
            "imap.newhost.example",
            "993",
            "new-user@example.com",
            "INBOX/DMARC",
            "newdomain.example",
        ]
    )
    with patch("builtins.input", side_effect=lambda *_: next(answers)):
        with patch.object(keychain, "get_password", return_value="already-set"):
            result = cli.cmd_setup(_args(reconfigure=True))

    assert result == 0
    saved = read_raw_config(config_path())
    assert saved["imap_host"] == "imap.newhost.example"
    assert saved["imap_user"] == "new-user@example.com"
    assert saved["own_domains"] == ["newdomain.example"]


def test_without_reconfigure_existing_config_is_not_reprompted(tmp_path, monkeypatch):
    _seed_configured_home(tmp_path, monkeypatch)
    with patch.object(keychain, "get_password", return_value="already-set"):
        with patch("builtins.input") as mock_input:
            result = cli.cmd_setup(_args())

    mock_input.assert_not_called()
    assert result == 0
    saved = read_raw_config(config_path())
    assert saved["imap_user"] == "user@example.com"  # unverändert
