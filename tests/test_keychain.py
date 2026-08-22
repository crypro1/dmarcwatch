"""Tests für keychain.py mit gemocktem keyring-Modul.

Diese Tests rufen absichtlich NIE die echten keyring-Funktionen auf - sie
würden sonst den echten macOS-Schlüsselbund der Person verändern, die die
Tests ausführt. Stattdessen wird dmarcwatch.keychain.keyring gemockt.
"""
from unittest.mock import patch

import keyring.errors
import pytest

from dmarcwatch import keychain


def test_set_password_calls_keyring_with_service_and_account():
    with patch.object(keychain.keyring, "set_password") as mock_set:
        keychain.set_password("dmarc@example.com", "s3cret")
    mock_set.assert_called_once_with(keychain.SERVICE_NAME, "dmarc@example.com", "s3cret")


def test_set_empty_password_rejected_without_calling_keyring():
    with patch.object(keychain.keyring, "set_password") as mock_set:
        with pytest.raises(keychain.KeychainError):
            keychain.set_password("dmarc@example.com", "")
    mock_set.assert_not_called()


def test_get_password_wraps_keyring_errors():
    with patch.object(keychain.keyring, "get_password", side_effect=keyring.errors.KeyringError("boom")):
        with pytest.raises(keychain.KeychainError):
            keychain.get_password("dmarc@example.com")


def test_prompt_and_store_rejects_mismatched_passwords_without_storing(capsys):
    with patch("getpass.getpass", side_effect=["password1", "password2"]):
        with patch.object(keychain.keyring, "set_password") as mock_set:
            with pytest.raises(keychain.KeychainError):
                keychain.prompt_and_store("dmarc@example.com")
    mock_set.assert_not_called()


def test_prompt_and_store_saves_matching_password():
    with patch("getpass.getpass", side_effect=["password1", "password1"]):
        with patch.object(keychain.keyring, "set_password") as mock_set:
            keychain.prompt_and_store("dmarc@example.com")
    mock_set.assert_called_once_with(keychain.SERVICE_NAME, "dmarc@example.com", "password1")


def test_delete_password_ignores_missing_entry():
    with patch.object(
        keychain.keyring, "delete_password", side_effect=keyring.errors.PasswordDeleteError()
    ):
        keychain.delete_password("dmarc@example.com")  # darf nicht werfen
