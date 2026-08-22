"""Zugriff auf das macOS-Schlüsselbund für das IMAP-Passwort.

Das Passwort landet ausschließlich im Schlüsselbund. Es wird nie als
Kommandozeilenargument übergeben (Prozesslisten sind für andere lokale
Nutzer sichtbar), sondern über getpass() interaktiv eingelesen und
programmatisch über das keyring-Modul gespeichert, das auf macOS die
Security-Framework-APIs direkt aufruft statt eine Shell zu benutzen.
"""
from __future__ import annotations

import getpass

import keyring
import keyring.errors

SERVICE_NAME = "dmarcwatch"


class KeychainError(RuntimeError):
    pass


def get_password(account: str) -> str | None:
    try:
        return keyring.get_password(SERVICE_NAME, account)
    except keyring.errors.KeyringError as exc:
        raise KeychainError(f"Schlüsselbund konnte nicht gelesen werden: {exc}") from exc


def set_password(account: str, password: str) -> None:
    if not password:
        raise KeychainError("Leeres Passwort wird nicht gespeichert")
    try:
        keyring.set_password(SERVICE_NAME, account, password)
    except keyring.errors.KeyringError as exc:
        raise KeychainError(f"Schlüsselbund konnte nicht beschrieben werden: {exc}") from exc


def delete_password(account: str) -> None:
    try:
        keyring.delete_password(SERVICE_NAME, account)
    except keyring.errors.PasswordDeleteError:
        pass
    except keyring.errors.KeyringError as exc:
        raise KeychainError(f"Schlüsselbund-Eintrag konnte nicht gelöscht werden: {exc}") from exc


def prompt_and_store(account: str) -> None:
    """Fragt das Passwort interaktiv ab (kein Echo) und speichert es.

    Das Passwort erscheint dabei nie als Prozessargument oder in der
    Shell-History.
    """
    print(f"Anwendungsspezifisches Passwort für {account} (mailbox.org, IMAP).")
    password = getpass.getpass("Passwort (wird nicht angezeigt): ")
    confirm = getpass.getpass("Passwort wiederholen: ")
    if password != confirm:
        raise KeychainError("Eingaben stimmen nicht überein, nichts gespeichert")
    set_password(account, password)
    print(f"Gespeichert im Schlüsselbund unter Dienst={SERVICE_NAME!r}, Account={account!r}.")
