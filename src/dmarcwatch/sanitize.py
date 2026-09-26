"""Escaping für Ausgaben, die potenziell als Befehl interpretiert werden.

SwiftBar nutzt "|" als Trenner zwischen Anzeigetext und Parametern; ein
Parameter wie "bash=" führt einen Befehl aus. Alle Report-Daten sind
unvertrauenswürdig (siehe parser.py), also muss jeder Wert, der in eine
Menüleisten-Zeile oder eine Benachrichtigung eingebettet wird, hier
durchlaufen, bevor er ausgegeben wird.
"""
from __future__ import annotations

import re

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
# Bidi-Overrides (U+202A-U+202E, U+2066-U+2069) koennen die Anzeigereihenfolge
# von Text umkehren/verschleiern, Zero-Width-Zeichen und BOM (U+200B-U+200F,
# U+FEFF) sind unsichtbar - beides liesse sich fuer Spoofing im Menuleisten-
# Titel missbrauchen (z.B. eine gefaelschte Domain vortaeuschen).
_INVISIBLE_CHARS = re.compile(r"[\u202a-\u202e\u2066-\u2069\u200b-\u200f\ufeff]")


def sanitize_field(value: str, max_len: int = 80) -> str:
    """Macht einen Wert sicher für die Anzeige in SwiftBar-Zeilen oder Notifications.

    Entfernt "|" (SwiftBar-Parameter-Trenner), ANSI-Escapes, Steuerzeichen,
    Zeilenumbrüche sowie unsichtbare/Bidi-Steuerzeichen, und begrenzt die Länge.
    """
    if value is None:
        return ""
    text = str(value)
    text = _ANSI_ESCAPE.sub("", text)
    text = _CONTROL_CHARS.sub("", text)
    text = _INVISIBLE_CHARS.sub("", text)
    text = text.replace("|", "/")
    text = " ".join(text.split())  # kollabiert auch verbleibende Whitespaces/Newlines
    if len(text) > max_len:
        text = text[: max_len - 1].rstrip() + "…"
    return text


def mask_email(address: str) -> str:
    """Kürzt eine Mailadresse für Logs (4.7: keine vollständigen Mailadressen in Logs)."""
    if not address or "@" not in address:
        return "***"
    local, _, domain = address.partition("@")
    local_masked = (local[0] + "***") if local else "***"
    return f"{local_masked}@{domain}"
