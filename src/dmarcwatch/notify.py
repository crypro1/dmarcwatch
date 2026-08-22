"""macOS-Benachrichtigungen über osascript.

Kein os.system, kein shell=True - subprocess mit Argumentliste. Der Text
kommt aus Report-Daten und ist unvertrauenswürdig, daher wird er zuerst
mit sanitize_field() bereinigt und zusätzlich für den AppleScript-
Stringliteral-Kontext escaped (Anführungszeichen, Backslashes).
"""
from __future__ import annotations

import subprocess

from .sanitize import sanitize_field


def _applescript_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"')


def _build_script(title: str, message: str, subtitle: str = "") -> str:
    safe_title = _applescript_escape(sanitize_field(title, max_len=80))
    safe_message = _applescript_escape(sanitize_field(message, max_len=200))
    safe_subtitle = _applescript_escape(sanitize_field(subtitle, max_len=80))

    script = f'display notification "{safe_message}" with title "{safe_title}"'
    if safe_subtitle:
        script += f' subtitle "{safe_subtitle}"'
    return script


def send_notification(title: str, message: str, subtitle: str = "") -> None:
    script = _build_script(title, message, subtitle)
    subprocess.run(
        ["/usr/bin/osascript", "-e", script],
        check=False,
        capture_output=True,
        timeout=10,
    )
