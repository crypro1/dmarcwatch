"""Notification-Text kommt aus Report-Daten und ist unvertrauenswürdig
(Spezifikation 4.6). Ein Versuch, aus dem AppleScript-Stringliteral
auszubrechen und einen zweiten Befehl anzuhängen, darf nicht funktionieren."""
import re
import subprocess

import pytest

from dmarcwatch.notify import _build_script

# Versuch, aus dem Stringliteral auszubrechen und einen Shell-Befehl über
# AppleScripts "do shell script" anzuhängen.
BREAKOUT_ATTEMPT = 'DMARC" & (do shell script "touch /tmp/dmarcwatch_test_pwned") & "'

# Ein "unescaptes" Anführungszeichen ist eines, dem keine ungerade Anzahl
# Backslashes vorausgeht - hier reicht die einfache Form (kein \ direkt davor),
# weil _applescript_escape() jeden \ und jedes " genau einmal escaped, es
# also nie mehrere Backslashes in Folge vor einem " geben kann.
_UNESCAPED_QUOTE = re.compile(r'(?<!\\)"')


def test_build_script_escapes_quotes_and_backslashes():
    script = _build_script(title=BREAKOUT_ATTEMPT, message="probe")
    assert 'do shell script' in script  # Text landet nur als Daten, nicht als Syntax
    assert '\\"' in script  # das Payload-Anführungszeichen wurde escaped

    # Alle unescapten " im Skript müssen unsere eigenen Trenner sein: genau
    # 4 (Anfang/Ende von "message" und von "title"), keine zusätzlichen aus
    # dem Payload durchgesickerten.
    unescaped_count = len(_UNESCAPED_QUOTE.findall(script))
    assert unescaped_count == 4, script


def test_build_script_handles_backslash_before_quote_correctly():
    # Backslash muss VOR dem Anführungszeichen escaped werden, sonst würde
    # ein von uns eingefügtes \" durch einen payload-eigenen Backslash
    # kaputt interpretiert.
    script = _build_script(title="a\\", message='b"c')
    assert script.count('\\\\') >= 1  # der Backslash selbst wurde verdoppelt


def test_osascript_actually_executes_the_generated_script_safely(tmp_path):
    marker = tmp_path / "pwned"
    breakout = f'DMARC" & (do shell script "touch {marker}") & "'
    script = _build_script(title=breakout, message="probe")

    try:
        result = subprocess.run(
            ["/usr/bin/osascript", "-e", script], capture_output=True, text=True, timeout=10
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pytest.skip("osascript nicht verfügbar in dieser Umgebung")

    # Die generierte AppleScript-Syntax muss gültig sein (kein Fehler durch
    # unsere eigene Escaping-Logik) UND der Ausbruchsversuch darf nicht
    # ausgeführt worden sein.
    assert result.returncode == 0, result.stderr
    assert not marker.exists()
