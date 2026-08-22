#!/bin/bash
# Ein-Kommando-Installer für dmarcwatch.
#
# Macht mechanisch, was in der README unter "Installation" beschrieben ist:
# venv anlegen, pip aktualisieren, Paket installieren. Erst danach - und nur
# mit Rückfrage - wird optional `dmarcwatch setup` aufgerufen, das
# interaktiv (getpass, kein Kommandozeilenargument) nach dem IMAP-Passwort
# fragt und es im Schlüsselbund ablegt, und optional den täglichen
# LaunchAgent installiert. Beides sind dauerhafte Änderungen am System und
# passieren deshalb nicht automatisch ohne Bestätigung.
#
# Idempotent: mehrfaches Ausführen ist unschädlich, ein bestehendes .venv
# wird weiterverwendet statt neu angelegt.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "== dmarcwatch Installer =="
echo

if ! command -v python3 >/dev/null 2>&1; then
    echo "Fehler: python3 wurde nicht gefunden." >&2
    echo "Bitte Python 3.9 oder neuer installieren (System oder Homebrew)." >&2
    exit 1
fi

PY_VERSION="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
PY_OK="$(python3 -c 'import sys; print(1 if sys.version_info >= (3, 9) else 0)')"
if [ "$PY_OK" != "1" ]; then
    echo "Fehler: Python $PY_VERSION gefunden, dmarcwatch braucht mindestens 3.9." >&2
    exit 1
fi
echo "Python $PY_VERSION gefunden."

if [ ! -d .venv ]; then
    echo "Lege virtuelle Umgebung an (.venv) ..."
    python3 -m venv .venv
else
    echo ".venv existiert bereits, wird weiterverwendet."
fi

echo "Aktualisiere pip ..."
.venv/bin/pip install --upgrade pip --quiet

echo "Installiere dmarcwatch ..."
.venv/bin/pip install . --quiet

echo
echo "Installation abgeschlossen: $SCRIPT_DIR/.venv/bin/dmarcwatch"
echo

read -r -p "Jetzt Schlüsselbund-Passwort einrichten? [Y/n] " REPLY
REPLY="${REPLY:-Y}"
if [[ "$REPLY" =~ ^[Yy] ]]; then
    read -r -p "Zusätzlich täglichen LaunchAgent (automatischer Abruf) installieren? [Y/n] " AGENT_REPLY
    AGENT_REPLY="${AGENT_REPLY:-Y}"
    if [[ "$AGENT_REPLY" =~ ^[Yy] ]]; then
        .venv/bin/dmarcwatch setup --install-agent
    else
        .venv/bin/dmarcwatch setup
        echo "LaunchAgent übersprungen. Später: $SCRIPT_DIR/.venv/bin/dmarcwatch setup --install-agent"
    fi
else
    echo "Schlüsselbund-Einrichtung übersprungen. Später jederzeit:"
    echo "  $SCRIPT_DIR/.venv/bin/dmarcwatch setup --install-agent"
fi

echo
echo "Fertig. Testlauf: $SCRIPT_DIR/.venv/bin/dmarcwatch fetch -v"
echo "Tabelle ansehen:  $SCRIPT_DIR/.venv/bin/dmarcwatch report"
