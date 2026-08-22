#!/bin/bash
# Deinstalliert dmarcwatch. Gegenstück zu install.sh.
#
# Standardmäßig sicher: entfernt beide LaunchAgents und lokale
# Build-Artefakte (.venv, Swift-Build - beides jederzeit über install.sh
# neu erzeugbar), löscht aber KEINE echten Daten (Konfiguration,
# Report-Datenbank, Logs, Schlüsselbund-Passwort) ohne explizite Flags.
# Der Projektordner selbst wird nie automatisch gelöscht - das macht der
# Nutzer bewusst von Hand, siehe Ausgabe am Ende.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

DELETE_DATA=false
DELETE_KEYCHAIN=false
for arg in "$@"; do
    case "$arg" in
        --delete-data) DELETE_DATA=true ;;
        --delete-keychain) DELETE_KEYCHAIN=true ;;
        --all) DELETE_DATA=true; DELETE_KEYCHAIN=true ;;
        -h|--help)
            echo "Usage: ./uninstall.sh [--delete-data] [--delete-keychain] [--all]"
            echo "  --delete-data       Konfiguration, Datenbank und Logs löschen"
            echo "  --delete-keychain   Schlüsselbund-Passwort löschen"
            echo "  --all               beides"
            exit 0
            ;;
    esac
done

echo "== dmarcwatch Deinstallation =="
echo

echo "Entferne LaunchAgents ..."
if [ -x .venv/bin/dmarcwatch ]; then
    .venv/bin/dmarcwatch setup --remove-agent --remove-menubar-agent || true
else
    launchctl bootout "gui/$(id -u)/local.dmarcwatch.fetch" 2>/dev/null || true
    launchctl bootout "gui/$(id -u)/local.dmarcwatch.menubar" 2>/dev/null || true
    rm -f "$HOME/Library/LaunchAgents/local.dmarcwatch.fetch.plist"
    rm -f "$HOME/Library/LaunchAgents/local.dmarcwatch.menubar.plist"
fi

MENUBAR_BINARY="macapp/DmarcwatchMenuBar/DmarcwatchMenuBar.app/Contents/MacOS/DmarcwatchMenuBar"
if [ -x "$MENUBAR_BINARY" ]; then
    # Falls über "Bei Anmeldung starten" (SMAppService) registriert - sonst
    # bliebe nach dem Löschen des Bundles weiter unten eine tote
    # Login-Item-Referenz zurück.
    "$MENUBAR_BINARY" --unregister-login-item 2>/dev/null || true
fi
pkill -f DmarcwatchMenuBar 2>/dev/null || true

echo
if [ "$DELETE_KEYCHAIN" = true ]; then
    IMAP_USER=$(python3 -c "
import json
from pathlib import Path
p = Path.home() / 'Library/Application Support/dmarcwatch/config.json'
print(json.load(open(p))['imap_user'] if p.exists() else '')
" 2>/dev/null || echo "")
    if [ -n "$IMAP_USER" ]; then
        security delete-generic-password -s dmarcwatch -a "$IMAP_USER" >/dev/null 2>&1 || true
        echo "Schlüsselbund-Eintrag für $IMAP_USER entfernt (falls vorhanden)."
    else
        echo "Kein imap_user in der Konfiguration gefunden, Schlüsselbund unverändert."
    fi
else
    echo "Schlüsselbund-Passwort NICHT entfernt (mit --delete-keychain oder --all löschen)."
fi

echo
if [ "$DELETE_DATA" = true ]; then
    rm -rf "$HOME/Library/Application Support/dmarcwatch"
    echo "Konfiguration, Datenbank und Logs entfernt."
else
    echo "Lokale Daten NICHT entfernt: ~/Library/Application Support/dmarcwatch"
    echo "  (Konfiguration, Report-Datenbank, Logs - mit --delete-data oder --all löschen)"
fi

echo
echo "Entferne lokale Build-Artefakte (.venv, Swift-Build) ..."
rm -rf .venv
rm -rf macapp/DmarcwatchMenuBar/.build
rm -rf macapp/DmarcwatchMenuBar/DmarcwatchMenuBar.app

echo
echo "Fertig. Keine LaunchAgents und keine Hintergrundprozesse mehr aktiv."
echo "Der Projektordner selbst ($SCRIPT_DIR) wurde NICHT gelöscht."
echo "Falls gewünscht, von Hand entfernen: rm -rf $SCRIPT_DIR"
