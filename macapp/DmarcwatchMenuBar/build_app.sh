#!/bin/bash
# Baut DmarcwatchMenuBar.app: Release-Binary, Icon und Info.plist zu einem
# echten App-Bundle zusammenpacken.
#
# Ohne das zeigt macOS (Aktivitätsanzeige, Systemeinstellungen > Anmelde-
# objekte) nur ein leeres Icon, weil eine bloße Mach-O-Datei kein Bundle
# mit Icon-Ressource ist - `swift build` allein erzeugt nur die Binary,
# kein .app.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

APP_NAME="DmarcwatchMenuBar"
APP_BUNDLE="$APP_NAME.app"

echo "Baue Release-Binary ..."
swift build -c release
BINARY_PATH="$(swift build -c release --show-bin-path)/$APP_NAME"

if [ ! -f "AppIcon.icns" ]; then
    echo "AppIcon.icns fehlt - einmalig erzeugen mit:"
    echo "  swift generate_icon.swift && iconutil -c icns AppIcon.iconset -o AppIcon.icns"
    exit 1
fi

echo "Packe App-Bundle ..."
rm -rf "$APP_BUNDLE"
mkdir -p "$APP_BUNDLE/Contents/MacOS" "$APP_BUNDLE/Contents/Resources"
cp "$BINARY_PATH" "$APP_BUNDLE/Contents/MacOS/$APP_NAME"
cp "AppIcon.icns" "$APP_BUNDLE/Contents/Resources/AppIcon.icns"
cp "Info.plist" "$APP_BUNDLE/Contents/Info.plist"

# Lokal (ad-hoc) signieren, sonst kann Gatekeeper beim ersten Start meckern.
# Kein Developer-ID nötig - reines lokales Werkzeug, keine Veröffentlichung.
codesign --force --deep --sign - "$APP_BUNDLE" 2>&1 | grep -v "replacing existing signature" || true

echo "Fertig: $SCRIPT_DIR/$APP_BUNDLE"
