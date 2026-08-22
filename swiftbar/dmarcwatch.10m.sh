#!/bin/bash
# SwiftBar-Plugin für dmarcwatch.
#
# Installation: diese Datei (oder einen Symlink darauf) in den
# SwiftBar-Plugin-Ordner legen. Der Dateiname bestimmt das Intervall
# ("10m" = alle 10 Minuten); bei Bedarf umbenennen.
#
# Ruft nur `dmarcwatch menubar` im venv auf und gibt dessen Ausgabe
# unverändert weiter - alle Sicherheits-relevante Bereinigung (SwiftBar
# nutzt "|" als Parameter-Trenner, "bash=" führt Befehle aus) passiert
# bereits in dmarcwatch selbst (menubar.py / sanitize.py), nicht hier.

set -euo pipefail

DMARCWATCH_HOME="${DMARCWATCH_HOME:-$HOME/dmarcwatch}"
DMARCWATCH_BIN="$DMARCWATCH_HOME/.venv/bin/dmarcwatch"

if [ ! -x "$DMARCWATCH_BIN" ]; then
    echo "DMARC ⚠︎ setup"
    echo "---"
    echo "dmarcwatch nicht gefunden unter: $DMARCWATCH_BIN"
    echo "DMARCWATCH_HOME in diesem Skript anpassen oder dmarcwatch installieren."
    exit 0
fi

exec "$DMARCWATCH_BIN" menubar
