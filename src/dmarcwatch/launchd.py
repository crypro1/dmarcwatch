"""launchd-LaunchAgent-Verwaltung.

Nur noch ein selbst installierter Agent: LABEL (`fetch`, einmal täglich,
Background), ruft `<python> -m dmarcwatch fetch` auf. Keine Zugangsdaten in
der plist - das Passwort kommt zur Laufzeit aus dem Schlüsselbund.

Die Menüleisten-App registriert sich seit der SMAppService-Umstellung
selbst als Login-Item (siehe macapp/.../LoginItemManager.swift) - hier
bleibt nur noch MENUBAR_LABEL/uninstall_menubar() als Migrationshilfe für
die alte, plist-basierte Installation (`dmarcwatch setup
--remove-menubar-agent`).
"""
from __future__ import annotations

import plistlib
import stat
import subprocess
import sys
from pathlib import Path

from .config import app_support_dir

# "local." statt einer echten reverse-DNS-Domain: dmarcwatch gehört keiner
# registrierten Domain, "local." ist die übliche macOS-Konvention für
# lokal definierte, nicht veröffentlichte Bundle-Identifier.
LABEL = "local.dmarcwatch.fetch"
MENUBAR_LABEL = "local.dmarcwatch.menubar"


def plist_path() -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"{LABEL}.plist"


def build_plist(python_executable: str, hour: int = 7, minute: int = 30) -> bytes:
    logs_dir = app_support_dir()
    plist = {
        "Label": LABEL,
        "ProgramArguments": [
            python_executable, "-m", "dmarcwatch", "fetch", "--skip-if-already-run-today",
        ],
        "StartCalendarInterval": {"Hour": hour, "Minute": minute},
        # Bewusst KEIN RunAtLoad: das würde diese plist als "öffnet bei der
        # Anmeldung"-Eintrag in Systemeinstellungen > Anmeldeobjekte
        # auftauchen lassen - als nacktes "python3, unbekannter Entwickler"
        # ohne App-Zuordnung, unnötig verwirrend. Das eigentliche Problem
        # (launchd holt einen wegen ausgeschaltetem Mac verpassten
        # StartCalendarInterval-Termin NICHT von selbst nach, anders als
        # z. B. cron+anacron) wird stattdessen von der bereits sichtbaren,
        # namentlich zugeordneten Menüleisten-App gelöst: die stößt bei
        # jedem eigenen Start (main.swift) einen `fetch
        # --skip-if-already-run-today`-Lauf an. --skip-if-already-run-today
        # verhindert dabei unnötige doppelte IMAP-Checks (siehe
        # config.read_last_fetch_date) - egal ob der Auslöser die App oder
        # der planmäßige StartCalendarInterval-Termin war.
        "RunAtLoad": False,
        "StandardOutPath": str(logs_dir / "launchd.out.log"),
        "StandardErrorPath": str(logs_dir / "launchd.err.log"),
        "ProcessType": "Background",
        # Kernel-durchgesetzte Obergrenze für CPU-Zeit als Backstop gegen
        # ausufernde Rechenzeit, zusätzlich zu den eigenen Größenprüfungen
        # im Code. Wert aus echten Messungen abgeleitet (6 Läufe, Median
        # 0.08s CPU-Zeit) mit großzügigem Sicherheitsabstand - fetch ist
        # ein kurzlebiger, täglich neu gestarteter Prozess, RLIMIT_CPU
        # zählt also pro Lauf, nicht kumulativ über die Zeit.
        #
        # Nur SoftResourceLimits, kein HardResourceLimits: empirisch
        # getestet (Testprozess, der SIGXCPU fängt und ignoriert lief auf
        # diesem macOS 34+s weiter, obwohl das Hard-Limit bei 3s lag - kein
        # SIGKILL). Der Soft-Limit-Pfad (SIGXCPU, Default-Aktion
        # "terminate") wurde separat verifiziert und funktioniert
        # zuverlässig, solange kein eigener Signal-Handler installiert ist
        # - genau der Fall hier, fetch.py fängt SIGXCPU nicht ab.
        "SoftResourceLimits": {"CPU": 1},
    }
    return plistlib.dumps(plist)


def install(python_executable: str | None = None, hour: int = 7, minute: int = 30) -> Path:
    python_executable = python_executable or sys.executable
    target = plist_path()
    target.parent.mkdir(parents=True, exist_ok=True)

    data = build_plist(python_executable, hour, minute)
    with open(target, "wb") as f:
        f.write(data)
    target.chmod(stat.S_IRUSR | stat.S_IWUSR)

    # bootout etwaiger alter Version ignorieren, falls keine läuft
    subprocess.run(
        ["launchctl", "bootout", f"gui/{_uid()}/{LABEL}"], check=False, capture_output=True
    )
    subprocess.run(["launchctl", "load", "-w", str(target)], check=True, capture_output=True)
    return target


def uninstall() -> bool:
    target = plist_path()
    subprocess.run(
        ["launchctl", "bootout", f"gui/{_uid()}/{LABEL}"], check=False, capture_output=True
    )
    if target.exists():
        subprocess.run(["launchctl", "unload", "-w", str(target)], check=False, capture_output=True)
        target.unlink()
        return True
    return False


def menubar_plist_path() -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"{MENUBAR_LABEL}.plist"


def uninstall_menubar() -> bool:
    target = menubar_plist_path()
    subprocess.run(
        ["launchctl", "bootout", f"gui/{_uid()}/{MENUBAR_LABEL}"], check=False, capture_output=True
    )
    if target.exists():
        subprocess.run(["launchctl", "unload", "-w", str(target)], check=False, capture_output=True)
        target.unlink()
        return True
    return False


def _uid() -> int:
    import os

    return os.getuid()
