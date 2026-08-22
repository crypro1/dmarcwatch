"""Konfiguration für dmarcwatch.

Enthält keine Zugangsdaten. Das Passwort liegt ausschließlich im
macOS-Schlüsselbund (siehe keychain.py).
"""
from __future__ import annotations

import ipaddress
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path

APP_NAME = "dmarcwatch"

DEFAULT_CONFIG = {
    # Kein Default: dmarcwatch ist ein öffentliches Projekt, nicht nur für
    # mailbox.org-Postfächer (auch wenn das der primär getestete Anbieter
    # ist) - ein vorbelegter mailbox.org-Hostname würde bei Enter ohne
    # genaues Lesen zu einem verwirrenden Verbindungsfehler gegen den
    # falschen Server führen, statt offensichtlich das eigene Postfach zu
    # sein. `dmarcwatch setup` fragt das deshalb genauso zwingend ab wie
    # imap_user/own_domains weiter unten.
    "imap_host": "",
    # imap_port bleibt vorbelegt: 993 (IMAPS/implizites TLS) ist
    # anbieterunabhängig der Standardport, kein mailbox.org-Spezifikum.
    "imap_port": 993,
    # Kein Default: der IMAP-Login ist das echte Postfach, nicht die
    # rua-Alias-Adresse aus dem DMARC-DNS-Eintrag - bei mailbox.org sind
    # Aliase i. d. R. kein eigenständiger IMAP-Login, die Mails landen im
    # echten Postfach. Wird bei `dmarcwatch setup` abgefragt.
    "imap_user": "",
    # Bei mailbox.org liegen per Filterregel angelegte Ordner meist unter
    # INBOX (in der Weboberfläche "Eingang" genannt), nicht als eigener
    # Top-Level-Ordner. Bei Zweifel: `dmarcwatch fetch` mit falschem Namen
    # ausführen, die Fehlermeldung listet die tatsächlichen Ordnernamen.
    "imap_folder": "INBOX/DMARC",
    "move_to_processed_folder": False,
    "processed_folder": "INBOX/DMARC/verarbeitet",
    # Kein Default: muss die eigene(n) Domain(s) sein, nicht irgendeine.
    "own_domains": [],
    # CIDR-Netze, keine Zeichenketten-Präfixe: IPv6-Adressen haben mehrere
    # gültige Schreibweisen (Kompression, Groß-/Kleinschreibung), da scheitert
    # ein reiner Präfixvergleich. Kein sinnvoller Default möglich - die
    # eigenen Sende-Netze kennt man i. d. R. erst nach den ersten echten
    # Reports (oder aus dem eigenen SPF-Eintrag). Leer = sicherer, aber
    # sichtbarer Zustand: jede IP gilt zunächst als "unbekannt" und wird
    # markiert, bis das hier gefüllt ist - kein stilles Falsch-negativ.
    "own_ip_networks": [],
    # 10 MB unkomprimiertes XML ist laut IETF-Draft zur DMARC-Aggregate-
    # Reporting-Spezifikation "far larger than any real aggregate report" -
    # als Obergrenze bewusst großzügig, aber kein willkürlicher Wert.
    "max_attachment_size_mb": 5,
    "max_xml_size_mb": 10,
    # Obergrenze für die gesamte Nachricht (Header + alle MIME-Teile,
    # base64-kodiert), geprüft VOR dem eigentlichen IMAP-Abruf des Bodys -
    # nicht nur für den einzelnen Anhang danach. Jeder kann eine Mail an die
    # rua-Adresse schicken, die Nachricht selbst ist unvertrauenswürdig.
    # Aus max_attachment_size_mb abgeleitet: base64 bläht ~1.37x auf
    # (5 MB -> ~6.85 MB), plus Spielraum für Header/MIME-Boundaries.
    "max_message_size_mb": 8,
    # Belt-and-suspenders gegen viele flache <record>-Elemente innerhalb der
    # ohnehin schon vorhandenen Größengrenze: ein einzelner Report an der
    # 10-MB-Grenze mit ~42.000 flachen Records kostet empirisch bereits unter
    # 1s CPU-Zeit (siehe README, Sicherheitsentscheidungen) - dieses Limit
    # macht das Verhalten bei absichtlicher Datenflut zusätzlich
    # deterministisch, statt sich allein auf die CPU-Zeit-Obergrenze des
    # LaunchAgents zu verlassen.
    "max_records_per_report": 10000,
    "notify_on_new_findings": True,
    "enable_reverse_dns_lookup": False,
    "menubar_days": 7,
}


def app_support_dir() -> Path:
    return Path.home() / "Library" / "Application Support" / APP_NAME


def config_path() -> Path:
    return app_support_dir() / "config.json"


def db_path() -> Path:
    return app_support_dir() / "dmarc.sqlite"


def log_path() -> Path:
    return app_support_dir() / "dmarcwatch.log"


def last_fetch_marker_path() -> Path:
    return app_support_dir() / "last_fetch_success"


def read_last_fetch_date(path: Path | None = None) -> str | None:
    """Datum (YYYY-MM-DD, lokale Zeitzone) des letzten erfolgreich
    DURCHGELAUFENEN `fetch` - unabhängig davon, ob dabei neue Reports
    gefunden wurden. Für den `--skip-if-already-run-today`-Aufruf des
    LaunchAgents (siehe launchd.py): RunAtLoad allein würde bei jedem
    Login/Neustart einen (harmlosen, aber unnötigen) IMAP-Check auslösen -
    dieses Datum lässt cmd_fetch erkennen, ob heute schon einer lief."""
    path = path or last_fetch_marker_path()
    if not path.exists():
        return None
    try:
        return path.read_text(encoding="utf-8").strip() or None
    except OSError:
        return None


def write_last_fetch_date(date_str: str, path: Path | None = None) -> Path:
    path = path or last_fetch_marker_path()
    _ensure_dir_secure(path.parent)
    with open(path, "w", encoding="utf-8") as f:
        f.write(date_str)
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0600
    return path


def _ensure_dir_secure(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, stat.S_IRWXU)  # 0700


@dataclass
class Config:
    imap_host: str
    imap_port: int
    imap_user: str
    imap_folder: str
    move_to_processed_folder: bool
    processed_folder: str
    own_domains: tuple[str, ...]
    own_ip_networks: tuple[str, ...]
    max_attachment_size_mb: int
    max_xml_size_mb: int
    max_message_size_mb: int
    max_records_per_report: int
    notify_on_new_findings: bool
    enable_reverse_dns_lookup: bool
    menubar_days: int

    def __post_init__(self) -> None:
        networks = []
        for n in self.own_ip_networks:
            try:
                networks.append(ipaddress.ip_network(n, strict=False))
            except ValueError as exc:
                raise ValueError(f"Ungültiges Netz in own_ip_networks: {n!r}") from exc
        self._own_networks = tuple(networks)

    @property
    def max_attachment_size_bytes(self) -> int:
        return self.max_attachment_size_mb * 1024 * 1024

    @property
    def max_xml_size_bytes(self) -> int:
        return self.max_xml_size_mb * 1024 * 1024

    @property
    def max_message_size_bytes(self) -> int:
        return self.max_message_size_mb * 1024 * 1024

    def is_own_domain(self, domain: str) -> bool:
        domain = (domain or "").strip().lower().rstrip(".")
        return domain in {d.strip().lower().rstrip(".") for d in self.own_domains}

    def is_own_ip(self, ip: str) -> bool:
        # Netzzugehörigkeit über ipaddress, kein Zeichenkettenvergleich:
        # dieselbe IPv6-Adresse hat mehrere gültige Schreibweisen, und ein
        # Präfixvergleich auf Zeichenketten-Ebene entspricht nicht
        # zuverlässig einer CIDR-Netzgrenze.
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self._own_networks)

    @classmethod
    def from_dict(cls, data: dict) -> "Config":
        merged = {**DEFAULT_CONFIG, **data}
        return cls(
            imap_host=str(merged["imap_host"]),
            imap_port=int(merged["imap_port"]),
            imap_user=str(merged["imap_user"]),
            imap_folder=str(merged["imap_folder"]),
            move_to_processed_folder=bool(merged["move_to_processed_folder"]),
            processed_folder=str(merged["processed_folder"]),
            own_domains=tuple(merged["own_domains"]),
            own_ip_networks=tuple(merged["own_ip_networks"]),
            max_attachment_size_mb=int(merged["max_attachment_size_mb"]),
            max_xml_size_mb=int(merged["max_xml_size_mb"]),
            max_message_size_mb=int(merged["max_message_size_mb"]),
            max_records_per_report=int(merged["max_records_per_report"]),
            notify_on_new_findings=bool(merged["notify_on_new_findings"]),
            enable_reverse_dns_lookup=bool(merged["enable_reverse_dns_lookup"]),
            menubar_days=int(merged["menubar_days"]),
        )


def load_config(path: Path | None = None) -> Config:
    path = path or config_path()
    if not path.exists():
        return Config.from_dict({})
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return Config.from_dict(data)


def write_default_config_if_missing(path: Path | None = None) -> Path:
    path = path or config_path()
    _ensure_dir_secure(path.parent)
    if not path.exists():
        with open(path, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_CONFIG, f, indent=2, ensure_ascii=False, sort_keys=True)
            f.write("\n")
    # Immer durchsetzen, nicht nur bei Neuanlage - falls die Datei aus einer
    # älteren Version oder von Hand mit laxeren Rechten entstanden ist.
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0600
    return path


def read_raw_config(path: Path | None = None) -> dict:
    """Liest die rohen JSON-Werte (nicht die typisierte Config), für
    partielle Updates durch den interaktiven Setup-Dialog."""
    path = path or config_path()
    if not path.exists():
        return dict(DEFAULT_CONFIG)
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return {**DEFAULT_CONFIG, **data}


def write_config(data: dict, path: Path | None = None) -> Path:
    path = path or config_path()
    _ensure_dir_secure(path.parent)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, sort_keys=True)
        f.write("\n")
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0600
    return path
