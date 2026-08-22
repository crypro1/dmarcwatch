"""`dmarcwatch verify-dns <domain>`: prüft die eigenen DMARC/SPF/DKIM-
DNS-Einträge auf Gültigkeit und häufige Fehlkonfigurationen - Diagnose,
nicht Reaktion. dmarcwatchs Kernfunktion wertet aus, was andere Server
über bereits verschickte Mail *beobachtet* haben; das hier prüft
stattdessen proaktiv, ob die eigenen DNS-Einträge überhaupt korrekt
aufgesetzt sind, unabhängig von jedem einzelnen Report.

Verlässt das Gerät (DNS) - deshalb ein expliziter CLI-Befehl, nie
automatisch während `fetch` ausgeführt, gleiche Begründung wie bei
`inspect --whois` und `resolve-spf`.

DKIM-Selektoren werden nicht geraten (die üblichen Tools probieren eine
feste Liste "typischer" Namen durch, was zwangsläufig unvollständig
bleibt) - stattdessen aus bereits vorhandenen, echten Reports in der
lokalen Datenbank gelesen (siehe store.get_known_dkim_selectors). Das ist
zuverlässiger, hat aber eine Voraussetzung: es funktioniert nur für
Selektoren, die in mindestens einem bisher abgerufenen Report tatsächlich
aufgetaucht sind.
"""
from __future__ import annotations

import re
import sqlite3
import subprocess
from dataclasses import dataclass, field

from .spf import DIG_TIMEOUT_SECONDS, SPFCheckResult, _txt_records, validate_spf
from .store import get_known_dkim_selectors

VALID_POLICIES = {"none", "quarantine", "reject"}


class DNSVerifyError(RuntimeError):
    pass


@dataclass
class DMARCCheckResult:
    exists: bool
    record: str | None = None
    policy: str | None = None
    subdomain_policy: str | None = None
    pct: int | None = None
    rua: str | None = None
    ruf: str | None = None
    adkim: str | None = None
    aspf: str | None = None
    warnings: list[str] = field(default_factory=list)


@dataclass
class DKIMCheckResult:
    selector: str
    exists: bool
    key_type: str | None = None
    warnings: list[str] = field(default_factory=list)


@dataclass
class DomainVerification:
    domain: str
    dmarc: DMARCCheckResult
    spf: SPFCheckResult
    dkim: list[DKIMCheckResult]


def _parse_dmarc_tags(record: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in record.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        key, _, value = part.partition("=")
        tags[key.strip().lower()] = value.strip()
    return tags


def check_dmarc(domain: str) -> DMARCCheckResult:
    """Prüft `_dmarc.<domain>` auf einen gültigen DMARC-Eintrag und
    typische Fehlkonfigurationen (fehlende `rua` - keine Reports möglich;
    `p=none` - noch keine Durchsetzung; mehrere DMARC-Einträge - laut
    RFC 7489 komplett ungültig, nicht nur der erste zählt)."""
    all_records = _txt_records(f"_dmarc.{domain}")
    dmarc_records = [r for r in all_records if r.lower().startswith("v=dmarc1")]

    if not dmarc_records:
        return DMARCCheckResult(exists=False, warnings=["Kein DMARC-Eintrag (v=DMARC1) gefunden."])

    warnings: list[str] = []
    if len(dmarc_records) > 1:
        warnings.append(
            f"{len(dmarc_records)} DMARC-Einträge unter _dmarc.{domain} gefunden - laut "
            "RFC 7489 macht das den gesamten Eintrag ungültig (Empfänger sehen dann gar "
            "keinen gültigen DMARC-Schutz), nicht nur der erste zählt."
        )

    tags = _parse_dmarc_tags(dmarc_records[0])
    policy = tags.get("p")
    if policy is None:
        warnings.append("Pflicht-Tag 'p' (Policy) fehlt - der Eintrag ist damit ungültig.")
    elif policy not in VALID_POLICIES:
        warnings.append(f"Ungültiger Policy-Wert p={policy!r} (erlaubt: none/quarantine/reject).")
    elif policy == "none":
        warnings.append(
            "p=none: rein beobachtend, noch keine Durchsetzung gegen Spoofing - "
            "üblicher erster Schritt, aber kein aktiver Schutz."
        )

    if "rua" not in tags:
        warnings.append(
            "Kein 'rua' (Aggregate-Report-Adresse) gesetzt - ohne das bekommt niemand "
            "Reports zugeschickt, dmarcwatch selbst hätte dann nichts zum Abrufen."
        )

    pct_raw = tags.get("pct")
    pct = None
    if pct_raw is not None:
        try:
            pct = int(pct_raw)
        except ValueError:
            warnings.append(f"Ungültiger 'pct'-Wert {pct_raw!r} (muss eine Zahl 0-100 sein).")
        else:
            if not (0 <= pct <= 100):
                warnings.append(f"'pct'-Wert {pct} liegt außerhalb 0-100.")
            elif pct < 100 and policy != "none":
                warnings.append(
                    f"pct={pct}: nur {pct}% der Mail unterliegt der Durchsetzung - der Rest "
                    "wird wie bei p=none behandelt."
                )

    return DMARCCheckResult(
        exists=True,
        record=dmarc_records[0],
        policy=policy,
        subdomain_policy=tags.get("sp"),
        pct=pct,
        rua=tags.get("rua"),
        ruf=tags.get("ruf"),
        adkim=tags.get("adkim", "r"),
        aspf=tags.get("aspf", "r"),
        warnings=warnings,
    )


_RSA_KEY_RE = re.compile(r"p=([A-Za-z0-9+/=]+)")


def check_dkim(domain: str, selector: str) -> DKIMCheckResult:
    """Prüft `<selector>._domainkey.<domain>` auf einen gültigen
    DKIM-Key-Eintrag. Unterscheidet RSA (Default, `k=rsa` oder kein `k`-Tag)
    von Ed25519 (`k=ed25519`) - beide werden von DKIM unterstützt."""
    name = f"{selector}._domainkey.{domain}"
    try:
        result = subprocess.run(
            ["dig", "+short", "+time=3", "+tries=1", "TXT", name],
            capture_output=True,
            text=True,
            timeout=DIG_TIMEOUT_SECONDS,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        return DKIMCheckResult(
            selector=selector, exists=False, warnings=[f"DNS-Abfrage fehlgeschlagen: {exc}"]
        )
    if result.returncode != 0:
        detail = result.stderr.strip() or f"dig beendete sich mit Code {result.returncode}"
        return DKIMCheckResult(selector=selector, exists=False, warnings=[f"DNS-Abfrage fehlgeschlagen: {detail}"])

    lines = [line for line in result.stdout.splitlines() if line.strip()]
    # Viele Anbieter (u. a. mailbox.org) verwenden ein CNAME auf den
    # eigenen Domainkey-Eintrag, damit Kund:innen bei einer Schlüsselrotation
    # nichts an ihrer DNS ändern müssen - `dig +short` zeigt dann zuerst das
    # CNAME-Ziel als reine, unquotierte Zeile, erst danach den tatsächlichen
    # TXT-Inhalt in Anführungszeichen. Nicht einfach die erste Zeile nehmen,
    # sondern gezielt die TXT-Nutzlast suchen (die einzige Zeile mit `"`).
    txt_lines = [line for line in lines if '"' in line]
    if not txt_lines:
        return DKIMCheckResult(
            selector=selector, exists=False,
            warnings=[f"Kein DKIM-Eintrag unter {name} gefunden."],
        )

    parts = txt_lines[-1].split('"')
    record = "".join(parts[i] for i in range(1, len(parts), 2))
    tags = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            key, _, value = part.partition("=")
            tags[key.strip().lower()] = value.strip()

    warnings: list[str] = []
    key_type = tags.get("k", "rsa").lower()
    if key_type not in ("rsa", "ed25519"):
        warnings.append(f"Unbekannter Key-Typ k={key_type!r} (erwartet: rsa oder ed25519).")
    if not tags.get("p"):
        warnings.append(
            "Kein Public Key ('p'-Tag leer oder fehlt) - falls das ein Widerruf sein soll, "
            "ist das korrekt, sonst ist der Selektor nicht funktionsfähig."
        )

    return DKIMCheckResult(selector=selector, exists=True, key_type=key_type, warnings=warnings)


def verify_domain(conn: sqlite3.Connection, domain: str) -> DomainVerification:
    """DMARC + SPF + DKIM (bekannte Selektoren aus echten, bereits
    abgerufenen Reports) für `domain` prüfen."""
    dmarc = check_dmarc(domain)
    spf = validate_spf(domain)
    selectors = get_known_dkim_selectors(conn, domain)
    dkim = [check_dkim(domain, selector) for selector in selectors]
    return DomainVerification(domain=domain, dmarc=dmarc, spf=spf, dkim=dkim)
