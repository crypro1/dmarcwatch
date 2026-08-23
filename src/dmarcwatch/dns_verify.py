"""`dmarcwatch verify-dns <domain>`: prüft die eigenen DMARC/SPF/DKIM-
DNS-Einträge auf Gültigkeit und häufige Fehlkonfigurationen - Diagnose,
nicht Reaktion. dmarcwatchs Kernfunktion wertet aus, was andere Server
über bereits verschickte Mail *beobachtet* haben; das hier prüft
stattdessen proaktiv, ob die eigenen DNS-Einträge überhaupt korrekt
aufgesetzt sind, unabhängig von jedem einzelnen Report.

Verlässt das Gerät (DNS, bei konfiguriertem MTA-STS zusätzlich ein
einzelner HTTPS-Abruf der eigenen Policy-Datei, und für die eigenen
MX-Server-IP(s) eine Spamhaus-ZEN-Abfrage, siehe blacklist.py) - deshalb
ein expliziter CLI-Befehl, nie automatisch während `fetch` ausgeführt,
gleiche Begründung wie bei `inspect --whois` und `resolve-spf`.

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
import ssl
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from .blacklist import BlacklistCheckError, check_ip_blacklist
from .spf import DIG_TIMEOUT_SECONDS, SPFCheckResult, SPFResolutionError, _dig, _txt_records, validate_spf
from .store import get_known_dkim_selectors

_HTTPS_TIMEOUT_SECONDS = 5.0

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
class MTASTSCheckResult:
    """MTA-STS (RFC 8461) ist optional - anders als DMARC/SPF/DKIM erzeugt
    ein komplettes Fehlen hier keine Warnung, nur ein angefangenes, aber
    unvollständiges Setup.

    policy_reachable: None, solange kein HTTPS-Abruf versucht wurde (z. B.
    weil noch nicht mal der Hostname konfiguriert ist), sonst das
    tatsächliche Ergebnis des Abrufs von https://mta-sts.<domain>/
    .well-known/mta-sts.txt - anbieterunabhängig, prüft die eigene Domain
    direkt statt eines Drittanbieter-Status."""

    configured: bool
    cname_target: str | None = None
    policy_txt: str | None = None
    policy_reachable: bool | None = None
    warnings: list[str] = field(default_factory=list)


@dataclass
class TLSRPTDNSCheckResult:
    """Der DNS-Eintrag, der anderen Mailservern sagt, wohin TLS-RPT-Berichte
    für die eigene Domain geschickt werden sollen (RFC 8460) - unabhängig
    von dmarcwatchs eigener TLS-RPT-Auswertung (enable_tls_rpt). Ebenfalls
    optional, keine Warnung bei komplettem Fehlen."""

    configured: bool
    record: str | None = None
    warnings: list[str] = field(default_factory=list)


@dataclass
class WildcardSPFCheckResult:
    """SPF für *.<domain> - schützt vor Phishing über nicht existierende
    Subdomains. Optional/fortgeschritten, keine Warnung bei Fehlen."""

    configured: bool
    record: str | None = None
    warnings: list[str] = field(default_factory=list)


@dataclass
class MXBlacklistCheckResult:
    """Prüft die IP(s) der eigenen Mailserver (per MX-Eintrag aufgelöst)
    gegen Spamhaus ZEN (siehe blacklist.py) - ein gelisteter eigener
    Mailserver ist ein ernstzunehmendes Problem (viele Empfänger lehnen
    Mail von dort ab), unabhängig vom sonstigen DMARC/SPF/DKIM-Setup.

    checked=False, wenn keine MX-Einträge gefunden wurden oder die
    DNS-Abfrage dafür fehlschlug - dann gibt es nichts zu warnen (kein MX
    heißt meist einfach, dass die Domain selbst keine Mail empfängt)."""

    checked: bool
    mx_hosts: list[str] = field(default_factory=list)
    listed: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class DomainVerification:
    domain: str
    dmarc: DMARCCheckResult
    spf: SPFCheckResult
    dkim: list[DKIMCheckResult]
    mta_sts: MTASTSCheckResult
    tlsrpt_dns: TLSRPTDNSCheckResult
    wildcard_spf: WildcardSPFCheckResult
    mx_blacklist: MXBlacklistCheckResult


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


def _fetch_mta_sts_policy(hostname: str) -> tuple[bool, str | None]:
    """Ruft die tatsächliche MTA-STS-Policy-Datei per HTTPS ab (RFC 8461) -
    liefert (erreichbar, Fehlermeldung-falls-nicht). Anbieterunabhängig:
    prüft direkt, ob die eigene Domain funktioniert, statt sich auf den
    allgemeinen Status eines bestimmten Hosting-Anbieters zu verlassen -
    der könnte "up" sein, während die eigene Policy trotzdem falsch
    konfiguriert ist (oder umgekehrt)."""
    url = f"https://{hostname}/.well-known/mta-sts.txt"
    context = ssl.create_default_context()
    request = urllib.request.Request(url)
    try:
        with urllib.request.urlopen(request, timeout=_HTTPS_TIMEOUT_SECONDS, context=context) as response:
            if response.status != 200:
                return False, f"HTTP {response.status}"
            content = response.read(4096).decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return False, str(exc)

    if not content.strip().lower().startswith("version: stsv1"):
        return False, "Antwort beginnt nicht mit 'version: STSv1'"
    return True, None


def check_mta_sts(domain: str) -> MTASTSCheckResult:
    """Prüft `mta-sts.<domain>` (CNAME oder direkter A/AAAA-Eintrag) und
    `_mta-sts.<domain>` (Policy-TXT, RFC 8461). Optional - fehlt beides
    komplett, ist das keine Warnung (die meisten Domains nutzen kein
    MTA-STS), nur ein angefangenes, aber unvollständiges Setup wird
    gemeldet (z. B. Policy-TXT ohne erreichbaren Hostnamen - genau der
    Fehler, der bei einem doppelt eingetragenen Domainnamen im DNS-Panel
    entsteht)."""
    try:
        cname_lines = _dig("CNAME", f"mta-sts.{domain}")
    except SPFResolutionError:
        cname_lines = []
    cname_target = cname_lines[0].rstrip(".") if cname_lines else None

    has_address = False
    if not cname_target:
        try:
            has_address = bool(_dig("A", f"mta-sts.{domain}")) or bool(_dig("AAAA", f"mta-sts.{domain}"))
        except SPFResolutionError:
            has_address = False
    hostname_configured = bool(cname_target) or has_address

    try:
        policy_records = [r for r in _txt_records(f"_mta-sts.{domain}") if r.lower().startswith("v=stsv1")]
    except SPFResolutionError:
        policy_records = []
    policy_txt = policy_records[0] if policy_records else None

    configured = hostname_configured or policy_txt is not None
    warnings: list[str] = []
    if configured:
        if not hostname_configured:
            warnings.append(
                f"_mta-sts.{domain} hat einen Policy-Eintrag, aber mta-sts.{domain} hat "
                "weder CNAME noch A/AAAA-Eintrag - die Policy-Datei ist für andere "
                "Mailserver dadurch nicht erreichbar."
            )
        if not policy_txt:
            warnings.append(
                f"mta-sts.{domain} ist konfiguriert, aber _mta-sts.{domain} hat keinen "
                "gültigen 'v=STSv1'-Policy-Eintrag - MTA-STS wird von anderen "
                "Mailservern dadurch nicht erkannt."
            )
        elif "id=" not in policy_txt.lower():
            warnings.append(f"_mta-sts.{domain}-Eintrag hat kein 'id='-Tag (Pflichtfeld laut RFC 8461).")

    # Nur tatsächlich abrufen, wenn der Hostname überhaupt auflöst - sonst
    # bräuchte es keinen Netzverkehr, um "nicht erreichbar" festzustellen,
    # das steht schon aus den DNS-Prüfungen oben fest.
    policy_reachable: bool | None = None
    if hostname_configured:
        reachable, error = _fetch_mta_sts_policy(f"mta-sts.{domain}")
        policy_reachable = reachable
        if not reachable:
            warnings.append(
                f"Policy-Datei unter https://mta-sts.{domain}/.well-known/mta-sts.txt "
                f"nicht erreichbar oder ungültig: {error}"
            )

    return MTASTSCheckResult(
        configured=configured, cname_target=cname_target, policy_txt=policy_txt,
        policy_reachable=policy_reachable, warnings=warnings,
    )


def check_tlsrpt_dns(domain: str) -> TLSRPTDNSCheckResult:
    """Prüft `_smtp._tls.<domain>` (TLS-RPT-Policy-DNS-Eintrag, RFC 8460) -
    sagt anderen Mailservern, wohin TLS-Berichte für die eigene Domain
    geschickt werden sollen. Unabhängig von dmarcwatchs eigener
    TLS-RPT-Auswertung (`enable_tls_rpt`): dieser DNS-Eintrag existiert für
    die eigene Domain, egal ob die eingehenden Berichte selbst mit
    dmarcwatch ausgewertet werden oder über einen Drittanbieter laufen.
    Optional, keine Warnung bei komplettem Fehlen."""
    try:
        records = [r for r in _txt_records(f"_smtp._tls.{domain}") if r.lower().startswith("v=tlsrptv1")]
    except SPFResolutionError:
        records = []

    if not records:
        return TLSRPTDNSCheckResult(configured=False)

    record = records[0]
    warnings: list[str] = []
    if "rua=" not in record.lower():
        warnings.append(
            f"_smtp._tls.{domain}-Eintrag hat kein 'rua='-Tag - ohne Berichts-Adresse "
            "bekommt niemand TLS-RPT-Berichte zugeschickt."
        )
    if len(records) > 1:
        warnings.append(
            f"{len(records)} TLS-RPT-Einträge unter _smtp._tls.{domain} gefunden - "
            "mehrere Einträge können zu uneindeutigem Verhalten führen."
        )

    return TLSRPTDNSCheckResult(configured=True, record=record, warnings=warnings)


def check_wildcard_spf(domain: str) -> WildcardSPFCheckResult:
    """Prüft `*.<domain>` TXT - schützt vor Phishing über nicht existierende
    Subdomains. Optional/fortgeschritten, keine Warnung bei Fehlen, nur ein
    vorhandener, aber zu offener Eintrag wird gemeldet."""
    try:
        records = [r for r in _txt_records(f"*.{domain}") if r.lower().startswith("v=spf1")]
    except SPFResolutionError:
        records = []

    if not records:
        return WildcardSPFCheckResult(configured=False)

    record = records[0]
    warnings: list[str] = []
    if "-all" not in record.lower():
        warnings.append(
            f"Wildcard-SPF-Eintrag (*.{domain}) endet nicht auf '-all' - er sollte "
            "möglichst restriktiv sein, da er für alle nicht existierenden Subdomains gilt."
        )

    return WildcardSPFCheckResult(configured=True, record=record, warnings=warnings)


def check_mx_blacklist(domain: str) -> MXBlacklistCheckResult:
    """Löst die MX-Einträge von `domain` auf, prüft deren IP(s) gegen
    Spamhaus ZEN. Kein MX oder eine fehlgeschlagene DNS-Abfrage ergibt
    checked=False statt einer Warnung - siehe MXBlacklistCheckResult."""
    try:
        mx_lines = _dig("MX", domain)
    except SPFResolutionError:
        return MXBlacklistCheckResult(checked=False)

    hosts: list[str] = []
    for line in mx_lines:
        parts = line.split()
        if not parts:
            continue
        hostname = parts[-1].rstrip(".")
        if hostname and hostname not in hosts:
            hosts.append(hostname)
    if not hosts:
        return MXBlacklistCheckResult(checked=False)

    # Mehrere MX-Hosts können auf dieselbe IP zeigen (z. B. Failover-
    # Konfiguration) - jede IP nur einmal tatsächlich abfragen.
    ip_to_host: dict[str, str] = {}
    for host in hosts:
        try:
            a_records = _dig("A", host)
        except SPFResolutionError:
            a_records = []
        for ip in a_records:
            ip_to_host.setdefault(ip, host)

    listed: list[str] = []
    warnings: list[str] = []
    for ip, host in ip_to_host.items():
        try:
            result = check_ip_blacklist(ip)
        except BlacklistCheckError as exc:
            warnings.append(f"Spamhaus-Abfrage für {host} ({ip}) fehlgeschlagen: {exc}")
            continue
        if result.listed:
            reasons = "; ".join(result.reasons)
            listed.append(f"{host} ({ip}): {reasons}")
            warnings.append(f"Mailserver {host} ({ip}) ist bei Spamhaus ZEN gelistet: {reasons}")

    return MXBlacklistCheckResult(checked=True, mx_hosts=hosts, listed=listed, warnings=warnings)


def verify_domain(conn: sqlite3.Connection, domain: str) -> DomainVerification:
    """DMARC + SPF + DKIM (bekannte Selektoren aus echten, bereits
    abgerufenen Reports) sowie MTA-STS/TLS-RPT-DNS/Wildcard-SPF (alle drei
    optional) und eine Spamhaus-Prüfung der eigenen MX-Server für `domain`
    prüfen."""
    dmarc = check_dmarc(domain)
    spf = validate_spf(domain)
    selectors = get_known_dkim_selectors(conn, domain)
    dkim = [check_dkim(domain, selector) for selector in selectors]
    mta_sts = check_mta_sts(domain)
    tlsrpt_dns = check_tlsrpt_dns(domain)
    wildcard_spf = check_wildcard_spf(domain)
    mx_blacklist = check_mx_blacklist(domain)
    return DomainVerification(
        domain=domain, dmarc=dmarc, spf=spf, dkim=dkim,
        mta_sts=mta_sts, tlsrpt_dns=tlsrpt_dns, wildcard_spf=wildcard_spf,
        mx_blacklist=mx_blacklist,
    )


def has_warnings(result: DomainVerification) -> bool:
    """True, wenn verify_domain() für diese Domain irgendeine Auffälligkeit
    gefunden hat - für die Rot-Einfärbung in der Menüleisten-App (siehe
    cmd_verify_dns/cmd_fetch in cli.py). Jede Warnung zählt, auch kleinere
    wie p=none oder pct<100 - nichts wird hier stillschweigend als "nicht
    schlimm genug" eingestuft. Ein SPF-Fehler (spf.error, z. B. DNS nicht
    erreichbar) zählt ebenfalls, auch ohne eigene Warnung in der Liste.
    MTA-STS/TLS-RPT-DNS/Wildcard-SPF sind optional - nur ein angefangenes,
    unvollständiges Setup zählt als Warnung, nicht das bloße Fehlen."""
    if result.dmarc.warnings:
        return True
    if result.spf.warnings or result.spf.error:
        return True
    if any(d.warnings for d in result.dkim):
        return True
    if result.mta_sts.warnings:
        return True
    if result.tlsrpt_dns.warnings:
        return True
    if result.wildcard_spf.warnings:
        return True
    return bool(result.mx_blacklist.warnings)
