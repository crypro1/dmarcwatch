"""SPF-Auflösung für "Aus SPF ermitteln" im Setup-Fenster der Menüleisten-App.

Löst den SPF-DNS-Eintrag einer Domain auf (inkl. include:/redirect=/a/mx)
und gibt die resultierenden CIDR-Bereiche zurück - ein Vorschlag für
own_ip_networks, kein automatischer, unbeaufsichtigter Eintrag: die GUI
zeigt das Ergebnis nur zur Bestätigung/Bearbeitung an, bevor gespeichert
wird (siehe SetupView.swift/SetupViewModel.swift), und fragt vorher per
Dialog nach - genau wie beim WHOIS-Lookup ist das die einzige Stelle, an
der ein Klick tatsächlich nach außen geht (hier: DNS statt HTTP).

Nutzt `dig` per subprocess statt einer neuen Abhängigkeit (z. B.
dnspython) - konsistent mit dem Rest des Projekts (osascript, launchctl),
keine zusätzliche Drittanbieter-Bibliothek nur für DNS-Lookups.

RFC 7208 begrenzt SPF-Auswertung auf maximal 10 DNS-"lookups" für
include/a/mx/ptr/exists/redirect-Mechanismen - dieselbe Grenze wird hier
durchgesetzt, sowohl gegen kaputte als auch gegen böswillig verschachtelte
Records (inklusive echter Zyklen wie "A inkludiert B inkludiert A").
"""
from __future__ import annotations

import ipaddress
import re
import subprocess
from dataclasses import dataclass, field

DIG_TIMEOUT_SECONDS = 5.0
MAX_DNS_LOOKUPS = 10


class SPFResolutionError(RuntimeError):
    pass


# Syntaktisch gültiger DNS-Name (Labels aus Buchstaben, Ziffern, "_" und
# "-", Label beginnt nie mit "-"), optional mit abschließendem Punkt. Die
# abgefragten Namen stammen teils aus unauthentifizierten Quellen (SPF-
# include/redirect/a/mx-Ziele und MX-Antworten aus fremden DNS-Zonen,
# DKIM-Selektoren aus Report-XML) - ein Wert wie "+tcp", "-f/etc/x" oder
# "@server" würde von dig sonst als Option bzw. Server-Angabe gelesen.
_DNS_NAME_RE = re.compile(
    r"(?=.{1,253}\.?$)[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,62})?"
    r"(?:\.[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,62})?)*\.?"
)


def is_valid_dns_name(name: str) -> bool:
    return bool(_DNS_NAME_RE.fullmatch(name))


def dig_command(record_type: str, name: str, *options: str) -> list[str]:
    """Baut die dig-Argumentliste für alle dig-Aufrufe im Projekt.

    Doppelt abgesichert: der Name wird vorher als DNS-Name validiert
    (SPFResolutionError sonst), und er wird per `-q` übergeben, damit dig
    ihn auch dann ausschließlich als Abfragenamen liest, sollte die
    Validierung je etwas durchlassen, das mit "+", "-" oder "@" beginnt.
    `options` kommen nur aus festen Literalen im Code, nie aus Daten."""
    if not is_valid_dns_name(name):
        raise SPFResolutionError(f"Ungültiger DNS-Name, Abfrage verweigert: {name!r}")
    return ["dig", *options, "-t", record_type, "-q", name]


def _dig(record_type: str, name: str) -> list[str]:
    try:
        result = subprocess.run(
            dig_command(record_type, name, "+short", "+time=3", "+tries=1"),
            capture_output=True,
            text=True,
            timeout=DIG_TIMEOUT_SECONDS,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        raise SPFResolutionError(f"DNS-Abfrage fehlgeschlagen ({record_type} {name}): {exc}") from exc
    if result.returncode != 0:
        detail = result.stderr.strip() or f"dig beendete sich mit Code {result.returncode}"
        raise SPFResolutionError(f"DNS-Abfrage fehlgeschlagen ({record_type} {name}): {detail}")
    return [line for line in result.stdout.splitlines() if line.strip()]


def _dig_full(record_type: str, name: str) -> str:
    """Volle dig-Ausgabe (ohne `+short`, inklusive Header mit Antwortstatus)."""
    try:
        result = subprocess.run(
            dig_command(record_type, name, "+time=3", "+tries=1"),
            capture_output=True,
            text=True,
            timeout=DIG_TIMEOUT_SECONDS,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        raise SPFResolutionError(f"DNS-Abfrage fehlgeschlagen ({record_type} {name}): {exc}") from exc
    if result.returncode != 0:
        detail = result.stderr.strip() or f"dig beendete sich mit Code {result.returncode}"
        raise SPFResolutionError(f"DNS-Abfrage fehlgeschlagen ({record_type} {name}): {detail}")
    return result.stdout


def _response_status(dig_stdout: str) -> str | None:
    """Antwortstatus (NOERROR, NXDOMAIN, SERVFAIL, ...) aus der Header-Zeile
    einer vollen dig-Ausgabe, None wenn keine Header-Zeile vorhanden ist."""
    for line in dig_stdout.splitlines():
        if line.startswith(";; ->>HEADER<<-") and "status:" in line:
            return line.split("status:", 1)[1].split(",", 1)[0].strip()
    return None


def _raise_on_resolution_failure(record_type: str, name: str) -> None:
    """Für einen LEEREN `dig +short`-Befund: prüft per zweiter, voller
    Abfrage, ob das wirklich "kein Eintrag" (NOERROR/NXDOMAIN) war oder ein
    Auflösungsfehler (SERVFAIL, REFUSED, ...) - siehe _dig_checked(), warum
    `+short` beides nicht unterscheidet. Ohne diese Prüfung sähe z. B. ein
    vorübergehender SERVFAIL beim DMARC-Lookup genauso aus wie ein echtes
    Entfernen des Eintrags (falscher "DMARC-Policy geschwächt"-Alarm und eine
    verfälschte Baseline in dns_verify.diff_and_update_snapshot()).

    Wirft SPFResolutionError bei einem Status außer NOERROR/NXDOMAIN; eine
    Ausgabe ohne Header-Zeile gilt nicht als Fehler."""
    status = _response_status(_dig_full(record_type, name))
    if status is not None and status not in ("NOERROR", "NXDOMAIN"):
        raise SPFResolutionError(f"DNS-Abfrage fehlgeschlagen ({record_type} {name}): Status {status}")


def _dig_checked(record_type: str, name: str) -> list[str]:
    """Wie _dig(), aber ohne `+short` und mit Prüfung des DNS-Antwortstatus:
    `dig +short` liefert sowohl bei einer echten leeren Antwort (NXDOMAIN)
    als auch bei einem Auflösungsfehler (z. B. SERVFAIL, etwa wenn Spamhaus
    einen gemeinsam genutzten/öffentlichen Resolver drosselt) gleichermaßen
    leeres stdout mit Exit-Code 0 - für Aufrufer, die das unterscheiden
    müssen (siehe check_ip_blacklist() in blacklist.py), reicht der
    Exit-Code allein nicht.

    Wirft SPFResolutionError bei jedem Status außer NOERROR/NXDOMAIN."""
    stdout = _dig_full(record_type, name)

    status = _response_status(stdout) or "SERVFAIL"
    answers: list[str] = []
    in_answer_section = False
    for line in stdout.splitlines():
        if line.startswith(";; ANSWER SECTION:"):
            in_answer_section = True
        elif in_answer_section:
            if not line.strip() or line.startswith(";;"):
                in_answer_section = False
            else:
                fields = line.split()
                if len(fields) >= 5 and fields[3] == "A":
                    answers.append(fields[-1])

    if status not in ("NOERROR", "NXDOMAIN"):
        raise SPFResolutionError(f"DNS-Abfrage fehlgeschlagen ({record_type} {name}): Status {status}")
    return answers


def _txt_records(domain: str) -> list[str]:
    records = []
    for line in _dig("TXT", domain):
        # dig gibt jedes Character-String eines TXT-Eintrags in
        # Anführungszeichen aus, mehrere direkt hintereinander, falls der
        # Text über 255 Byte lang war (`"teil1" "teil2"`) - zusammenfügen.
        parts = line.split('"')
        content = "".join(parts[i] for i in range(1, len(parts), 2))
        if content:
            records.append(content)
    if not records:
        _raise_on_resolution_failure("TXT", domain)
    return records


def _find_spf_record(domain: str) -> str | None:
    for record in _txt_records(domain):
        if record.lower().startswith("v=spf1"):
            return record
    return None


def _resolve_host_to_networks(hostname: str) -> set[str]:
    networks: set[str] = set()
    for ip in _dig("A", hostname):
        networks.add(f"{ip.strip()}/32")
    for ip in _dig("AAAA", hostname):
        networks.add(f"{ip.strip()}/128")
    return networks


class _LookupBudget:
    """Setzt das RFC-7208-Limit von 10 DNS-Lookups durch - Schutz gegen
    kaputte oder böswillig tief verschachtelte SPF-Ketten."""

    def __init__(self, limit: int = MAX_DNS_LOOKUPS) -> None:
        self._limit = limit
        self._used = 0

    def spend(self, context: str) -> None:
        self._used += 1
        if self._used > self._limit:
            raise SPFResolutionError(
                f"Zu viele verschachtelte SPF-Lookups (> {self._limit}) - Abfrage bei "
                f"{context!r} abgebrochen (RFC-7208-Limit)."
            )

    @property
    def used(self) -> int:
        return self._used


def _resolve(domain: str, budget: _LookupBudget, path: set[str], count_lookup: bool = True) -> set[str]:
    """path enthält nur die Domains auf dem AKTUELLEN Rekursionspfad (wird
    beim Verlassen wieder entfernt), nicht jede je besuchte Domain - eine
    Raute (A inkludiert B und C, beide inkludieren D) ist laut RFC 7208
    erlaubt und kein Zyklus; nur ein echter Rückbezug auf eine Domain weiter
    oben im selben Pfad (A -> B -> A) ist einer. Der Gesamtaufwand bleibt
    unabhängig davon durch das Lookup-Budget begrenzt.

    count_lookup=False nur für den Einstiegsaufruf: die TXT-Abfrage des
    eigenen Eintrags zählt laut RFC 7208 4.6.4 nicht zum Limit von 10, nur
    include/a/mx/ptr/exists/redirect tun das."""
    domain = domain.strip().rstrip(".").lower()
    if not domain:
        return set()
    if domain in path:
        raise SPFResolutionError(f"Zyklus in SPF-Includes entdeckt bei {domain!r}.")
    if count_lookup:
        budget.spend(domain)
    path.add(domain)
    try:
        record = _find_spf_record(domain)
        if record is None:
            raise SPFResolutionError(f"Kein SPF-Eintrag (v=spf1) für {domain!r} gefunden.")

        networks: set[str] = set()
        redirect_target: str | None = None

        for token in record.split():
            low = token.lower()
            if low.startswith("ip4:"):
                value = token[len("ip4:"):]
                networks.add(value if "/" in value else f"{value}/32")
            elif low.startswith("ip6:"):
                value = token[len("ip6:"):]
                networks.add(value if "/" in value else f"{value}/128")
            elif low.startswith("include:"):
                networks |= _resolve(token[len("include:"):], budget, path)
            elif low == "a" or low.startswith("a:"):
                target = token.split(":", 1)[1] if ":" in token else domain
                budget.spend(target)
                networks |= _resolve_host_to_networks(target)
            elif low == "mx" or low.startswith("mx:"):
                target = token.split(":", 1)[1] if ":" in token else domain
                # Der mx-Mechanismus zählt als EIN Lookup - die
                # Adressabfragen der einzelnen MX-Hosts zählen laut RFC 7208
                # 4.6.4 nicht zum Gesamtlimit, haben aber ein eigenes Limit
                # von 10 pro mx-Mechanismus.
                budget.spend(target)
                mx_hosts = []
                for mx_line in _dig("MX", target):
                    mx_parts = mx_line.split()
                    if len(mx_parts) < 2:
                        continue
                    mx_hosts.append(mx_parts[1].rstrip("."))
                if len(mx_hosts) > MAX_DNS_LOOKUPS:
                    raise SPFResolutionError(
                        f"'mx' für {target!r} liefert {len(mx_hosts)} MX-Hosts, mehr als die "
                        f"von RFC 7208 erlaubten {MAX_DNS_LOOKUPS} Adressabfragen."
                    )
                for mx_host in mx_hosts:
                    networks |= _resolve_host_to_networks(mx_host)
            elif low.startswith("redirect="):
                redirect_target = token[len("redirect="):]
            # Bewusst nicht behandelt: CIDR-Längen-Modifikatoren wie "a/24" oder
            # "mx/24" (selten), "ptr" (von RFC 7208 selbst als veraltet
            # markiert) und "exists:" (liefert keine IP-Menge, nur einen
            # Wahrheitswert) - werden übersprungen, nicht als Fehler behandelt.

        if redirect_target:
            networks |= _resolve(redirect_target, budget, path)

        return networks
    finally:
        path.discard(domain)


def resolve_own_ip_networks(domain: str) -> list[str]:
    """Löst den SPF-Eintrag von `domain` rekursiv auf (include:/redirect=/a/mx,
    RFC-7208-Lookup-Limit von 10) und gibt die gefundenen CIDR-Bereiche
    dedupliziert und sortiert zurück.

    Wirft SPFResolutionError bei fehlendem SPF-Eintrag, einem Zyklus in den
    Includes, oder zu vielen verschachtelten Lookups."""
    budget = _LookupBudget()
    raw_networks = _resolve(domain, budget, set(), count_lookup=False)

    validated: list[str] = []
    for network in raw_networks:
        try:
            validated.append(str(ipaddress.ip_network(network, strict=False)))
        except ValueError:
            continue  # seltene/unparsebare Mechanismus-Syntax überspringen
    return sorted(validated)


@dataclass
class SPFCheckResult:
    """Ergebnis von validate_spf() für `dmarcwatch verify-dns`
    (dns_verify.py) - ein Diagnosebericht, keine Exception bei Problemen:
    das Ziel ist, Fehlkonfigurationen aufzulisten, nicht abzubrechen."""

    exists: bool
    record: str | None = None
    lookup_count: int = 0
    lookup_limit_ok: bool = True
    warnings: list[str] = field(default_factory=list)
    error: str | None = None


def validate_spf(domain: str) -> SPFCheckResult:
    """Prüft den SPF-Eintrag von `domain` auf Gültigkeit und häufige
    Fehlkonfigurationen: mehrere SPF-Einträge (laut RFC 7208 ein PermError -
    es darf nur genau einer sein), fehlender oder zu offener
    `all`-Mechanismus, und die tatsächliche Anzahl verbrauchter
    DNS-Lookups gegenüber dem RFC-7208-Limit von 10."""
    try:
        top_level_records = [r for r in _txt_records(domain) if r.lower().startswith("v=spf1")]
    except SPFResolutionError as exc:
        return SPFCheckResult(exists=False, error=str(exc))

    if not top_level_records:
        return SPFCheckResult(exists=False, warnings=["Kein SPF-Eintrag (v=spf1) gefunden."])

    warnings: list[str] = []
    if len(top_level_records) > 1:
        warnings.append(
            f"{len(top_level_records)} SPF-Einträge gefunden - laut RFC 7208 ungültig "
            "(PermError), es darf nur genau einer sein."
        )

    record = top_level_records[0]
    tokens = record.split()
    all_mechanism = next((t for t in tokens if t.lower().lstrip("+-~?") == "all"), None)
    if all_mechanism is None:
        warnings.append(
            "Kein 'all'-Mechanismus am Ende - uneindeutiges Verhalten für nicht "
            "explizit genannte Absender."
        )
    elif all_mechanism.lower() in ("all", "+all"):
        warnings.append(
            "'+all' (bzw. unqualifiziertes 'all') erlaubt praktisch jedem Server, im "
            "Namen dieser Domain zu senden - macht SPF wirkungslos."
        )

    budget = _LookupBudget()
    lookup_limit_ok = True
    try:
        _resolve(domain, budget, set(), count_lookup=False)
    except SPFResolutionError as exc:
        lookup_limit_ok = False
        warnings.append(str(exc))

    return SPFCheckResult(
        exists=True,
        record=record,
        lookup_count=budget.used,
        lookup_limit_ok=lookup_limit_ok,
        warnings=warnings,
    )
