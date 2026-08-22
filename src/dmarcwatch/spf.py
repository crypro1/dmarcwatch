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
import subprocess

DIG_TIMEOUT_SECONDS = 5.0
MAX_DNS_LOOKUPS = 10


class SPFResolutionError(RuntimeError):
    pass


def _dig(record_type: str, name: str) -> list[str]:
    try:
        result = subprocess.run(
            ["dig", "+short", "+time=3", "+tries=1", record_type, name],
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


def _resolve(domain: str, budget: _LookupBudget, seen: set[str]) -> set[str]:
    domain = domain.strip().rstrip(".").lower()
    if not domain:
        return set()
    if domain in seen:
        raise SPFResolutionError(f"Zyklus in SPF-Includes entdeckt bei {domain!r}.")
    seen.add(domain)
    budget.spend(domain)

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
            networks |= _resolve(token[len("include:"):], budget, seen)
        elif low == "a" or low.startswith("a:"):
            target = token.split(":", 1)[1] if ":" in token else domain
            budget.spend(target)
            networks |= _resolve_host_to_networks(target)
        elif low == "mx" or low.startswith("mx:"):
            target = token.split(":", 1)[1] if ":" in token else domain
            budget.spend(target)
            for mx_line in _dig("MX", target):
                mx_parts = mx_line.split()
                if len(mx_parts) < 2:
                    continue
                mx_host = mx_parts[1].rstrip(".")
                budget.spend(mx_host)
                networks |= _resolve_host_to_networks(mx_host)
        elif low.startswith("redirect="):
            redirect_target = token[len("redirect="):]
        # Bewusst nicht behandelt: CIDR-Längen-Modifikatoren wie "a/24" oder
        # "mx/24" (selten), "ptr" (von RFC 7208 selbst als veraltet
        # markiert) und "exists:" (liefert keine IP-Menge, nur einen
        # Wahrheitswert) - werden übersprungen, nicht als Fehler behandelt.

    if redirect_target:
        networks |= _resolve(redirect_target, budget, seen)

    return networks


def resolve_own_ip_networks(domain: str) -> list[str]:
    """Löst den SPF-Eintrag von `domain` rekursiv auf (include:/redirect=/a/mx,
    RFC-7208-Lookup-Limit von 10) und gibt die gefundenen CIDR-Bereiche
    dedupliziert und sortiert zurück.

    Wirft SPFResolutionError bei fehlendem SPF-Eintrag, einem Zyklus in den
    Includes, oder zu vielen verschachtelten Lookups."""
    budget = _LookupBudget()
    raw_networks = _resolve(domain, budget, set())

    validated: list[str] = []
    for network in raw_networks:
        try:
            validated.append(str(ipaddress.ip_network(network, strict=False)))
        except ValueError:
            continue  # seltene/unparsebare Mechanismus-Syntax überspringen
    return sorted(validated)
