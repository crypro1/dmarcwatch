"""Spamhaus-ZEN-Abfrage (DNSBL) für eine einzelne IP-Adresse.

Rein informativ, wie whois.py - ändert NIE die Auffälligkeits-Einstufung
einer IP (own_ip_networks bleibt die einzige Quelle für "eigen" vs.
"unbekannt"). Nur auf explizite Anfrage über `dmarcwatch inspect
--blacklist` bzw. den MX-Server-Check in `verify-dns`, niemals automatisch
während `fetch`.

Bewusst nur Spamhaus ZEN, nicht die üblichen "großen sechs" (Barracuda,
SpamCop, UCEProtect, SpamRATS, PSBL, Invaluement): eine Whois-Prüfung der
jeweiligen Nameserver-IPs ergab, dass nur Spamhaus tatsächlich in der EU
gehostete Infrastruktur hat (u. a. ein Nameserver auf einem
Hetzner/Deutschland-Adressbereich) - die anderen fünf liegen alle in den
USA. Spamhaus gilt davon unabhängig ohnehin als die fachlich angesehenste
einzelne Liste. Invaluement erfordert zusätzlich einen bezahlten
Abfrage-Key und ist ohne Registrierung gar nicht frei abfragbar (leere
Antwort bei einem Test mit der Standard-Testadresse 127.0.0.2).
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from .spf import SPFResolutionError, _dig

DNSBL_ZONE = "zen.spamhaus.org"

# Offiziell von Spamhaus dokumentierte Bedeutung der zurückgegebenen
# 127.0.0.x-Antworten (https://www.spamhaus.org/zen/) - unbekannte Codes
# werden trotzdem angezeigt, nur ohne Klartext-Erklärung.
_RETURN_CODE_MEANINGS = {
    "127.0.0.2": "SBL - bekannte Spam-Quelle",
    "127.0.0.3": "SBL CSS - Spam-Quelle (Snowshoe-Spamming)",
    "127.0.0.4": "XBL/CBL - kompromittiert oder infiziert (z. B. Botnetz)",
    "127.0.0.9": "SBL DROP/EDROP - gekapertes oder böswillig genutztes Netz",
    "127.0.0.10": "PBL - Richtlinie: Endkunden-/Heimnetz, sollte nicht direkt senden",
    "127.0.0.11": "PBL - Richtlinie: von Spamhaus verwaltete Sperre für Direktversand",
}


class BlacklistCheckError(RuntimeError):
    pass


@dataclass
class BlacklistResult:
    ip: str
    listed: bool
    reasons: list[str] = field(default_factory=list)


def check_ip_blacklist(ip: str) -> BlacklistResult:
    """Fragt Spamhaus ZEN für eine einzelne IPv4-Adresse ab.

    IPv6 wird aktuell nicht unterstützt - eingehende Mail läuft in der
    Praxis fast ausschließlich über IPv4, und eine korrekte IPv6-Abfrage
    bräuchte ein eigenes, ungetestetes Nibble-Format statt der einfachen
    Oktett-Umkehrung hier.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError as exc:
        raise BlacklistCheckError(f"Ungültige IP-Adresse: {ip}") from exc
    if addr.version != 4:
        raise BlacklistCheckError("Blacklist-Prüfung unterstützt aktuell nur IPv4-Adressen.")

    reversed_ip = ".".join(reversed(ip.split(".")))
    try:
        records = _dig("A", f"{reversed_ip}.{DNSBL_ZONE}")
    except SPFResolutionError as exc:
        raise BlacklistCheckError(str(exc)) from exc

    reasons = [_RETURN_CODE_MEANINGS.get(code, f"Unbekannter Rückgabecode {code}") for code in records]
    return BlacklistResult(ip=ip, listed=bool(records), reasons=reasons)
