"""RDAP-Lookup (WHOIS-Nachfolger) für IP-Adressen.

Rein informativ - ändert NIE die Auffälligkeits-Einstufung einer IP
(own_ip_networks bleibt die einzige Quelle für "eigen" vs. "unbekannt",
siehe anomaly.py). Ein WHOIS-Treffer wie "Google LLC" oder "Microsoft
Corporation" ist kein Sicherheitsnachweis: dieselben Konzerne betreiben
riesige Cloud-Bereiche (Azure, GCP), die sich jeder mieten kann - ein
Angreifer, der gezielt spoofen will, könnte genau dort landen. Das hier
liefert einen Hinweis für die eigene Einschätzung, keine Entscheidung.

Nur auf explizite Anfrage über `dmarcwatch inspect --whois`, niemals
automatisch während `fetch` - der tägliche Hintergrundlauf verbindet sich
weiterhin ausschließlich zum konfigurierten IMAP-Host.
"""
from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request

_TIMEOUT_SECONDS = 5.0


class WhoisLookupError(RuntimeError):
    pass


def lookup_ip_organization(ip: str, timeout: float = _TIMEOUT_SECONDS) -> str | None:
    """Fragt die Organisation hinter einer IP per RDAP ab.

    Nutzt den IANA-Bootstrap-Dienst (rdap.org), der automatisch zur
    zuständigen Regional Internet Registry (ARIN/RIPE/APNIC/...)
    weiterleitet - eine einzelne, einheitliche Abfrage statt eigener
    Zuständigkeits-Logik pro Registry.
    """
    url = f"https://rdap.org/ip/{ip}"
    context = ssl.create_default_context()
    request = urllib.request.Request(url, headers={"Accept": "application/rdap+json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            raw = response.read()
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise WhoisLookupError(f"RDAP-Abfrage für {ip} fehlgeschlagen: {exc}") from exc

    try:
        data = json.loads(raw.decode("utf-8", errors="replace"))
    except ValueError as exc:
        raise WhoisLookupError(f"RDAP-Antwort für {ip} konnte nicht gelesen werden: {exc}") from exc

    if not isinstance(data, dict):
        return None
    return _extract_organization_name(data)


def _vcard_field(vcard_array, field_name: str) -> str | None:
    """Extrahiert ein Feld (z. B. 'fn' oder 'kind') aus einem jCard-Array."""
    if not isinstance(vcard_array, list) or len(vcard_array) < 2:
        return None
    fields = vcard_array[1]
    if not isinstance(fields, list):
        return None
    for field in fields:
        if isinstance(field, list) and len(field) >= 4 and field[0] == field_name:
            return str(field[3])
    return None


def _extract_organization_name(data: dict) -> str | None:
    """Sucht den plausibelsten Organisationsnamen in einer RDAP-Antwort.

    Registries (v. a. RIPE) liefern oft mehrere "registrant"-Entities
    gleichzeitig - darunter technische Maintainer-Objekte (z. B.
    "MICROSOFT-MAINT") und sogar einzelne Kontaktpersonen mit
    role=administrative (z. B. "Divya Quamara" für eine Microsoft-Range).
    Deren Rolle allein reicht nicht, um die tatsächliche Organisation zu
    finden - das vCard-Feld "kind" tut das zuverlässig: "org" markiert laut
    RFC 6350 explizit eine Organisation, "individual"/"group" eine Person
    bzw. Gruppe. Deshalb zuerst gezielt danach suchen, erst danach auf
    Rollen-Heuristiken zurückfallen (für Registries wie ARIN, die "kind"
    nicht immer setzen).
    """
    entities = data.get("entities")
    if isinstance(entities, list):
        dict_entities = [e for e in entities if isinstance(e, dict)]

        # 1. Eindeutigstes Signal: vCard kind == "org", unabhängig von der Rolle.
        for entity in dict_entities:
            if _vcard_field(entity.get("vcardArray"), "kind") == "org":
                name = _vcard_field(entity.get("vcardArray"), "fn")
                if name:
                    return name

        # 2. registrant, aber explizit keine Einzelperson (deckt Registries
        #    ohne "kind"-Feld ab, z. B. viele ARIN-Antworten).
        for entity in dict_entities:
            roles = entity.get("roles") or []
            if "registrant" not in roles:
                continue
            if _vcard_field(entity.get("vcardArray"), "kind") == "individual":
                continue
            name = _vcard_field(entity.get("vcardArray"), "fn")
            if name:
                return name

        # 3. registrant notfalls auch als Einzelperson/Maintainer-Objekt.
        for entity in dict_entities:
            if "registrant" in (entity.get("roles") or []):
                name = _vcard_field(entity.get("vcardArray"), "fn")
                if name:
                    return name

        # 4. administrative als letzter, am wenigsten aussagekräftiger Fallback.
        for entity in dict_entities:
            if "administrative" in (entity.get("roles") or []):
                name = _vcard_field(entity.get("vcardArray"), "fn")
                if name:
                    return name

        # 5. irgendein Name, egal welche Rolle.
        for entity in dict_entities:
            name = _vcard_field(entity.get("vcardArray"), "fn")
            if name:
                return name

    name = data.get("name")
    return str(name) if name else None
