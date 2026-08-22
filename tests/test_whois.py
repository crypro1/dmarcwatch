"""RDAP-Lookup: rein informativ, siehe whois.py-Modul-Docstring. Tests
mocken das Netzwerk - ein automatisierter Testlauf darf nicht von einem
echten Drittanbieter-Dienst abhängen (Flakiness, Offline-Fähigkeit)."""
import json
from unittest.mock import MagicMock, patch

import pytest

from dmarcwatch.whois import WhoisLookupError, _extract_organization_name, lookup_ip_organization

# Vereinfachte, aber strukturell reale RDAP-Antwortform (ARIN-Stil).
ARIN_STYLE_RESPONSE = {
    "name": "GOOGLE",
    "entities": [
        {
            "roles": ["registrant"],
            "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Google LLC"]]],
        }
    ],
}

NO_ENTITIES_RESPONSE = {"name": "SOME-NETBLOCK"}

# Echte, vereinfachte RDAP-Struktur (RIPE-Stil) für 2a01:111:f403:c200::5 -
# entdeckt, weil die erste, naive Implementierung hier "Divya Quamara"
# (eine private Kontaktperson) statt "Microsoft Limited" zurückgab. Mehrere
# "registrant"-artige Entities gleichzeitig, eine davon ein reines
# Wartungsobjekt ("MICROSOFT-MAINT", kind=individual), eine ein
# administrativer Einzelkontakt (kind=individual) - nur das Entity mit
# vCard kind="org" ist tatsächlich die Organisation.
RIPE_STYLE_MICROSOFT_RESPONSE = {
    "name": "UK-MICROSOFT-20060601",
    "entities": [
        {
            "handle": "DH5439-RIPE",
            "roles": ["administrative"],
            "vcardArray": ["vcard", [["fn", {}, "text", "Divya Quamara"], ["kind", {}, "text", "individual"]]],
        },
        {
            "handle": "MICROSOFT-MAINT",
            "roles": ["registrant"],
            "vcardArray": ["vcard", [["fn", {}, "text", "MICROSOFT-MAINT"], ["kind", {}, "text", "individual"]]],
        },
        {
            "handle": "MRPA3-RIPE",
            "roles": ["technical"],
            "vcardArray": [
                "vcard",
                [["fn", {}, "text", "Microsoft Routing, Peering, and DNS"], ["kind", {}, "text", "group"]],
            ],
        },
        {
            "handle": "ORG-MA42-RIPE",
            "roles": ["registrant"],
            "vcardArray": ["vcard", [["fn", {}, "text", "Microsoft Limited"], ["kind", {}, "text", "org"]]],
        },
        {
            "handle": "RIPE-NCC-HM-MNT",
            "roles": ["registrant"],
            "vcardArray": ["vcard", [["fn", {}, "text", "RIPE-NCC-HM-MNT"], ["kind", {}, "text", "individual"]]],
        },
    ],
}


def test_extract_organization_prefers_registrant_fn():
    assert _extract_organization_name(ARIN_STYLE_RESPONSE) == "Google LLC"


def test_extract_organization_prefers_vcard_kind_org_over_individual_registrant():
    # Regressionstest für den realen Fund: nicht die erste passende Rolle
    # nehmen, sondern gezielt die Entity mit vCard kind="org".
    assert _extract_organization_name(RIPE_STYLE_MICROSOFT_RESPONSE) == "Microsoft Limited"


def test_extract_organization_falls_back_to_network_name():
    assert _extract_organization_name(NO_ENTITIES_RESPONSE) == "SOME-NETBLOCK"


def test_extract_organization_handles_malformed_entities_gracefully():
    malformed = {"name": "FALLBACK", "entities": [{"roles": ["registrant"]}, "not-a-dict", {}]}
    assert _extract_organization_name(malformed) == "FALLBACK"


def _mock_response(payload: dict):
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps(payload).encode("utf-8")
    mock_resp.__enter__.return_value = mock_resp
    mock_resp.__exit__.return_value = False
    return mock_resp


def test_lookup_ip_organization_success():
    with patch("urllib.request.urlopen", return_value=_mock_response(ARIN_STYLE_RESPONSE)):
        result = lookup_ip_organization("209.85.208.69")
    assert result == "Google LLC"


def test_lookup_ip_organization_wraps_network_errors():
    import urllib.error

    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("no route")):
        with pytest.raises(WhoisLookupError):
            lookup_ip_organization("203.0.113.1")


def test_lookup_ip_organization_wraps_malformed_json():
    mock_resp = MagicMock()
    mock_resp.read.return_value = b"not valid json{{{"
    mock_resp.__enter__.return_value = mock_resp
    mock_resp.__exit__.return_value = False
    with patch("urllib.request.urlopen", return_value=mock_resp):
        with pytest.raises(WhoisLookupError):
            lookup_ip_organization("203.0.113.1")
