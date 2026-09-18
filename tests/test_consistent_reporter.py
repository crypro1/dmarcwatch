"""is_consistent_reporter() - Metadaten-Konsistenzprüfung zwischen
report_metadata/org_name und der Absenderdomain der Report-Mail selbst.

Ausdrücklich KEINE Authentifizierung (siehe Docstring in report.py) - nur
ein Filter gegen Zero-Effort-Fälschungen. Die fünf Paare unten sind echte,
über `SELECT DISTINCT org_name, email FROM reports` aus einer produktiven
dmarcwatch-Datenbank gewonnene Reporter (Google, Amazon SES, Microsoft,
GMX, Mimecast) - Grundlage für die Allowlist-Entscheidung, nicht geraten.
"""
from dmarcwatch.report import DEFAULT_CONSISTENT_REPORTERS, is_consistent_reporter


# --- Die fünf echten Paare ---


def test_google_matches_via_exact_normalization():
    """org_name="google.com" enthält einen Punkt, die E-Mail-Domain auch -
    beide Seiten müssen normalisiert werden (Satzzeichen entfernt), sonst
    matcht der sonst triviale Exact-Match-Fall nicht."""
    assert is_consistent_reporter("google.com", "noreply-dmarc-support@google.com") is True


def test_amazon_ses_matches_via_generic_substring_rule():
    """org_name="AMAZON-SES" (Bindestrich, Großschreibung) gegen die Domain
    amazonses.com - kein Allowlist-Eintrag nötig, die generische Regel
    reicht bereits."""
    assert is_consistent_reporter("AMAZON-SES", "postmaster@amazonses.com") is True


def test_google_tls_rpt_org_name_matches_via_word_based_rule():
    """Echter, empirisch an realen TLS-RPT-Reports gefundener Fall:
    derselbe Anbieter meldet bei TLS-RPT einen ANDEREN org_name als bei
    DMARC ("Google Inc." statt "google.com") - als GANZE Zeichenkette kein
    Substring von "google.com" (normalisiert "googleinc" vs. "googlecom"),
    das Kernwort "google" aber schon. Ohne wortbasierten Abgleich wäre
    Google selbst auf der TLS-RPT-Seite fälschlich inkonsistent."""
    assert is_consistent_reporter("Google Inc.", "smtp-tls-reporting@google.com") is True


def test_microsoft_tls_rpt_org_name_matches_via_word_based_rule_without_allowlist():
    """Ebenfalls echt gefunden: TLS-RPT meldet "Microsoft Corporation",
    nicht "Enterprise Outlook" wie bei DMARC - braucht KEINEN eigenen
    Allowlist-Eintrag, weil "microsoft" als eigenständiges Wort bereits in
    "microsoft.com" vorkommt (anders als "Enterprise Outlook", das gar
    kein Wort mit Bezug zu "microsoft.com" enthält)."""
    assert is_consistent_reporter("Microsoft Corporation", "tlsrpt-noreply@microsoft.com") is True


def test_gmx_matches_via_generic_substring_rule():
    assert is_consistent_reporter("GMX", "noreply-dmarc@sicher.gmx.net") is True


def test_mimecast_matches_via_generic_substring_rule():
    """Mimecast braucht KEINEN Allowlist-Eintrag - "mimecast" ist bereits
    als Substring in "uk-1.mimecastreport.com" enthalten."""
    assert is_consistent_reporter("Mimecast", "no-reply@uk-1.mimecastreport.com") is True


def test_enterprise_outlook_needs_the_allowlist_entry():
    """Der eine echte Mismatch: "Enterprise Outlook" hat keinerlei
    textuellen Bezug zu "microsoft.com" - ohne den Allowlist-Eintrag würde
    der mit Abstand größte reale Reporter fälschlich als inkonsistent
    gelten."""
    assert is_consistent_reporter("Enterprise Outlook", "dmarcreport@microsoft.com") is True
    # Und die generische Regel allein (ohne Allowlist) würde das NICHT lösen:
    assert "enterpriseoutlook" not in "microsoft.com".replace(".", "")


def test_default_allowlist_has_exactly_the_one_needed_entry():
    """Nicht "Repair für alle fünf", sondern "Repair für den einen echten
    Mismatch" - Amazon/GMX/Mimecast/Google brauchen keinen Eintrag."""
    assert DEFAULT_CONSISTENT_REPORTERS == {"enterpriseoutlook": ("microsoft.com",)}


# --- Negativ-Kontrollen ---


def test_random_org_name_without_matching_domain_is_inconsistent():
    assert is_consistent_reporter("Definitely Not A Real Reporter", "spam@random-domain.example") is False


def test_missing_email_is_inconsistent_fail_closed():
    assert is_consistent_reporter("google.com", "") is False


def test_email_without_at_sign_is_inconsistent_fail_closed():
    assert is_consistent_reporter("google.com", "not-an-email") is False


def test_blank_org_name_is_inconsistent():
    assert is_consistent_reporter("", "noreply-dmarc-support@google.com") is False


# --- Dokumentierte Grenze: Identitäts-Kopie ---


def test_identity_copy_of_a_real_pair_is_reported_as_consistent():
    """Dokumentierte Grenze, kein Bug: is_consistent_reporter prüft NUR
    Metadaten-Konsistenz, keine Authentizität. Beide Felder (org_name UND
    email) stehen im selben, unauthentifizierten Report-XML - ein
    Angreifer, der bereits eine Mail an die rua-Adresse schicken kann,
    kopiert sich Googles echtes Paar 1:1 und kommt durch. Schließt erst
    eine künftige DKIM-Prüfung der Report-Mail selbst (Stage 2, nicht
    implementiert)."""
    assert is_consistent_reporter("google.com", "noreply-dmarc-support@google.com") is True


# --- Allowlist: Escalation, nicht Reparatur (Replace-Semantik) ---


def test_allowlist_entry_replaces_generic_rule_not_extends_it():
    """Ein allowlisteter org_name darf NICHT zusätzlich über die generische
    Substring-Regel durchkommen - sonst wäre der Allowlist-Eintrag keine
    Verschärfung, sondern ein zusätzliches, spoofbares Schlupfloch.
    org_name="mimecast" mit einer selbst kontrollierten Domain, die zufällig
    "mimecast" enthält, darf nur matchen, wenn "mimecast" NICHT allowlisted
    wäre (siehe test_mimecast_matches_via_generic_substring_rule oben, ohne
    Override) - hier wird ein künstlicher Override gesetzt, der die
    generische Regel für genau diesen org_name absichtlich unterläuft, um
    die Replace-Semantik zu belegen."""
    overrides = {"mimecast": ("mimecast.example",)}
    # Ohne Override würde die generische Substring-Regel "mimecast" in
    # "attacker-mimecast-evil.example" finden und True liefern.
    assert is_consistent_reporter("Mimecast", "x@attacker-mimecast-evil.example") is True
    # Mit dem (Test-)Override ERSETZT der Suffix-Check die generische Regel -
    # attacker-mimecast-evil.example endet nicht auf "mimecast.example".
    assert is_consistent_reporter("Mimecast", "x@attacker-mimecast-evil.example", overrides) is False
    # Eine tatsächlich zum Override passende Domain matcht weiterhin.
    assert is_consistent_reporter("Mimecast", "x@reports.mimecast.example", overrides) is True


def test_allowlist_suffix_match_respects_domain_boundary_not_bare_substring():
    """Kernkorrektur aus dem Review: der Allowlist-Check muss eine echte
    Zonen-Grenze prüfen (endswith "." + suffix oder exakt gleich), NICHT
    denselben zeichenketten-basierten Substring-Test wie die generische
    Regel - sonst würde "evilmicrosoft.com" (kein Microsoft-Server, aber
    "microsoftcom" als Bindestrich-freie Zeichenkette enthalten) fälschlich
    matchen und die per Allowlist beabsichtigte Verschärfung aushebeln."""
    assert is_consistent_reporter("Enterprise Outlook", "x@evilmicrosoft.com") is False
    assert is_consistent_reporter("Enterprise Outlook", "x@dmarcreport.microsoft.com") is True


def test_config_overrides_extend_default_allowlist():
    overrides = {"newlegitreporter": ("newreporter.example",)}
    assert is_consistent_reporter("NewLegitReporter", "x@reports.newreporter.example", overrides) is True
    assert is_consistent_reporter("NewLegitReporter", "x@totally-unrelated.example", overrides) is False
    # Default-Eintrag bleibt trotz zusätzlicher Overrides erhalten.
    assert is_consistent_reporter("Enterprise Outlook", "dmarcreport@microsoft.com", overrides) is True


def test_generic_rule_is_documented_as_spoofable_not_fixed():
    """Dokumentierte Grenze, kein Bug: die generische (nicht allowlistete)
    Regel prüft nur Zeichenketten-Enthaltung nach Normalisierung, keine
    echte Zonen-Grenze - ein Angreifer kann org_name="amazonses" mit einer
    selbst kontrollierten Domain wie "amazonses.evil.example" kombinieren.
    Structurell nur mit einer Public-Suffix-Liste zu schließen, was gegen
    die ohnehin dominierende Identitäts-Kopie (siehe oben) kein
    zusätzlicher Schutz wäre - deshalb bewusst nicht gebaut."""
    assert is_consistent_reporter("AMAZON-SES", "x@amazonses.evil.example") is True
