# Changelog

Alle nennenswerten Änderungen an dmarcwatch werden hier festgehalten.
Format angelehnt an [Keep a Changelog](https://keepachangelog.com/de/1.0.0/),
Versionierung nach [Semantic Versioning](https://semver.org/lang/de/).

## [0.9.0] - 2026-08-29

Erster versionierter Stand vor dem geplanten 1.0-Release. Bündelt die
gesamte bisherige Entwicklung (siehe `git log` für die vollständige
Historie) sowie zuletzt:

### Hinzugefügt
- DNSSEC-Prüfung (`dig +dnssec` gegen einen validierenden Resolver) und
  DANE/TLSA-Prüfung als Teil der DNS-Verifizierung, inklusive Status-Pille
  in der "DNS-Prüfung…"-Ansicht der Menüleisten-App.
- BIMI-Prüfung: liest den BIMI-DNS-Eintrag, holt das referenzierte
  SVG-Logo per HTTPS und validiert es gegen die BIMI-SVG-Tiny-PS-Vorgaben
  (`baseProfile`/`version`, Pflicht-`<title>`, verbotene Elemente wie
  `<script>`/`<animate*>`, keine externen Referenzen, quadratisches Format,
  32-KB-Grenze). Das Logo wird bei erfolgreicher Prüfung direkt in der
  Menüleisten-App angezeigt.
- Neuer Befehl `dmarcwatch stats [--days N] [--json]` sowie "Statistik…"
  in der Menüleisten-App: Tagestrend (DMARC sauber/auffällig, TLS-RPT
  Fehlschläge) als Liniendiagramm mit Legende, Ring-Überblicke für DMARC
  und TLS-RPT, und eine Einschätzung, ob eine Verschärfung von DMARC
  (Richtung `p=reject`) bzw. MTA-STS (Richtung `mode=enforce`) im
  gewählten Zeitraum sicher gewesen wäre.
- Die Verschärfungs-Einschätzung berücksichtigt eine nach Sendevolumen
  gestaffelte Mindestbeobachtungsdauer (unter 1 Eintrag/Sitzung pro Tag im
  Schnitt: 60 Tage, 1 bis unter 5 pro Tag: 30 Tage, ab 5 pro Tag: 14 Tage)
  statt eines starren Zeitraums für alle Domains - bei sehr wenig Volumen
  reicht ein kurzer Beobachtungszeitraum sonst nicht aus, um sicher zu
  sein, dass seltene, aber legitime Absender im Fenster überhaupt schon
  aufgetaucht wären.

### Geändert
- Minimale macOS-Version für die Menüleisten-App auf macOS 14 (Sonoma)
  angehoben (erforderlich für Swift Charts' `SectorMark`).

## Davor

Die Entwicklung vor 0.9.0 wurde nicht einzeln versioniert - siehe
`git log` für den vollständigen Verlauf ab dem Initial-Commit.
