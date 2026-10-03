# Changelog

Alle nennenswerten Änderungen an dmarcwatch werden hier festgehalten.
Format angelehnt an [Keep a Changelog](https://keepachangelog.com/de/1.0.0/),
Versionierung nach [Semantic Versioning](https://semver.org/lang/de/).

## [Unreleased]

### Hinzugefügt
- Auffällige Absender-Identitäten in `stats`/"Statistik…"
  (`compute_spoofed_identities`, [report.py](src/dmarcwatch/report.py)):
  `header_from` wurde zwar gespeichert und bei fremden Werten bereits als
  `foreign_header_from` markiert, aber nirgends ausgewertet. Die als
  gefälscht markierten Records werden jetzt nach `header_from` gruppiert -
  Anzahl E-Mails und Reports, erstes/letztes Auftreten und meldende
  Organisationen. So ist erkennbar, welche Identität gerade gefälscht
  wird und ob es ein Ausreißer oder eine laufende Kampagne ist. Wie alles in
  `stats` bezieht sich das auf das gewählte `--days`-Fenster ("zuerst am"
  heißt "zuerst im Zeitraum"); die Überschrift nennt den Zeitraum
  ausdrücklich. Neue Karte im Statistik-Fenster, Textblock in `stats`.
  Kein neues Schema, nur bereits gespeicherte Felder.
- `inspect <ip>`: bei mehreren verschiedenen `header_from`-Werten hinter den
  Treffern eine Übersicht "Header-From-Verteilung" vor der Detailliste.
- Wirkung der eigenen Policy: `stats` und die DMARC-Karte zeigen jetzt, wie
  viele E-Mails (echte Nachrichtenzahl, nicht Report-Zeilen) per
  `disposition=reject` abgewiesen wurden (`blocked_count` pro Tag).
  Zeilen mit fremdem `header_from` zählen nicht mit - ein "reject" dort kann
  nicht von der eigenen Policy stammen, und ein gefälschter Report könnte
  die Wirkung sonst mit einem hohen `count` aufblähen.
- Empfehlung, `sp` nachzuziehen (`sp_behind_recommendation`): steht eine
  Domain bereits bei `p=reject; pct=100`, aber `sp` explizit schwächer, galt
  sie bisher als "vollständig durchgesetzt", ohne dass die schwächere
  Subdomain-Policy je auffiel.

### Geändert
- Der orange Warntext bei `needs_recheck` ("Bereits bei p=reject, aber
  own_ip_auth_fail …") ist in normalem Deutsch formuliert und nennt, was
  passiert ist, warum es bei `p=reject` zählt, was zu prüfen ist und wann
  die Warnung verschwindet, ohne interne Feldnamen. Der Hinweis unter "Noch
  nicht bereit" nutzt dieselbe Formulierung.
- DKIM-Selektoren für `verify-dns` kommen nur noch aus Reports der letzten
  30 Tage und nur, wenn der Selektor mindestens einmal mit `pass` gemeldet
  wurde (Zeitfenster nach dem früheren von `date_end` und Abrufzeitpunkt, da
  `date_end` fälschbar ist). Ein nach einer Schlüsselrotation stillgelegter
  oder in einem gefälschten Report erfundener Selektor warnt damit nicht
  dauerhaft. Selektoren mit `*` oder ungültigem Namen werden verworfen, die
  Änderungserkennung führt den Stand je Selektor fort.
- `verify-dns <domain>` mit einer eigenen Domain aktualisiert nur deren
  Eintrag in der Menüleiste (Reihenfolge und Datum des Gesamtlaufs bleiben),
  mit einer fremden Domain bleibt der angezeigte Stand der eigenen Domains
  unverändert. Der automatische Check in `fetch` ist zusätzlich fällig, wenn
  eine eigene Domain im gespeicherten Stand fehlt. Die Änderungserkennung pro
  Domain läuft in jedem Fall weiter.
- Die DNS-Änderungserkennung vergleicht die effektive Durchsetzung (`p` und
  `sp` zusammen mit `pct`) statt nur einzelner Felder: der vom Tool selbst
  empfohlene Rollout-Schritt (z. B. `quarantine@100` → `reject@25`) löst
  keine Warnung mehr aus, ein echtes Zurückstufen weiterhin.
- Eine DKIM-Schlüsseländerung bei gleichem Selektor und gleichem Algorithmus
  wird von der Änderungserkennung jetzt gesehen (Schlüssel-Fingerabdruck
  statt nur `selektor:typ`).

### Sicherheit
- Alle `dig`-Aufrufe laufen über eine einzige Funktion
  ([spf.py](src/dmarcwatch/spf.py) `dig_command`), die den Namen als DNS-Namen
  validiert und per `-q` übergibt. Namen aus unauthentifizierten Quellen
  (SPF-Ziele, MX-Antworten fremder Zonen, DKIM-Selektoren aus Report-XML)
  können damit nie als `dig`-Option oder `@server` gelesen werden.
- Weitere aus Reports stammende Felder werden vor der Terminal-Ausgabe in
  `stats`/`inspect` bereinigt (`sanitize_field`), darunter `header_from`,
  meldende Organisationen, Domain, Policy-Werte und die WHOIS-Organisation;
  `current_sp` wurde in der JSON-Ausgabe bisher nicht bereinigt.
- Weitere unsichtbare/Bidi-Steuerzeichen (U+2060, U+180E, U+061C) werden
  entfernt.

### Behoben
- `fetch` bricht nicht mehr dauerhaft bei Nachrichten ab, die vor dem
  Markieren als verarbeitet scheitern würden: rohe 8-Bit-Bytes im `From`-Header
  (`mask_email` bekam ein `Header`-Objekt statt `str`), ZIP-Einträge mit
  ungültigem UTF-8 im Namen oder defekten LZMA-Daten, übergroße
  JSON-Ganzzahlen. Dieselbe Fehlerklasse wie schon der gzip-Fall in 1.2.0.
- Ein vorübergehender DNS-Fehler (SERVFAIL, Timeout) wird nicht mehr als "kein
  Eintrag" bzw. "DMARC-Policy entfernt" gewertet: das hätte einen falschen
  Alarm "Policy geschwächt" ausgelöst und den gespeicherten Vergleichsstand
  verfälscht. Gilt für DMARC, SPF, DKIM, MTA-STS, TLS-RPT, DANE und BIMI
  (Stand wird dann aus der letzten erfolgreichen Prüfung übernommen); ein
  leeres `dig +short`-Ergebnis wird per zweiter Abfrage auf SERVFAIL/REFUSED
  geprüft.
- "Policy geschwächt" erkennt jetzt ein explizit gesetztes schwächeres `sp`,
  auch wenn es vorher fehlte (erbt laut RFC 7489 von `p`), und meldet kein
  Zurückstufen, wenn ein redundantes `sp` einfach entfernt wird.
- Lesen und Schreiben des DNS-Schnappschusses sind eine einzige Transaktion
  (`BEGIN IMMEDIATE`): zwei gleichzeitige Prüfungen (geplanter Lauf und
  Klick) konnten sich sonst gegenseitig die erkannte Änderung überschreiben.
- Spamhaus-Rückgabecodes `127.255.255.x` (Abfrage über öffentlichen Resolver
  abgelehnt, zu viele Abfragen) gelten nicht mehr als Listing; sie wären sonst
  für jede IP gemeldet und im Cache gespeichert worden.
- SPF-Auflösung: eine Raute (A inkludiert B und C, beide D) ist kein Zyklus
  mehr, die Lookup-Zählung folgt RFC 7208 (die erste TXT-Abfrage zählt nicht,
  `mx` zählt als ein Lookup), Null-MX und `a:host/24`-Ziele werden korrekt
  behandelt, und ein CNAME in einer DNSBL-Antwort wird nicht mehr als
  Rückgabecode gelesen.
- `_detect_reporting_gap` erkennt auch dann eine lange Lücke, wenn es nur
  wenige Report-Tage mit ähnlich großen Lücken gibt (zusätzlicher absoluter
  Grenzwert von 75 Tagen).
- Die sp-bewusste Rollout-Empfehlung überspringt die 25-%-Stufe nur noch beim
  Schritt `quarantine` → `reject`, nie beim ersten Schritt von `p=none`.
- `setup` prüft die Konfiguration, bevor sie geschrieben wird (ein Tippfehler
  in `own_ip_networks` aus dem Einrichtungsfenster ließ sonst jeden Folgebefehl
  abstürzen); `consistent_reporter_overrides` werden wie `org_name`
  normalisiert und wirken damit auch in natürlicher Schreibweise.
- Kleinkram: `lstrip('⚠ ')` entfernte eine Zeichenmenge statt eines Präfixes;
  die Warnung "Policy geschwächt" erschien in der DNS-Prüfung doppelt.

## [1.3.0] - 2026-09-26

### Hinzugefügt
- sp-aware Rollout-Empfehlung für `stats`/"Statistik…"
  (`_next_dmarc_rollout_step`, [report.py](src/dmarcwatch/report.py)):
  `pct` ist laut RFC 7489 ein einziger, geteilter Wert für `p` **oder**
  `sp`, nie für beide getrennt. Stand bereits `sp` auf einer strengeren,
  vollständig durchgesetzten Stufe als `p` (z. B. `p=quarantine;
  sp=reject` ohne gesetztes `pct`), hätte die bisherige, naive erste
  Rollout-Stufe für `p` (`pct=25`) das bereits durchgesetzte `sp` mit
  zurückgestuft - genau das ist einer realen Domain in diesem Tool
  passiert. Die Empfehlung überspringt die 25%-Zwischenstufe jetzt in
  diesem Fall und schlägt direkt `pct=100` vor
  (`next_step_pct_adjusted_for_sp`, sichtbar in Terminal und
  Menüleisten-App).
- DNS-Änderungserkennung für `verify-dns`/"DNS prüfen…"
  (`diff_and_update_snapshot`, [dns_verify.py](src/dmarcwatch/dns_verify.py),
  neue `dns_snapshots`-Tabelle, Schema v5): jede Prüfung vergleicht die
  aktuellen DNS-Einträge jetzt zusätzlich gegen einen lokal gespeicherten
  Schnappschuss der letzten Prüfung derselben Domain - nicht nur, ob der
  aktuelle Zustand nach den bestehenden Regeln gut aussieht, sondern auch,
  ob sich seit dem letzten Mal überhaupt etwas geändert hat. Eine
  grüne/rote Pille pro Domain zeigt das auf einen Blick, darunter im
  Änderungsfall die genauen Felder (alter → neuer Wert). Eine
  zurückgestufte DMARC-Policy (`p` oder `sp` schwächer als beim letzten
  Mal, z. B. `reject` → `none`) bekommt eine eigene, lautere Warnung und
  löst beim automatischen periodischen Check (`enable_auto_dns_check`)
  eine eigene Notification aus, getrennt von der üblichen
  "DNS-Konfiguration auffällig"-Meldung - der durch die bestehenden
  Regeln allein unauffällige neue Zustand (`p=none` ist für sich
  genommen technisch gültig) wäre sonst nicht als Rückschritt erkennbar
  gewesen, egal ob durch einen Angriff, einen Tippfehler im
  Registrar-Panel oder Versehen verursacht.
- Versionsnummer in "Einstellungen…" (unten links, aus
  `CFBundleShortVersionString` gelesen statt fest verdrahtet).

### Behoben
Zehn Befunde aus einer gezielten Adversarial-Review, jeder mit einem
Regressionstest, der gegen den alten Code nachweislich fehlschlägt:
- `_extract_zip` ([archive.py](src/dmarcwatch/archive.py)) fing
  `zlib.error` bei einem gezielt beschädigten Deflate-Stream in einem
  Zip-Anhang nicht ab (anders als `_extract_gz` daneben) - ein
  entkommener Fehler hätte `fetch` bei jedem künftigen Lauf erneut zum
  Absturz gebracht, da die auslösende Nachricht nie als verarbeitet
  markiert wird.
- `policy_published/pct` ([parser.py](src/dmarcwatch/parser.py)) und
  drei TLS-RPT-Zählfelder ([tls_parser.py](src/dmarcwatch/tls_parser.py))
  wurden ohne Obergrenze geparst - ein Report mit einem absurd großen
  Wert ließ SQLite beim Einfügen mit `OverflowError` abstürzen, ebenfalls
  ein wiederkehrender Absturz-Loop aus einer einzigen präparierten Mail.
- `_search_unseen`/`_mark_processed` ([fetch.py](src/dmarcwatch/fetch.py))
  arbeiteten mit IMAP-Sequenznummern statt UIDs, kombiniert mit einem
  `expunge()` pro Nachricht - da EXPUNGE laut RFC 3501 alle höheren
  Sequenznummern verschiebt, konnten bei aktivem
  `move_to_processed_folder` und mehreren ungelesenen Nachrichten Reports
  übersprungen, doppelt verarbeitet oder ungelesen verworfen werden. Läuft
  jetzt durchgehend über stabile UIDs.
- `own_ip_fail_rows` ([report.py](src/dmarcwatch/report.py)) zählte
  jeden Record mit `disposition != none` als Auth-Fehlschlag, auch wenn
  DKIM und SPF beide bestanden hatten - eine unrelated
  Policy-Override-Begründung des Empfängers konnte so `needs_recheck`
  fälschlich dauerhaft auslösen.
- `_detect_reporting_gap` ([report.py](src/dmarcwatch/report.py)) konnte
  bei exakt drei unterschiedlichen Report-Tagen (zwei Lücken) eine
  Report-Lücke rechnerisch gar nicht mehr erkennen, weil der Ausreißer
  seine eigene Vergleichsbasis mit verzerrte - eine mehrmonatige Lücke
  wäre unbemerkt geblieben.
- `is_own_ip` ([config.py](src/dmarcwatch/config.py)) erkannte
  IPv4-mapped-IPv6-Adressen (`::ffff:203.0.113.5`) nicht als Mitglied
  einer IPv4-CIDR in `own_ip_networks` - ein echter eigener
  Auth-Fehlschlag von einem Dual-Stack-Sender konnte so unbemerkt am
  Sicherheitsnetz vorbeirutschen.
- `check_ip_blacklist` ([blacklist.py](src/dmarcwatch/blacklist.py))
  behandelte eine leere `dig +short`-Antwort immer als "nicht gelistet" -
  das ist von einem echten SERVFAIL (z. B. Spamhaus drosselt den
  abfragenden Resolver) nicht zu unterscheiden, ein gelisteter eigener
  Mailserver konnte so fälschlich als sauber gemeldet werden.
- `check_dmarc` ([dns_verify.py](src/dmarcwatch/dns_verify.py)) war als
  einzige Prüfung in dieser Datei nicht gegen einen DNS-Abfragefehler
  abgesichert - ein einzelner Timeout ließ `verify-dns` komplett
  abstürzen statt den Fehler als Warnung zu melden.
- `sanitize_field` ([sanitize.py](src/dmarcwatch/sanitize.py)) entfernte
  nur klassische Steuerzeichen, keine Unicode-Bidi-Override-Zeichen
  (z. B. U+202E) - ein präparierter `org_name` hätte sich in der
  Menüleisten-App optisch umsortieren/tarnen können, genau dort, wo
  Nutzer:innen beurteilen, welcher Absender auffällig ist.

## [1.2.0] - 2026-09-19

### Hinzugefügt
- Metadaten-Konsistenzprüfung für `stats`/"Statistik…"
  (`is_consistent_reporter`, [report.py](src/dmarcwatch/report.py)):
  `report_metadata/org_name` und `/email` (bzw. `contact_info` bei
  TLS-RPT) stehen beide im selben, unauthentifizierten Report - jeder
  kann eine Mail an die rua-Adresse schicken und damit z. B. einen
  fingierten `own_ip_auth_fail` einschleusen, der die "Tage seit dem
  letzten Fehlschlag"-Zählung beliebig oft zurücksetzt, oder mit einem
  hohen `count` Sendevolumen vortäuschen, um eine frühere Verschärfung
  nahezulegen. Nur Reports, deren `org_name` zur Absenderdomain der
  Report-Mail passt, fließen jetzt in `total_count`/`clean_days`/
  `avg_daily_volume`/`current_policy` ein - ausdrücklich KEINE
  Authentifizierung, nur ein Filter gegen Zero-Effort-Fälschungen.
  Ausgeschlossene Reports werden sichtbar gemacht
  (`excluded_count`/`excluded_reporters`), nicht stillschweigend
  verworfen. Neuer Config-Schlüssel `consistent_reporter_overrides` für
  Reporter, deren `org_name` nicht zu ihrer Mail-Domain passt (z. B.
  Microsofts "Enterprise Outlook"/"Microsoft Corporation").
- Partielle Auth-Fail-Erkennung: `own_ip_auth_fail` (Regel 2 in
  [anomaly.py](src/dmarcwatch/anomaly.py)) verlangt `dkim` UND `spf`
  fail - ein PARTIELLER Fail auf einer eigenen IP (nur einer von beiden,
  aber `disposition != none`, typisch bei einer rotierenden/kaputten
  DKIM-Selector-Konfiguration) blockiert jetzt ebenfalls die
  Verschärfungs-Empfehlung, statt unsichtbar zu bleiben.
- Neue Auffälligkeit `foreign_header_from`
  ([anomaly.py](src/dmarcwatch/anomaly.py)): `identifiers/header_from`
  eines Records, das weder zur im selben Report veröffentlichten Domain
  noch zu einer ihrer Subdomains gehört, wird jetzt markiert statt
  kommentarlos durchzulaufen.

### Behoben
- `_extract_gz` ([archive.py](src/dmarcwatch/archive.py)) fing nur
  `OSError` ab - ein abgeschnittener gzip-Stream wirft aber `EOFError`,
  ein bitweise beschädigter kann `zlib.error` werfen, beides kein
  `OSError`-Subtyp (empirisch geprüft). Ein entkommener Fehler hätte den
  kompletten `fetch`-Lauf abgebrochen, bevor die auslösende Nachricht als
  verarbeitet markiert wird - ein einzelner absichtlich abgeschnittener
  Anhang an die rua-Adresse hätte jeden künftigen Lauf erneut zum
  Absturz gebracht.
- Schema-Migrationen ([store.py](src/dmarcwatch/store.py) `_migrate`)
  waren durch `executescript()`s implizites Autocommit-Verhalten nicht
  atomar - ein Absturz mitten in einer Migration ließ Tabellen halb
  angelegt zurück, während `user_version` noch die alte Version zeigte;
  jeder künftige Start scheiterte dann an "table already exists"
  (dauerhafter Boot-Loop, empirisch nachgestellt). Jede Migration trägt
  jetzt ihr eigenes `BEGIN`/`PRAGMA user_version`/`COMMIT`. Zusätzlich
  ein Downgrade-Guard gegen eine Datenbank mit neuerer `user_version`
  als unterstützt.
- `config.json` und die Marker-Dateien wurden direkt in die Zieldatei
  geschrieben - ein Absturz mitten im Schreiben hätte eine leere/halb
  geschriebene `config.json` zurückgelassen und die App bis zum
  manuellen Eingriff unbrauchbar gemacht (`load_config()` fing
  `json.load()`-Fehler nicht ab). Jetzt atomares Schreiben über eine
  temporäre Datei plus `os.replace()`.
- `read_last_fetch_date` fing nur `OSError`, nicht `ValueError` (deckt
  u. a. `UnicodeDecodeError` ab) - eine binär-kaputte Markerdatei hätte
  `fetch` abstürzen statt gracefully degradieren lassen, anders als die
  strukturell identischen `read_skipped_items`/`read_dns_check_result`.
- Leere `own_domains` (z. B. vor dem ersten `setup`) ließen `fetch`
  ausnahmslos jeden Report als `REJECTED_FOREIGN_DOMAIN` verwerfen - ein
  technisch "erfolgreicher" Lauf, der die Datenbank für immer leer ließ,
  ohne dass das je auffiel. `cmd_fetch` bricht jetzt mit einer klaren
  Fehlermeldung ab, statt still zu "funktionieren".
- `is_own_domain` baute ihr Vergleichs-Set bei jedem Aufruf neu statt
  wie `is_own_ip` einmalig zu cachen - inkonsistent, jetzt einheitlich.

## [1.1.0] - 2026-08-30

### Hinzugefügt
- `dmarcwatch stats`/"Statistik…": deutlich intelligentere
  Verschärfungs-Einschätzung statt der bisherigen starren
  "keine einzige Zeile mit Fehlschlag im Fenster"-Regel:
  - Zeit seit dem JÜNGSTEN Fehlschlag statt "keiner irgendwo im
    gewählten Fenster" - ein einzelner alter Vorfall blockiert nicht
    mehr unbegrenzt, sobald seitdem genug Zeit und Sendevolumen
    vergangen sind.
  - Gestaffelter DMARC-Rollout in 25 %-Schritten (`p=none` →
    `quarantine` 25/50/75/100 → `reject` 25/50/75/100) statt eines
    einzigen Sprungs auf `p=reject; pct=100` - eine bereits bei
    `p=reject` stehende Domain mit `pct<100` gilt nicht mehr
    fälschlich als fertig.
  - Regression-Warnung (`needs_recheck`): eine bereits bei `p=reject`
    stehende Domain mit einem frischen `own_ip_auth_fail` wird jetzt
    explizit gemeldet statt stillschweigend als "erledigt" zu gelten.
  - Mindest-Stichprobengröße (10 echte Nachrichten/Sitzungen) zusätzlich
    zur Mindestbeobachtungsdauer - viele verstrichene Tage mit kaum
    echtem Volumen ergeben kein "bereit".
  - Sendevolumen wird aus einem jüngeren, rollierenden 30-Tage-Fenster
    berechnet statt aus der gesamten Historie - eine frühere, ruhigere
    Phase verzerrt nicht mehr die nötige Wartezeit für eine inzwischen
    deutlich aktivere Domain.
  - Erkennung auffällig großer Lücken zwischen Tagen mit Reports
    (relativ zur sonst üblichen Lücke dieser Domain) - blockiert die
    Bereitschaft zusätzlich, da eine Lücke genauso gut ein
    zwischenzeitlich ausgefallener `fetch` sein kann wie echte Stille.
  - TLS-RPT-Fehlschläge werden zusätzlich nach RFC-8460-Ergebnistyp
    aufgeschlüsselt, gewichtet mit echten fehlgeschlagenen Sitzungen.
  - Ein expliziter Hinweis in jeder Ausgabe, dass DMARC-/TLS-RPT-
    Reporting branchenweit lückenhaft ist - "0 Fehlschläge" war nie
    eine Garantie, das steht jetzt auch so da.
  - Zählungen (Gesamtzahl, Fehlschläge, Sendevolumen) basieren jetzt auf
    den echten `count`-Werten der Reports statt auf der Anzahl der
    Report-Zeilen.

### Behoben
- MTA-STS-Bereitschaft wurde über alle konfigurierten Domains hinweg zu
  einer einzigen Einschätzung zusammengefasst statt (wie bei DMARC) pro
  Domain berechnet - bei mehreren Domains mit TLS-RPT hätte eine
  Domain die Einschätzung der anderen verfälscht. Läuft jetzt wie
  DMARC unabhängig pro Domain.

## [1.0.1] - 2026-08-30

### Behoben
- `dmarcwatch stats`/"Statistik…": die für die Verschärfungs-Einschätzung
  nötige Mindestbeobachtungsdauer (`observed_days`) wurde bisher direkt
  aus dem angefragten `--days`-Wert übernommen statt aus dem tatsächlichen
  Alter des ältesten Reports im Fenster - `stats --days 90` konnte dadurch
  fälschlich "90 Tage beobachtet" anzeigen, obwohl eine Domain real erst
  seit deutlich kürzerer Zeit überhaupt Reports lieferte, und so eine
  Verschärfung als sicher ausweisen, ohne dass zusätzliche Zeit vergangen
  oder zusätzliche Daten hinzugekommen wären. `observed_days` (und darauf
  aufbauend `avg_daily_volume`) wird jetzt aus der tatsächlichen
  Reporthistorie berechnet.

## [1.0.0] - 2026-08-29

Erster versionierter Release. Bündelt die gesamte bisherige Entwicklung
(siehe `git log` für die vollständige Historie) sowie zuletzt:

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
- "DNS-Prüfung…"- und "Statistik…"-Fenster vergrößert, damit die
  erweiterten Inhalte (DNSSEC/DANE/BIMI bzw. Tagestrend/Verschärfung)
  ohne Scrollen passen.

## Davor

Die Entwicklung vor 1.0.0 wurde nicht einzeln versioniert - siehe
`git log` für den vollständigen Verlauf ab dem Initial-Commit.
