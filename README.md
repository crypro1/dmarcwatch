# dmarcwatch

Lokaler DMARC-Monitor für macOS. Holt DMARC-Aggregate-Reports per IMAP von
mailbox.org ab, wertet sie aus, speichert sie in einer lokalen SQLite-
Datenbank und zeigt Auffälligkeiten in einer nativen Menüleisten-App
(Swift/AppKit) an. Alternativ auch über SwiftBar nutzbar. Optional
(`enable_tls_rpt`) wertet dmarcwatch zusätzlich SMTP-TLS-RPT-Reports
(RFC 8460) aus einem separaten IMAP-Ordner aus.

Keine Cloud, kein Konto, kein Dritter. Der einzige Netzwerkverkehr, den
dmarcwatch erzeugt, ist die IMAP-Verbindung zum konfigurierten Host (plus,
nur auf ausdrücklichen Klick/Flag hin, eine einzelne WHOIS-Abfrage - siehe
[Sicherheitsentscheidungen](#sicherheitsentscheidungen)).

## Inhalt

- [Voraussetzungen](#voraussetzungen)
- [Installation](#installation-unter-10-minuten)
  - [Python-CLI](#python-cli)
  - [Native Menüleisten-App](#native-menüleisten-app)
- [Konfiguration](#konfiguration)
- [Befehle](#befehle)
- [launchd](#launchd)
- [Deinstallation](#deinstallation)
- [Tests](#tests)
- [Sicherheitsentscheidungen](#sicherheitsentscheidungen)
- [Nicht-Ziele](#nicht-ziele)

## Voraussetzungen

- macOS (Apple Silicon)
- Python 3.10 oder neuer - das von Apple mitgelieferte System-Python unter
  `/usr/bin/python3` reicht dafür meist nicht (oft noch 3.9), Homebrew-Python
  (`brew install python@3.13`) funktioniert
- Ein IMAP-Postfach, in dem DMARC-Aggregate-Reports bereits per Filterregel
  landen (hier: mailbox.org, Ordner `DMARC`)
- Ein **anwendungsspezifisches Passwort** für dieses Postfach (nicht das
  Hauptpasswort) - bei mailbox.org unter *Einstellungen → Mail & Cloud →
  IMAP/POP3/SMTP-Passwort* oder vergleichbar
- Für die native Menüleisten-App: Xcode Command Line Tools (`xcode-select
  --install`) für den Swift-Compiler
- Alternativ/zusätzlich: [SwiftBar](https://github.com/swiftbar/SwiftBar)
  für eine textbasierte Menüleisten-Anzeige ohne eigenes App-Bundle

## Installation (unter 10 Minuten)

### Python-CLI

```bash
cd dmarcwatch
./install.sh
```

Das Skript legt `.venv` an, installiert dmarcwatch hinein und fragt am Ende
interaktiv nach, ob es gleich das Schlüsselbund-Passwort einrichten
(`getpass`, landet nirgends außer im Schlüsselbund) und den täglichen
LaunchAgent installieren soll. Beides sind dauerhafte Änderungen und
passieren deshalb nur mit Bestätigung, nicht automatisch. Mehrfaches
Ausführen ist unschädlich - ein bestehendes `.venv` wird weiterverwendet.

`install.sh` lädt nichts aus dem Netz und führt kein Fremdskript aus - es
ruft nur lokal `python3 -m venv`, `pip install .` und `dmarcwatch setup`
auf.

<details>
<summary>Manuelle Installation (falls kein Shellscript gewünscht ist)</summary>

```bash
cd dmarcwatch
python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -e .
```

Das Upgrade von pip schadet nie und stellt sicher, dass `pip install -e .`
(editierbare Installation aus einem reinen `pyproject.toml` ohne
`setup.py`) zuverlässig funktioniert - `-e` ist für die Entwicklung
gedacht (siehe [Tests](#tests)), für die normale Nutzung reicht
`pip install .` ohne `-e`.

Einrichtung (Konfiguration + Schlüsselbund-Passwort + optional LaunchAgent):

```bash
.venv/bin/dmarcwatch setup --install-agent
```

Das fragt interaktiv nach dem IMAP-Passwort (Eingabe wird nicht angezeigt,
landet nirgends außer im Schlüsselbund) und installiert einen täglichen
LaunchAgent (Default: 07:30 Uhr, mit `--hour`/`--minute` änderbar).

</details>

Testlauf von Hand:

```bash
.venv/bin/dmarcwatch fetch -v
.venv/bin/dmarcwatch report --days 7
```

`report` gibt eine Tabelle aus und beendet sich mit Exit-Code `1`, wenn im
Zeitraum etwas Auffälliges dabei war, sonst mit `0`.

### Native Menüleisten-App

Bauen und einmal öffnen:

```bash
cd macapp/DmarcwatchMenuBar
./build_app.sh
open DmarcwatchMenuBar.app
```

`build_app.sh` baut die Release-Binary, packt sie zusammen mit Icon und
`Info.plist` zu einem echten `DmarcwatchMenuBar.app`-Bundle (ohne echtes
Bundle zeigt macOS in Aktivitätsanzeige/Anmeldeobjekten nur ein leeres
Icon, da eine bloße Mach-O-Datei keine Icon-Ressource mitbringt) und
signiert es ad-hoc (rein lokal, kein Developer-ID nötig). Das Icon selbst
kommt aus `generate_icon.swift` - nur bei Bedarf neu auszuführen, falls
sich das Icon mal ändern soll (siehe Kommentar im Skript). Erfordert
macOS 13 (Ventura) oder neuer.

Vier Menüpunkte in der laufenden App ersetzen den Terminal-Weg von oben:

- **Einstellungen…** öffnet ein natives Formular für IMAP-Server/Login/
  Passwort/Ordner, eigene Domain(s), eigene Sende-Netze und die Uhrzeit des
  täglichen Abrufs - eine Alternative zu `dmarcwatch setup` für alle, die
  lieber keine Terminal-Eingabe machen wollen. Speichert intern trotzdem
  über denselben Python-Code (`dmarcwatch setup --from-stdin-json`,
  Konfiguration und Passwort als ein JSON-Objekt über stdin, nie als
  Kommandozeilenargument) - keine doppelte, potenziell abweichende
  Implementierung der sicherheitsrelevanten Schreibzugriffe (config.json,
  Schlüsselbund, LaunchAgent). Der Knopf **"Aus SPF ermitteln…"** neben dem
  Sende-Netze-Feld fragt (nach Bestätigung im Dialog) den SPF-DNS-Eintrag
  der eingetragenen Domain(s) ab und schlägt die daraus gefundenen
  CIDR-Bereiche vor - inklusive `include:`/`redirect=`/`a`/`mx`-Auflösung,
  mit dem RFC-7208-Lookup-Limit von 10 gegen kaputte oder böswillig
  verschachtelte Records abgesichert (siehe `spf.py`). Der Vorschlag landet
  nur im Textfeld, nichts wird ungesehen gespeichert.
- **Bei Anmeldung starten** registriert die App selbst als Login-Item über
  `SMAppService` (`LoginItemManager.swift`), statt wie früher über eine von
  `dmarcwatch setup` installierte LaunchAgent-plist. Vorteil: System
  Settings > Anmeldeobjekte zeigt das echte App-Icon statt eines
  generischen Platzhalters (plist-basierte LaunchAgents bekommen dort
  grundsätzlich nur ein Platzhalter-Icon, unabhängig vom Ziel-Bundle).
  Nachteil gegenüber der alten Lösung: kein automatischer Neustart bei
  einem Absturz - für ein reines Anzeige-Utility hinnehmbar.
- **WHOIS abrufen…** erscheint im Untermenü eines auffälligen Records ohne
  gecachten WHOIS-Eintrag. Fragt vor der eigentlichen Abfrage per Dialog
  nach ("Fragt die Organisation hinter \<IP\> bei rdap.org ab - das
  verlässt dein Gerät"), ruft erst nach Bestätigung `dmarcwatch inspect
  <ip> --whois` auf. Entspricht einem manuellen Terminal-Befehl, nur
  bequemer erreichbar - siehe Einschränkung direkt darunter.
- **DNS prüfen…** öffnet nach Bestätigung im Dialog ein Fenster mit dem
  Ergebnis von `dmarcwatch verify-dns --json` für alle konfigurierten
  `own_domains` - DMARC/SPF/DKIM/MTA-STS/TLS-RPT-DNS/Wildcard-SPF-Gültigkeit
  und Fehlkonfigurationen, siehe [`verify-dns`](#befehle) unten. Reine
  Diagnose, verändert nichts. Die Unterzeile unter "DNS prüfen…" zeigt immer
  den Zeitpunkt und das Ergebnis der letzten Prüfung (auch vom periodischen
  automatischen Check, siehe `enable_auto_dns_check` in der
  [Konfiguration](#konfiguration)), nicht nur von einem manuellen Klick.
  Sobald mindestens eine Domain eine Warnung hat, färben sich Symbol und die
  Fläche hinter den Statusleisten-Icons rot, und jede betroffene Domain
  bekommt darunter eine eigene, aufklappbare Zeile mit den konkreten
  Gründen - eine saubere Domain erzeugt keine zusätzliche Zeile, die
  Unterzeile "keine Auffälligkeiten" reicht dafür. Der Bestätigungsdialog
  selbst erklärt beim ersten Klick, was geprüft wird und wann rot erscheint,
  und lässt sich über "Nicht mehr fragen" dauerhaft überspringen.
- **TLS-RPT-Bericht…** öffnet ein Fenster mit den bereits lokal gespeicherten
  SMTP-TLS-RPT-Reports (`dmarcwatch tls-report --json`, siehe
  [Konfiguration](#konfiguration) und [`tls-report`](#befehle) unten) - pro
  Domain Policy-Typ, erfolgreiche/fehlgeschlagene TLS-Sitzungen und
  gemeldete Fehlertypen. Reines Lesen der lokalen DB wie die
  Haupt-Menüleiste, deshalb ohne Bestätigungsdialog (anders als "DNS
  prüfen…"/"WHOIS abrufen…", die tatsächlich nach außen gehen). Nur
  aussagekräftig, wenn `enable_tls_rpt` aktiviert ist.

Drei Kopfzeilen im Hauptmenü - DMARC, TLS-RPT und "Übersprungen" - erscheinen
jeweils nur dann, wenn es dazu tatsächlich etwas anzuzeigen gibt: die
TLS-RPT-Sektion nur bei aktivem `enable_tls_rpt` **und** mindestens einem
gespeicherten Report, "Übersprungen" nur, wenn beim letzten `fetch`-Lauf
tatsächlich eine Nachricht oder ein Anhang abgelehnt wurde (z. B. eine
Größengrenze oder eine erkannte Dekompressionsbombe, siehe
[Sicherheitsentscheidungen](#sicherheitsentscheidungen)) - keine dauerhaft
leere Sektion nur zur Vollständigkeit.

Abgesehen von **"WHOIS abrufen…"**, **"Aus SPF ermitteln…"** und
**"DNS prüfen…"** macht die App selbst **keine** Netzwerkanfrage von sich
aus - alles andere (inklusive **"TLS-RPT-Bericht…"**) liest ausschließlich
aus der lokalen SQLite-Datenbank, die `fetch` befüllt. Das sind die
einzigen drei Stellen, an denen ein Klick tatsächlich nach außen geht (RDAP
bzw. DNS), und alle drei immer erst nach expliziter Bestätigung im Dialog,
nie automatisch im Hintergrund.

Wichtig: dmarcwatch darf **nicht** unter `~/Desktop`, `~/Documents` oder
`~/Downloads` liegen. Diese Ordner sind unter macOS durch TCC geschützt -
ein interaktives Terminal hat dort in der Regel bereits Zugriff, ein von
launchd frisch gestarteter Prozess (z. B. der tägliche `fetch`-Agent oder
die Menüleisten-App) aber nicht, und scheitert dann mit "Operation not
permitted" beim Start, bevor überhaupt eigener Code läuft. `~/dmarcwatch`
selbst ist davon nicht betroffen.

Das war's - der Rechner sieht künftig täglich selbst nach und meldet sich
nur, wenn etwas auffällig ist.

<details>
<summary>Alternative: SwiftBar statt der nativen App</summary>

`swiftbar/dmarcwatch.10m.sh` in den SwiftBar-Plugin-Ordner verlinken oder
kopieren (Intervall steht im Dateinamen, `10m` = alle 10 Minuten). Falls
dmarcwatch nicht unter `~/dmarcwatch` liegt, `DMARCWATCH_HOME` in dem
Skript anpassen oder als Umgebungsvariable in SwiftBars
Plugin-Einstellungen setzen.

```bash
ln -s "$(pwd)/swiftbar/dmarcwatch.10m.sh" ~/Documents/SwiftBar/dmarcwatch.10m.sh
```

</details>

## Konfiguration

`~/Library/Application Support/dmarcwatch/config.json` (wird von `setup`
mit Defaults angelegt, Verzeichnis `0700`, Datei `0600`):

| Feld | Bedeutung | Default |
|---|---|---|
| `imap_host` | IMAP-Server¹ | kein Default |
| `imap_port` | IMAP-Port (anbieterunabhängiger IMAPS-Standard) | `993` |
| `imap_user` | IMAP-Login / Schlüsselbund-Account² | z. B. `mail@example.com` |
| `imap_folder` | Ordner mit den Reports³ | `INBOX/DMARC` |
| `move_to_processed_folder` | Nachrichten nach Verarbeitung verschieben statt nur als gelesen zu markieren | `false` |
| `processed_folder` | Zielordner, falls obiges aktiv ist | `INBOX/DMARC/verarbeitet` |
| `own_domains` | Eigene Domains, alles andere wird verworfen⁴ | z. B. `["example.com"]` |
| `own_ip_networks` | Eigene Sende-Netze als CIDR⁵ | z. B. `["192.0.2.0/24", "2001:db8:1::/48"]` |
| `max_attachment_size_mb` | Obergrenze für Anhänge | `5` |
| `max_xml_size_mb` | Obergrenze für entpacktes XML⁶ | `10` |
| `max_message_size_mb` | Obergrenze für die gesamte Nachricht⁷ | `8` |
| `max_records_per_report` | Obergrenze für `<record>`-Elemente pro Report⁸ | `10000` |
| `notify_on_new_findings` | macOS-Notification bei neuen Auffälligkeiten | `true` |
| `enable_reverse_dns_lookup` | Reverse-DNS für Quell-IPs (verlässt das Gerät!) - aktuell nicht implementiert, Platzhalter für künftige, ausdrücklich einzuschaltende Erweiterung | `false` |
| `menubar_days` | Zeitfenster für die Menüleisten-Anzeige | `7` |
| `enable_tls_rpt` | TLS-RPT-Auswertung (RFC 8460) ein-/ausschalten⁹ | `false` |
| `tlsrpt_imap_folder` | Ordner mit den TLS-RPT-Reports, nur relevant wenn obiges aktiv ist | `INBOX/TLS-RPT` |
| `tlsrpt_processed_folder` | Zielordner, falls `move_to_processed_folder` aktiv ist | `INBOX/TLS-RPT/verarbeitet` |
| `max_json_size_mb` | Obergrenze für entpacktes TLS-RPT-JSON¹⁰ | `2` |
| `max_tls_policies_per_report` | Obergrenze für `policies`-Einträge pro TLS-RPT-Report¹¹ | `50` |
| `max_tls_failure_details_per_policy` | Obergrenze für `failure-details`-Einträge pro Policy¹¹ | `200` |
| `enable_auto_dns_check` | Periodische, automatische `verify-dns`-Prüfung während `fetch`¹² | `false` |
| `auto_dns_check_interval_days` | Abstand zwischen zwei automatischen Prüfungen, falls obiges aktiv ist | `7` |

Das IMAP-Passwort steht **nicht** in dieser Datei, sondern ausschließlich im
Schlüsselbund (Dienst `dmarcwatch`, Account = `imap_user`).

<sup>1</sup> Bewusst kein Default trotz Namensähnlichkeit zum primär
getesteten Anbieter (mailbox.org, `imap.mailbox.org`) - dmarcwatch ist ein
öffentliches, anbieterunabhängiges Projekt, und ein vorbelegter fremder
Hostname würde bei zu schnellem Enter zu einem verwirrenden
Verbindungsfehler gegen den falschen Server führen statt offensichtlich
das eigene Postfach zu sein. Wird bei `dmarcwatch setup` genauso zwingend
abgefragt wie `imap_user`/`own_domains`.
<br>
<sup>2</sup> Das echte Postfach, **nicht** die rua-Alias-Adresse aus dem
DMARC-DNS-Eintrag (Aliase sind bei mailbox.org meist kein eigener
IMAP-Login). Wird bei `dmarcwatch setup` interaktiv abgefragt, kein Default.
<br>
<sup>3</sup> Bei mailbox.org liegen per Filterregel angelegte Ordner meist
unter `INBOX` ("Eingang" in der Weboberfläche), nicht als eigener
Top-Level-Ordner - `dmarcwatch fetch` mit falschem Namen listet in der
Fehlermeldung die tatsächlichen Ordnernamen.
<br>
<sup>4</sup> Wird bei `dmarcwatch setup` interaktiv abgefragt, kein Default.
<br>
<sup>5</sup> IPv4 und IPv6, Zugehörigkeit über `ipaddress`-Netzvergleich
geprüft, nicht per Zeichenkette. **Kein Default und keine interaktive
Abfrage** - die eigenen Sende-Netze kennt man i. d. R. erst nach den ersten
echten Reports (`source_ip` bei sauberen Einträgen) oder aus dem eigenen
SPF-DNS-Eintrag (der "Aus SPF ermitteln…"-Knopf in der Setup-GUI macht
genau das automatisch, siehe oben). Leer = jede IP gilt zunächst als
unbekannt und wird markiert - sicherer, sichtbarer Zustand statt eines
stillen Falsch-negativs.
<br>
<sup>6</sup> 10 MB ist laut IETF-Draft zur DMARC-Aggregate-Reporting-
Spezifikation "far larger than any real aggregate report".
<br>
<sup>7</sup> Header + alle MIME-Teile, base64-kodiert, geprüft per
`RFC822.SIZE` **vor** dem eigentlichen IMAP-Abruf des Bodys. Aus
`max_attachment_size_mb` abgeleitet (base64 bläht ~1.37x auf) plus
Spielraum.
<br>
<sup>8</sup> Belt-and-suspenders zur Größengrenze: ein Report an der
10-MB-Grenze mit ~42.000 flachen Records kostet empirisch bereits < 1s
CPU-Zeit, dieses Limit macht das Verhalten bei absichtlicher Datenflut
zusätzlich deterministisch, statt sich allein auf den CPU-Zeit-Backstop des
LaunchAgents zu verlassen.
<br>
<sup>9</sup> Standardmäßig aus: ein bestehendes Setup hätte sonst plötzlich
einen fehlschlagenden `fetch` (Ordner existiert nicht), nur weil ein Update
dieses Feld einführt. Vor dem Aktivieren zuerst eine Filterregel im
Postfach anlegen, die Mail an die TLS-RPT-`rua`-Adresse in
`tlsrpt_imap_folder` einsortiert.
<br><br>
Damit überhaupt TLS-RPT-Reports mit Inhalt hereinkommen, muss die eigene
Domain vorher **MTA-STS** (RFC 8461) oder **DANE** einrichten - ohne eine
der beiden bekommen die meisten Absender höchstens einen "no-policy-found"-
Eintrag ohne echte Fehlerdaten. Für MTA-STS braucht es eine per HTTPS
erreichbare Policy-Datei unter `https://mta-sts.<domain>/.well-known/mta-sts.txt`
mit einem zum Hostnamen passenden Zertifikat - ohne eigenen Webspace lässt
sich das z. B. über [CaptainDNS](https://www.captaindns.com/) (EU/Frankreich)
per CNAME hosten, ganz ohne eigenen Server. Eine Stolperfalle dabei, die
wenig bekannt ist und leicht zu Frust führt: CaptainDNS zeigt den
einzutragenden DNS-Namen als vollständigen Domainnamen an (z. B.
`_mta-sts.example.com.`), viele DNS-Verwalter (u. a. INWX) erwarten im
Namensfeld aber nur den Teil **vor** der eigenen Domain und hängen den Rest
selbst an. Trägt man dort den vollen Namen aus der Anleitung ein, entsteht
ein doppelter, nicht funktionierender Eintrag
(`_mta-sts.example.com.example.com` statt `_mta-sts.example.com`) - der
Eintrag scheint vorhanden zu sein, wird aber nie gefunden. Im Zweifel den
Eintrag danach direkt per `dig` gegen die eigenen Nameserver prüfen, nicht
nur im Panel nachsehen.

Beispiel für die Domain `example.com` (Werte hier frei erfunden, nicht die
tatsächlich von einem Anbieter ausgegebenen):

| Typ | Name **im DNS-Panel** (relativ zur Zone, z. B. bei INWX) | Wert |
|---|---|---|
| CNAME | `mta-sts` | `hosting.beispiel-anbieter.test` |
| TXT | `_mta-sts` | `v=STSv1; id=2026081900000001` |
| TXT | `_captaindns-assets-verify` (oder analog, je nach Anbieter) | `beispiel-verifizierungscode-123abc` |

Falsch wäre es, im Namensfeld stattdessen den vollen Namen aus der
Anbieter-Anleitung einzutragen:

| Typ | Falsch eingetragener Name | Tatsächlich entstehender (nutzloser) Eintrag |
|---|---|---|
| CNAME | `mta-sts.example.com` | `mta-sts.example.com.example.com` |
| TXT | `_mta-sts.example.com` | `_mta-sts.example.com.example.com` |

Ob es bei INWX genauso läuft wie bei anderen Panels: einfach ausprobieren
und mit `dig` gegenprüfen - das Prinzip (Namensfeld relativ zur eigenen
Zone, Anbieter-Anleitung zeigt aber oft den vollen Namen) betrifft nicht
nur CaptainDNS, sondern jeden Dienst, der einen fertigen DNS-Eintrag zum
Kopieren vorgibt.
<br>
<sup>10</sup> TLS-RPT-Reports (RFC 8460) sind typischerweise deutlich
kleiner als DMARC-Aggregate-Reports - keine Pro-Quell-IP-Aufschlüsselung in
vergleichbarem Umfang, deshalb ein eigener, kleinerer Wert statt
`max_xml_size_mb` mitzubenutzen.
<br>
<sup>11</sup> Analog zu `max_records_per_report` bei DMARC, aber bewusst
enger: ein TLS-RPT-Report hat pro Domain realistisch eine Handvoll
`policies`-Einträge (eigene STS-Policy, ggf. TLSA, "no-policy-found"), nicht
Tausende wie DMARC-Records bei großen Absendern. `failure-details` fasst
laut RFC bereits nach (Ergebnistyp, sendende MTA-IP, empfangender MX-Host)
zusammen - auch bei einer echten Störung realistischerweise eine niedrige
zweistellige Zahl unterschiedlicher Kombinationen, nicht Zehntausende.
<br>
<sup>12</sup> Läuft als Teil des täglichen `fetch`-Laufs mit, nicht als
eigener LaunchAgent - prüft vor jedem `fetch` anhand einer Datumsdatei, ob
seit der letzten automatischen Prüfung mindestens `auto_dns_check_interval_days`
Tage vergangen sind, und ruft dann intern dieselbe Prüfung wie `verify-dns`
auf. Das Ergebnis fließt in `menubar-json` ein (Statusleisten-Pille/rote
Domain-Zeilen, siehe [Native Menüleisten-App](#native-menüleisten-app)) und
löst bei Auffälligkeiten eine eigene Notification aus, hat aber **keinen**
Einfluss auf den Exit-Code von `fetch` selbst - ein DNS-Konfigurationsproblem
ist kein Anzeichen für einen fehlgeschlagenen Abruf.

## Befehle

- `dmarcwatch setup [--install-agent] [--remove-agent] [--hour H] [--minute M]`
  Legt Konfiguration und Schlüsselbund-Eintrag an, verwaltet den LaunchAgent.
- `dmarcwatch fetch [-v]`
  Holt neue Reports, wertet sie aus, speichert sie - DMARC immer, TLS-RPT
  zusätzlich aus einem separaten Ordner, wenn `enable_tls_rpt` aktiv ist
  (siehe [Konfiguration](#konfiguration)). Exit-Code `1`, wenn der Lauf neue
  DMARC-Auffälligkeiten oder gemeldete TLS-RPT-Fehlschläge gebracht hat,
  sonst `0`; Netzwerk-/IMAP-Fehler führen ebenfalls zu Exit-Code `1` und
  einem Logeintrag.
- `dmarcwatch report [--days N]`
  Tabellarische Zusammenfassung für die letzten N Tage (Default 7).
- `dmarcwatch tls-report [--days N] [--json]`
  Tabellarische Zusammenfassung der bereits gespeicherten TLS-RPT-Reports
  (RFC 8460) für die letzten N Tage - pro Domain Policy-Typ, erfolgreiche/
  fehlgeschlagene TLS-Sitzungen und gemeldete Fehlertypen. Exit-Code `1` bei
  mindestens einem Fehlschlag im Zeitraum, sonst `0`. `--json` gibt
  strukturierte Ausgabe statt der Tabelle aus - für das
  "TLS-RPT-Bericht…"-Fenster in der Menüleisten-App gedacht, funktioniert
  aber genauso von Hand im Terminal. Nur aussagekräftig, wenn
  `enable_tls_rpt` aktiv ist und `fetch` schon mindestens einmal danach
  gelaufen ist.
- `dmarcwatch inspect <ip-oder-cidr> [--days N] [--whois]`
  Vollständige Details zu einer IP oder einem Netz (z. B. `2a01:111::/32`),
  ohne von Hand SQL gegen die Datenbank zu schreiben. `--whois` fragt
  zusätzlich die Organisation hinter der IP per RDAP ab (rein informativ,
  keine Sicherheitseinstufung - Details und Begründung unter
  [Sicherheitsentscheidungen](#sicherheitsentscheidungen)) und legt das
  Ergebnis in `whois_cache` ab, damit die Menüleisten-App es anzeigen kann,
  ohne selbst je eine Netzwerkanfrage zu machen.
- `dmarcwatch menubar`
  Erzeugt die SwiftBar-Textausgabe (wird von `swiftbar/dmarcwatch.10m.sh`
  aufgerufen, nicht für den interaktiven Gebrauch gedacht).
- `dmarcwatch menubar-json`
  Strukturierte JSON-Ausgabe für die native Menüleisten-App (`macapp/`),
  inklusive gecachter WHOIS-Ergebnisse. Ebenfalls nicht für den
  interaktiven Gebrauch gedacht.
- `dmarcwatch resolve-spf <domain>`
  Löst den SPF-DNS-Eintrag einer Domain auf (`include:`/`redirect=`/`a`/`mx`,
  RFC-7208-Lookup-Limit von 10 gegen kaputte/böswillig verschachtelte
  Records) und gibt die gefundenen CIDR-Bereiche als JSON zurück - ein
  Vorschlag für `own_ip_networks`. Verlässt das Gerät (DNS). Für den "Aus
  SPF ermitteln…"-Knopf in der Setup-GUI gedacht, funktioniert aber genauso
  von Hand im Terminal.
- `dmarcwatch verify-dns [domain]`
  Prüft die eigenen DMARC-/SPF-/DKIM-DNS-Einträge auf Gültigkeit und
  häufige Fehlkonfigurationen (ohne Domain: alle konfigurierten
  `own_domains`) - Diagnose der eigenen Einrichtung, nicht Auswertung
  eingehender Reports. **DMARC**: Pflicht-Tags vorhanden, gültige
  Policy, mehrere Einträge (laut RFC 7489 macht das den ganzen Eintrag
  ungültig), fehlendes `rua` (keine Reports möglich), `p=none`
  (noch keine Durchsetzung), `pct` < 100. **SPF**: siehe
  `resolve-spf` oben, zusätzlich tatsächlich verbrauchte Lookups
  gegenüber dem RFC-7208-Limit, fehlender/zu offener `all`-Mechanismus
  (`+all`). **DKIM**: prüft Selektoren, die in bereits abgerufenen,
  echten Reports beobachtet wurden ([store.py](src/dmarcwatch/store.py)
  `get_known_dkim_selectors`) - bewusst nicht gegen eine geratene Liste
  "üblicher" Namen, das bleibt zwangsläufig unvollständig. Unterstützt
  RSA- und Ed25519-Schlüssel, folgt CNAME-Delegation (viele Anbieter,
  z. B. mailbox.org, verweisen den DKIM-Eintrag per CNAME auf sich
  selbst, damit Kund:innen bei einer Schlüsselrotation nichts ändern
  müssen). Verlässt das Gerät (DNS). Zusätzlich drei rein optionale Checks -
  **fehlen** sie ganz, erzeugt das keine Warnung, nur ein angefangenes/kaputtes
  Setup fällt auf: **MTA-STS** (RFC 8461) prüft `mta-sts.<domain>`
  (CNAME/A/AAAA) und die Policy-TXT unter `_mta-sts.<domain>`, ruft
  zusätzlich die tatsächliche Policy-Datei per HTTPS unter
  `https://mta-sts.<domain>/.well-known/mta-sts.txt` ab (anbieterunabhängig,
  kein Rückgriff auf eine bestimmte Hosting-API/Statusseite - siehe
  [Konfiguration](#konfiguration) oben zu CaptainDNS) und meldet, ob sie
  tatsächlich erreichbar ist und mit `version: STSv1` beginnt. **TLS-RPT-DNS**
  prüft den `_smtp._tls.<domain>`-TXT-Eintrag (`v=TLSRPTv1; rua=...`), der
  ankündigt, wohin TLS-RPT-Reports gehen sollen. **Wildcard-SPF** prüft einen
  `*.<domain>`-TXT-Eintrag als Schutz vor Phishing über nicht existierende
  Subdomains. `--json` gibt strukturierte Ausgabe statt der Tabelle aus -
  für das "DNS prüfen…"-Fenster in der Menüleisten-App gedacht, funktioniert
  aber genauso von Hand im Terminal.

Logs: `~/Library/Application Support/dmarcwatch/dmarcwatch.log` (0600,
keine Zugangsdaten, keine vollständigen Mailadressen).

## launchd

`dmarcwatch setup --install-agent` erzeugt und lädt
`~/Library/LaunchAgents/local.dmarcwatch.fetch.plist` (Programm-Pfad zeigt
auf den Python-Interpreter der venv, Zeitplan über `StartCalendarInterval`,
keine Zugangsdaten in der Datei). `launchd/local.dmarcwatch.fetch.plist.template`
liegt zusätzlich als Referenz für eine manuelle Installation bei.

Zusätzlich `RunAtLoad`: launchd holt einen wegen ausgeschaltetem oder
schlafendem Mac verpassten `StartCalendarInterval`-Termin **nicht** von
selbst nach (anders als z. B. cron+anacron unter Linux) - ohne `RunAtLoad`
bliebe ein Tag, an dem der Mac zur geplanten Zeit aus war, komplett ohne
Abruf. Damit das nicht bei jedem Login/Neustart einen unnötigen doppelten
IMAP-Check auslöst, prüft `fetch --skip-if-already-run-today` zuerst eine
einzelne Datei (`last_fetch_success`, nur ein Datum, wird bei jedem Lauf
überschrieben statt protokolliert) und überspringt den Abruf, wenn heute
schon einer erfolgreich lief. "Jetzt abrufen" im Menü und ein von Hand
getipptes `dmarcwatch fetch` lassen das Flag bewusst weg und prüfen immer
tatsächlich.

Die Menüleisten-App installiert **keine** eigene launchd-plist mehr -
"Bei Anmeldung starten" in ihrem Menü registriert stattdessen die App
selbst über `SMAppService` (siehe Abschnitt oben). `dmarcwatch setup
--remove-menubar-agent` bleibt als reine Migrationshilfe erhalten, um eine
noch aus einer älteren Version vorhandene `local.dmarcwatch.menubar.plist`
zu entfernen.

Fetch-LaunchAgent entfernen:

```bash
.venv/bin/dmarcwatch setup --remove-agent
```

Status prüfen: `launchctl list | grep dmarcwatch`

## Deinstallation

```bash
./uninstall.sh
```

Entfernt beide LaunchAgents und lokale Build-Artefakte (`.venv`,
Swift-Build - beides jederzeit über `install.sh` neu erzeugbar).
Löscht standardmäßig **keine** echten Daten. Für Konfiguration,
Report-Datenbank und Logs (`~/Library/Application Support/dmarcwatch`)
oder das Schlüsselbund-Passwort explizit dazusagen:

```bash
./uninstall.sh --delete-data       # Konfiguration, Datenbank, Logs
./uninstall.sh --delete-keychain   # IMAP-Passwort aus dem Schlüsselbund
./uninstall.sh --all               # beides
```

Der Projektordner selbst wird nie automatisch gelöscht - das steht am Ende
der Ausgabe als expliziter, von Hand auszuführender Schritt.

## Tests

```bash
.venv/bin/pip install -e ".[dev]"
.venv/bin/python -m pytest tests/ -q
```

212 Tests, siehe [tests/](tests/). Abgedeckt (Spezifikation Abschnitt 5 und
darüber hinaus):

**Funktional**
- SES-Report mit einem Record, alles `pass` ([test_parser.py](tests/test_parser.py), [fixtures/ses_single_pass.xml](tests/fixtures/ses_single_pass.xml))
- Microsoft-Report mit zwei Records (CRLF-Zeilenenden, andere Feldreihenfolge),
  davon einer mit `spf=fail`, `dkim=fail`, `disposition=quarantine` - wird als
  auffällig erkannt ([test_store.py](tests/test_store.py))
- Vier zusätzliche Dialekt-Fixtures, strukturell von echten Reports abgeleitet
  (Google als ZIP mit `np`-Feld, Microsoft mit `xmlns`-Attributen, Amazon SES
  Tab-eingerückt mit anderer `dkim`-Feldreihenfolge, Mimecast mit leerem
  `<human_result/>`-Element) - [test_dialect_fixtures.py](tests/test_dialect_fixtures.py)
- Derselbe Report zweimal eingelesen - keine Duplikate (`UNIQUE(org_name, report_id)`)
- Report mit unbekannter Quell-IP - wird als auffällig erkannt
- IPv6-Netzzugehörigkeit unabhängig von der Schreibweise (Kompression,
  Groß-/Kleinschreibung) - reiner Präfixvergleich würde hier scheitern
- Dateirechte (Verzeichnis 0700, DB/Log/Config 0600), auch nachträgliches
  Verschärfen bereits laxer Dateien ([test_permissions.py](tests/test_permissions.py))
- launchd-Plist-Generierung: korrekter Zeitplan, CPU-Ressourcenlimit, keine
  Zugangsdaten in der Datei ([test_launchd.py](tests/test_launchd.py))
- Interaktiver Ersteinrichtungs-Dialog: fragt Server/Login/Domain(s) ab,
  überspringt bereits vorhandene Werte, `--reconfigure` erzwingt Neuabfrage
  ([test_cli_setup.py](tests/test_cli_setup.py))

**Sicherheit**
- XXE (externe Entität) - abgelehnt ([fixtures/xxe_attack.xml](tests/fixtures/xxe_attack.xml))
- Billion Laughs (verschachtelte Entitäten) - abgelehnt ([fixtures/billion_laughs.xml](tests/fixtures/billion_laughs.xml))
- Gzip-Bombe - scheitert an der Größengrenze ([test_archive.py](tests/test_archive.py))
- ZIP mit Dateiname `../../evil.txt` - nichts wird außerhalb geschrieben
  (tatsächlich: archivinterne Namen werden nie zum Schreiben benutzt, die
  Extraktion passiert komplett im Speicher)
- Report-Feld mit `|` und `bash=...` - wird in der SwiftBar-Ausgabe nicht
  als Parameter interpretiert ([test_menubar.py](tests/test_menubar.py))
- SQL-Injection-Payload als Report-Feld - landet als reiner Text, Tabellen
  bleiben unangetastet ([test_sql_injection.py](tests/test_sql_injection.py))
- AppleScript-Injection-Versuch im Notification-Text (Ausbruch aus dem
  Stringliteral, `do shell script`-Anhängung) - schlägt fehl, echter
  `osascript`-Aufruf wird mitgetestet ([test_notify_injection.py](tests/test_notify_injection.py))
- Report für eine fremde Domain - wird verworfen
- Abgeschnittenes/kaputtes XML - Lauf läuft weiter, nur dieser Report fällt aus
  ([test_fetch.py](tests/test_fetch.py) zeigt das auch auf IMAP-Ebene:
  eine kaputte Nachricht stoppt nicht die Verarbeitung der übrigen, inklusive
  einer zu großen Nachricht, die vor dem eigentlichen Abruf erkannt wird)
- Schlüsselbund-Zugriff ausschließlich gemockt getestet - berührt nie den
  echten macOS-Schlüsselbund der ausführenden Person ([test_keychain.py](tests/test_keychain.py))

## Sicherheitsentscheidungen

Die verarbeiteten Reports kommen von außen - jeder kann eine Mail an die
`rua`-Adresse schicken und damit beliebige Anhänge in den Verarbeitungspfad
einschleusen. Der Parser ist deshalb als Angriffsfläche behandelt worden,
nicht als vertrauenswürdige Eingabe:

- **defusedxml statt xml.etree** ([parser.py](src/dmarcwatch/parser.py)):
  schaltet DTDs, externe Entitäten und Netzwerkzugriffe beim Parsen ab und
  verhindert damit XXE und Billion-Laughs strukturell, nicht durch
  Blocklisten.
- **Alles im Speicher, keine archivinternen Dateinamen**
  ([archive.py](src/dmarcwatch/archive.py)): ZIP- und gzip-Anhänge werden
  ausschließlich in `BytesIO` entpackt, nie auf die Festplatte geschrieben.
  Path-Traversal über `../../evil.txt` im Archivnamen ist damit kein Thema,
  weil der Name nirgends als Dateipfad verwendet wird - nicht, weil er
  gefiltert würde.
- **Größenbegrenzung unabhängig von Header-Angaben**: Sowohl bei gzip als
  auch bei ZIP wird die entpackte Größe während des Lesens laufend geprüft
  (`_read_bounded`), nicht erst am Ende. Ein ZIP, das im Header eine kleine
  Größe behauptet, aber mehr liefert, fliegt trotzdem raus, bevor Speicher
  vollläuft.
- **SQL ausschließlich parametrisiert** ([store.py](src/dmarcwatch/store.py)):
  Report-Felder landen nie per String-Verkettung in einem SQL-Statement.
- **IP-Validierung über `ipaddress`, nicht per String-Vergleich**
  ([parser.py](src/dmarcwatch/parser.py)): verhindert, dass z. B.
  `192.0.2.1.evil.com` fälschlich als eigene IP durchgeht, weil sie mit
  dem Präfix "beginnt".
- **Netzzugehörigkeit statt Zeichenketten-Präfix** ([config.py](src/dmarcwatch/config.py)
  `is_own_ip`): `own_ip_networks` sind CIDR-Netze, geprüft über
  `ipaddress.ip_network(...).__contains__`. Bei IPv4 wäre ein reiner
  Präfixvergleich noch zufällig oft richtig, bei IPv6 scheitert er
  grundsätzlich, weil dieselbe Adresse mehrere gültige Schreibweisen hat
  (`2001:DB8:1:0:465:0:0:201` und `2001:db8:1:0:465::201` sind
  dieselbe Adresse, aber unterschiedliche Zeichenketten).
- **Fremde Domains werden beim Einspeisen verworfen**
  ([store.py](src/dmarcwatch/store.py) `ingest_report`): ein Report, dessen
  `policy_published/domain` nicht in `own_domains` steht, landet nie in der
  Datenbank, unabhängig davon, was sonst noch im Report steht.
- **SwiftBar-Escaping** ([sanitize.py](src/dmarcwatch/sanitize.py)):
  SwiftBar trennt Text und Parameter mit `|`; ein Parameter wie `bash=`
  würde beim Klick einen Befehl ausführen. Jeder Wert, der in eine
  Menüleisten-Zeile eingebettet wird, läuft durch `sanitize_field()`, das
  `|`, Steuerzeichen, ANSI-Escapes und Zeilenumbrüche entfernt und die
  Länge begrenzt. Dieselbe Funktion wird für die CLI-Tabellenausgabe und
  für macOS-Notifications benutzt, weil auch ein Terminal auf ANSI-Escapes
  in Report-Feldern reagieren kann - nicht nur SwiftBar auf `|`.
- **Keine `shell=True`, keine Befehlszusammensetzung aus Strings**: sowohl
  `notify.py` (osascript) als auch `launchd.py` (launchctl) rufen
  `subprocess.run` mit einer Argumentliste auf.
- **Passwort ausschließlich im Schlüsselbund, nie als Prozessargument**
  ([keychain.py](src/dmarcwatch/keychain.py)): `setup` liest das Passwort
  über `getpass()` ein und speichert es über das `keyring`-Modul, das auf
  macOS die Security-Framework-APIs direkt aufruft. Es gibt keinen
  Codepfad, der das Passwort als Kommandozeilenargument an `security` oder
  einen anderen Prozess übergibt (das wäre über `ps` für andere lokale
  Nutzer sichtbar).
- **TLS fest verdrahtet, keine Abschaltoption**
  ([fetch.py](src/dmarcwatch/fetch.py) `build_ssl_context`):
  `ssl.create_default_context()` mit `minimum_version = TLSv1_2`. Es gibt
  bewusst keine Konfigurationsoption, Zertifikats- oder Hostname-Prüfung
  abzuschalten.
- **Fail closed** ([fetch.py](src/dmarcwatch/fetch.py)): Fehler bei
  einzelnen Anhängen oder Reports werden abgefangen, protokolliert und
  übersprungen - der Lauf macht weiter. Netzwerk- und IMAP-Protokollfehler
  werden dagegen bewusst *nicht* abgefangen, sondern brechen den Lauf mit
  Exit-Code `1` ab, damit ein Ausfall nicht als stiller "keine neuen
  Reports"-Tag durchgeht.
- **Nachrichtengröße wird vor dem Abruf geprüft, nicht erst danach**
  ([fetch.py](src/dmarcwatch/fetch.py) `_get_message_size`): "jeder kann
  eine Mail an die rua-Adresse schicken" heißt, die Nachricht selbst ist
  unvertrauenswürdig, nicht nur ihre Anhänge. Vor jedem `FETCH ... RFC822`
  wird per `RFC822.SIZE` die Größe abgefragt (ohne den Body zu laden); ist
  sie unbekannt oder über `max_message_size_mb`, wird die Nachricht
  übersprungen, protokolliert und als gelesen markiert, ohne den Body je
  abzurufen. Der Grenzwert ist aus `max_attachment_size_mb` abgeleitet
  (base64-Kodierung bläht ~1.37x auf), nicht unabhängig geraten.
- **Obergrenze für Records pro Report** ([parser.py](src/dmarcwatch/parser.py)):
  ein Report mit mehr als `max_records_per_report` (Default 10.000) flachen
  `<record>`-Elementen wird komplett verworfen statt stillschweigend
  gekürzt. Empirisch getestet: ein Report an der 10-MB-Grenze mit ~42.000
  Records kostet bereits < 1s CPU-Zeit für Parsen + Einspeisen - zusammen
  mit dem CPU-Zeit-Backstop des LaunchAgents (`SoftResourceLimits`) ist der
  Angriffsvektor "viele flache Records statt Entity-Explosion" damit schon
  vor diesem Limit gedeckelt; das Limit macht das Verhalten bei
  absichtlicher Datenflut zusätzlich deterministisch.
- **TLS-RPT (RFC 8460) als eigene, aber gleichwertig abgesicherte
  Angriffsfläche** ([tls_parser.py](src/dmarcwatch/tls_parser.py),
  [archive.py](src/dmarcwatch/archive.py)): dieselbe
  IMAP-Verbindung/TLS-Konfiguration, dieselbe
  Größenprüfung-vor-Volltextabruf, dieselbe
  Dekompressionsbomben-Absicherung (`_extract_gz`/`_extract_zip`, geteilter
  Code) und dieselbe Fremd-Domain-Filterung wie bei DMARC - siehe
  `max_json_size_mb`, `max_tls_policies_per_report`,
  `max_tls_failure_details_per_policy` oben. JSON kennt zwar keine
  externen Entitäten (kein XXE-Äquivalent), aber sehr tief verschachtelte
  Eingaben können `json.loads()` intern einen `RecursionError`/
  Stack-Overflow auslösen - wird abgefangen wie jeder andere
  Parse-Fehler (empirisch mit 200.000 Verschachtelungsebenen getestet,
  siehe [test_tls_parser.py](tests/test_tls_parser.py)), kein
  Absturz und kein Abbruch des restlichen Laufs.
- **WAL-Modus für SQLite** ([store.py](src/dmarcwatch/store.py) `connect`):
  echtes nicht-blockierendes Nebeneinander von Lesen (Menüleisten-App, alle
  paar Minuten) und Schreiben (täglicher `fetch`-Lauf, Bruchteile einer
  Sekunde) statt des Standard-Rollback-Journals. Wichtig, empirisch
  geprüft: anders als die Rollback-Journal-Datei erben die
  WAL-Begleitdateien (`-wal`, `-shm`) NICHT automatisch die 0600-Rechte der
  Hauptdatenbank, sondern kommen mit dem Standard-umask (world-readable) -
  sie enthalten echte Report-Inhalte und werden deshalb nach jedem
  Verbindungsaufbau und nach jedem Schreibvorgang explizit gesichert
  (`secure_wal_sidecar_files`).
- **Kein zusätzlicher Netzverkehr im automatischen Betrieb**: `fetch` (der
  tägliche LaunchAgent) verbindet sich ausschließlich zum konfigurierten
  IMAP-Host. Keine Telemetrie, keine Update-Prüfung, keine automatischen
  Reverse-DNS-/Geo-/WHOIS-Lookups. Drei Ausnahmen, alle nur auf
  ausdrückliche Anfrage, nie im Hintergrundlauf:
  - `dmarcwatch inspect --whois` ([whois.py](src/dmarcwatch/whois.py)) -
    eine RDAP-Abfrage an rdap.org (auch über den Bestätigungsdialog "WHOIS
    abrufen…" in der Menüleisten-App erreichbar, ruft denselben Befehl
    auf). Bewusst rein informativ: das Ergebnis fließt nirgends in
    `own_ip_networks` oder die Auffälligkeits-Einstufung ein, auch nicht
    als automatische Ausnahme für "bekannte" Anbieter - Google und
    Microsoft betreiben auch riesige, für jeden mietbare Cloud-Bereiche,
    ein WHOIS-Treffer auf einen großen Namen ist kein Nachweis für
    legitime Weiterleitung und darf die Erkennung nicht aufweichen.
  - `dmarcwatch resolve-spf` ([spf.py](src/dmarcwatch/spf.py)) - eine
    DNS-Abfrage zur SPF-Auflösung (auch über "Aus SPF ermitteln…" in der
    Setup-GUI erreichbar). Nur ein Vorschlag fürs Formularfeld, wird nie
    ungesehen übernommen oder automatisch gespeichert.
  - `dmarcwatch verify-dns` ([dns_verify.py](src/dmarcwatch/dns_verify.py)) -
    DNS-Abfragen zur Prüfung der eigenen DMARC/SPF/DKIM-Einträge. Reine
    Diagnose, verändert nichts an der Konfiguration oder Auffälligkeits-
    Einstufung.
- **Gepinnte, minimale Abhängigkeiten**: `defusedxml` und `keyring`, sonst
  Standardbibliothek. Beide sind sicherheitsrelevant (nicht kosmetisch) und
  in `pyproject.toml` auf exakte Versionen gepinnt.

## Nicht-Ziele

Kein Webinterface, kein Server, kein Docker, keine Mehrbenutzerfähigkeit,
keine forensischen Reports (`ruf`), keine DNS-Änderungen, keine Auswertung
von Mailinhalten - siehe Spezifikation Abschnitt 6.
