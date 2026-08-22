# Sicherheitsrichtlinie

dmarcwatch verarbeitet DMARC-Aggregate-Reports, die per IMAP ankommen -
und da jeder eine Mail an die `rua`-Adresse einer Domain schicken kann,
ist der Parser bewusst als Angriffsfläche behandelt worden, nicht als
vertrauenswürdige Eingabe. Welche Härtungsmaßnahmen dafür bereits
eingebaut sind (defusedxml, Größenlimits, kein `shell=True`, parametrisierte
SQL-Statements, TLS fest verdrahtet, u. a.), steht im Detail im Abschnitt
[Sicherheitsentscheidungen](README.md#sicherheitsentscheidungen) der
README.

Wer einen Weg findet, diese Maßnahmen zu umgehen, oder ein anderes
Sicherheitsproblem entdeckt, sollte das bitte **privat** melden statt über
ein öffentliches Issue.

## Eine Lücke melden

Bitte über GitHubs private Sicherheitsmeldungen: im
[Security-Tab](../../security/advisories/new) dieses Repos auf "Report a
vulnerability" klicken. Das läuft vertraulich zwischen Melder:in und
Maintainer - so kann das Problem besprochen und behoben werden, bevor es
öffentlich sichtbar wird.

Bitte **kein öffentliches Issue** für Sicherheitslücken öffnen.

Eine Rückmeldung ist innerhalb weniger Tage zu erwarten - dmarcwatch ist
ein Freizeitprojekt eines Einzelnen, kein Produkt mit Security-Team und
SLA.

## Relevant

- Parsing/Deserialisierung im DMARC-XML-Pfad ([parser.py](src/dmarcwatch/parser.py),
  [archive.py](src/dmarcwatch/archive.py)) - Report-Anhänge sind
  nicht vertrauenswürdige Eingabe
- SQL-Injection oder andere Datenverarbeitungsprobleme in der
  Speicherschicht ([store.py](src/dmarcwatch/store.py))
- Injection in SwiftBar-Ausgabe, CLI-Tabellenausgabe oder
  macOS-Notifications ([sanitize.py](src/dmarcwatch/sanitize.py),
  [notify.py](src/dmarcwatch/notify.py))
- Umgang mit dem IMAP-Passwort ([keychain.py](src/dmarcwatch/keychain.py)) -
  darf nie in Logs, Prozessargumenten oder der Konfigurationsdatei landen
- Probleme in der nativen Menüleisten-App (`macapp/`), insbesondere beim
  Aufruf des Python-CLI-Subprozesses oder der Login-Item-Registrierung

## Abhängigkeiten

Bekannte Sicherheitslücken in `defusedxml` oder `keyring` selbst
(gegenüber der in [pyproject.toml](pyproject.toml) gepinnten Version)
werden nicht nur über externe Meldungen bekannt - GitHubs
Dependabot-Sicherheitswarnungen sind für dieses Repo aktiviert und melden
automatisch, wenn eine gepinnte Version eine bekannte Lücke
(GitHub Advisory Database) betrifft. Ein direktes Issue hier ist trotzdem
willkommen, falls eine Lücke schneller bekannt wird, als Dependabot sie
meldet.

## Nicht relevant

- Angriffe, die bereits physischen oder administrativen Zugriff auf einen
  kompromittierten Rechner voraussetzen
