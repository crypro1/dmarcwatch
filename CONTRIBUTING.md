# Beitragen zu dmarcwatch

Danke für dein Interesse! dmarcwatch ist ein kleines, von einer Einzelperson
gepflegtes Freizeitprojekt - entsprechend pragmatisch sind auch die
Regeln hier.

**Sicherheitslücken bitte nicht als Issue oder PR** - siehe stattdessen
[SECURITY.md](SECURITY.md) für den privaten Meldeweg.

## Bevor du anfängst

Bei größeren Änderungen (neue Abhängigkeit, neues Feature, Architektur-
Umbau) lieber erst ein Issue aufmachen und kurz die Idee beschreiben,
bevor viel Arbeit in einen PR fließt, der am Ende nicht zum Projekt passt.
Kleine Bugfixes, Tippfehler, zusätzliche Tests: einfach direkt als PR.

## Entwicklungsumgebung

```bash
cd dmarcwatch
python3 -m venv .venv          # Python 3.10 oder neuer, siehe README
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -e ".[dev]"
```

Für die native Menüleisten-App zusätzlich Xcode Command Line Tools
(`xcode-select --install`) - siehe
[README: Native Menüleisten-App](README.md#native-menüleisten-app).

## Tests

```bash
.venv/bin/python -m pytest tests/ -q
```

Ein PR, der Python-Code ändert, sollte die bestehenden Tests nicht
brechen und - wo sinnvoll - neue Tests für das geänderte Verhalten
mitbringen. Besonders bei sicherheitsrelevantem Code (Parser, SQL,
Subprocess-Aufrufe) sind Tests kein Nice-to-have, siehe
[README: Sicherheitsentscheidungen](README.md#sicherheitsentscheidungen).

Für Swift-Änderungen: `cd macapp/DmarcwatchMenuBar && swift build -c
release` sollte fehlerfrei durchlaufen. Automatisierte UI-Tests gibt es
aktuell nicht - manuell mit `./build_app.sh && open
DmarcwatchMenuBar.app` gegenprüfen.

## Konventionen

- **Kommentare und Nutzertexte auf Deutsch**, konsistent mit dem Rest des
  Projekts (siehe auch die Notiz zu Lokalisierung weiter unten).
- **Keine neuen Abhängigkeiten ohne Diskussion.** Das Projekt hält sich
  bewusst an `defusedxml` und `keyring` plus Standardbibliothek (siehe
  README). Für einen neuen Bedarf lieber zuerst prüfen, ob sich das mit
  einem bereits vorhandenen Systemwerkzeug per `subprocess` lösen lässt
  (wie z. B. `dig` für die SPF-Auflösung), bevor eine neue Bibliothek
  vorgeschlagen wird.
- **Reports/Nutzereingaben sind nicht vertrauenswürdig.** Jeder kann eine
  Mail an die `rua`-Adresse schicken - Code, der Report-Inhalte
  verarbeitet, muss das als Angriffsfläche behandeln (keine
  String-Verkettung in SQL, keine `shell=True`, Größenlimits vor dem
  eigentlichen Verarbeiten prüfen, etc.).
- **Kein `shell=True`, keine Befehlszusammensetzung aus Strings** bei
  `subprocess`-Aufrufen - immer eine Argumentliste.

## Lokalisierung

Aktuell komplett Deutsch (UI-Texte, CLI-Ausgaben, Dokumentation) - das ist
eine bewusste, vorerst nicht geänderte Entscheidung, kein Zufall. Ein PR,
der Übersetzungsinfrastruktur einführt, ist grundsätzlich willkommen,
sollte aber vorher als Issue besprochen werden, da es quer durch beide
Codebasen (Python + Swift) geht.

## Pull Requests

- Möglichst kleine, fokussierte PRs statt große Sammel-PRs.
- Kurze Beschreibung, *warum* die Änderung sinnvoll ist, nicht nur *was*
  sich ändert (das zeigt der Diff schon).
- `python -m pytest` und (bei Python-Änderungen) `pyflakes src/ tests/`
  laufen lassen, bevor der PR aufgemacht wird.

## Lizenz

Mit einem Beitrag stimmst du zu, dass er unter derselben Lizenz wie das
Projekt steht ([PolyForm Noncommercial 1.0.0](LICENSE)).
