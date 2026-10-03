# Hinweise für Claude-Sessions in diesem Repo

## Commits und Veröffentlichung

- Commits tragen ausschließlich den Autor aus der `git config` des Repos
  (`user.name`/`user.email`). Ist dort keine Identität gesetzt, nicht
  committen, sondern nachfragen - nie auf eine eigene Identität ausweichen.
- Keine `Co-Authored-By`-, `Claude-Session`- oder sonstigen
  Attributionszeilen, keine Session-URLs und keine „Generated with…“-Hinweise
  in Commit-Texten oder PR-Beschreibungen.
- Nicht pushen und keine Branches oder Pull Requests anlegen, ohne dass
  ausdrücklich darum gebeten wurde. Lokal committen ist in Ordnung.
- Vor jedem Push den Diff auf persönliche Daten prüfen (siehe unten).

## Persönliche Daten

Das Repo ist öffentlich. Keine echten Domains, Mailadressen, Namen, IPs oder
Hostnamen aus dem Betrieb in Code, Kommentaren, Tests, Fixtures, Doku oder
Commit-Texten - nur Platzhalter (`example.com`, `192.0.2.0/24`,
`2001:db8::/32`).

## Entwicklung

- Vor jedem Commit müssen beide Befehle sauber durchlaufen:
  `.venv/bin/python -m pytest tests/ -q` und
  `.venv/bin/python -m pyflakes src/dmarcwatch/`.
- Neue Funktionen bekommen CLI und Menüleisten-App (`macapp/`). Swift prüfen
  mit `cd macapp/DmarcwatchMenuBar && swift build -c debug`.
- Texte, Kommentare und Doku sind deutsch. Kommentare nur dort, wo das
  Warum nicht offensichtlich ist.
- Von Anwender:innen gelesene Texte in normalem Deutsch formulieren, ohne
  interne Feld- oder Config-Namen (`own_ip_auth_fail` o. Ä.).
- Verhaltensänderungen in `README.md` und `CHANGELOG.md` nachziehen.
