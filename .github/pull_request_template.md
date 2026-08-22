## Was ändert sich, und warum?

<!-- Der Diff zeigt schon das "was" - hier vor allem das "warum". -->

## Checkliste

- [ ] `python -m pytest tests/ -q` läuft durch
- [ ] Bei Python-Änderungen: `pyflakes src/ tests/` ist sauber
- [ ] Bei sicherheitsrelevantem Code (Parser, SQL, Subprocess-Aufrufe): Tests decken den neuen Fall ab
- [ ] Bei Swift-Änderungen: `swift build -c release` in `macapp/DmarcwatchMenuBar` läuft durch
- [ ] Keine neue Abhängigkeit ohne vorherige Diskussion (siehe [CONTRIBUTING.md](../CONTRIBUTING.md))
