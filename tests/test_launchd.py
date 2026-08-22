import plistlib

from dmarcwatch.launchd import LABEL, build_plist


def test_plist_has_no_credentials_and_correct_schedule():
    data = build_plist("/opt/homebrew/bin/python3.14", hour=6, minute=15)
    parsed = plistlib.loads(data)

    assert parsed["Label"] == LABEL
    assert parsed["ProgramArguments"] == [
        "/opt/homebrew/bin/python3.14",
        "-m",
        "dmarcwatch",
        "fetch",
        "--skip-if-already-run-today",
    ]
    assert parsed["StartCalendarInterval"] == {"Hour": 6, "Minute": 15}
    # Bewusst kein RunAtLoad: das würde in Systemeinstellungen >
    # Anmeldeobjekte als unbeschriftetes "python3, unbekannter Entwickler"
    # auftauchen. Das Nachholen eines wegen ausgeschaltetem Mac verpassten
    # Termins übernimmt stattdessen die Menüleisten-App bei ihrem eigenen
    # Start (siehe macapp/.../main.swift), mit demselben
    # --skip-if-already-run-today-Flag.
    assert parsed["RunAtLoad"] is False

    # Backstop gegen ausufernde CPU-Zeit, aus echten Messungen abgeleitet
    # (siehe launchd.py) - fetch ist ein kurzlebiger Prozess, also pro Lauf.
    # Nur Soft-Limit: das Hard-Limit erwies sich beim Testen als wirkungslos
    # auf macOS (kein SIGKILL, siehe launchd.py-Kommentar).
    assert parsed["SoftResourceLimits"] == {"CPU": 1}
    assert "HardResourceLimits" not in parsed

    # Keine Zugangsdaten dürfen jemals in die plist gelangen.
    rendered = data.decode("utf-8", errors="ignore")
    assert "password" not in rendered.lower()
    assert "EnvironmentVariables" not in parsed
