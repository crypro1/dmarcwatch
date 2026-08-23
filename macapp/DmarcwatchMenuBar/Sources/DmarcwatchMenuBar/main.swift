import AppKit
import ServiceManagement

// Kommandozeilen-Kurzpfade für Skripte/Diagnose, ohne Statusleisten-Icon
// oder Run-Loop aufzubauen - die App selbst nutzt für denselben Zweck den
// Schalter "Automatisch starten" in den Einstellungen (SetupView.swift,
// LoginItemManager.swift).
//
// --unregister-login-item: reiner Aufräum-Pfad für uninstall.sh - die App
// entfernen, während sie noch als Login-Item registriert ist, würde eine
// tote Referenz auf einen gelöschten Bundle-Pfad hinterlassen.
if CommandLine.arguments.contains("--unregister-login-item") {
    try? SMAppService.mainApp.unregister()
    exit(0)
}
if CommandLine.arguments.contains("--register-login-item") {
    do {
        try LoginItemManager.setEnabled(true)
        exit(0)
    } catch {
        FileHandle.standardError.write("Registrierung fehlgeschlagen: \(error)\n".data(using: .utf8)!)
        exit(1)
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    private var statusBarController: StatusBarController?

    func applicationDidFinishLaunching(_ notification: Notification) {
        // .accessory: reines Menüleisten-Utility, kein Dock-Icon, kein
        // Fenster, kein Cmd-Tab-Eintrag.
        NSApp.setActivationPolicy(.accessory)
        statusBarController = StatusBarController()

        // Holt einen wegen ausgeschaltetem/schlafendem Mac verpassten
        // taeglichen Abruf nach, sobald die App startet (bei "Bei
        // Anmeldung starten" oder einfach beim naechsten manuellen
        // Oeffnen) - launchd holt einen verpassten
        // StartCalendarInterval-Termin nicht von selbst nach. Bewusst
        // hier statt per RunAtLoad auf dem fetch-LaunchAgent selbst, das
        // wuerde als unbeschriftetes "python3, unbekannter Entwickler" in
        // Systemeinstellungen > Anmeldeobjekte auftauchen (siehe
        // launchd.py-Kommentar). --skip-if-already-run-today verhindert
        // einen unnoetigen doppelten IMAP-Check, falls heute schon einer
        // lief.
        DmarcwatchCLI.runFetchAsync(skipIfAlreadyRunToday: true) { [weak self] _ in
            self?.statusBarController?.refresh(nil)
        }
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.run()
