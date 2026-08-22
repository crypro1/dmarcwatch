import ServiceManagement

// Ersetzt die frühere plist-basierte Installation (launchd.py
// install_menubar(), inzwischen entfernt): SMAppService.mainApp
// registriert direkt DIESE App als Login-Item bei Launch Services, nicht
// nur eine rohe Programm-Pfad-Referenz in einer separaten plist. Deshalb
// zeigt System Settings > Anmeldeobjekte jetzt das echte App-Icon statt
// eines generischen Symbols - legacy launchd-Agents werden dort nur mit
// Platzhalter-Icon angezeigt, unabhängig davon, ob ihr Ziel-Pfad in ein
// Bundle mit echtem Icon zeigt.
//
// Kompromiss gegenüber der alten Lösung: kein KeepAlive-Neustart bei
// Absturz mehr, SMAppService startet nur einmal bei der Anmeldung. Für ein
// reines Anzeige-Utility (keine kritische Hintergrundaufgabe) ist das
// hinnehmbar.
enum LoginItemManager {
    static var isEnabled: Bool {
        SMAppService.mainApp.status == .enabled
    }

    static func setEnabled(_ enabled: Bool) throws {
        if enabled {
            guard SMAppService.mainApp.status != .enabled else { return }
            try SMAppService.mainApp.register()
        } else {
            guard SMAppService.mainApp.status == .enabled else { return }
            try SMAppService.mainApp.unregister()
        }
    }
}
