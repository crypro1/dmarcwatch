import Foundation

/// Zustand + Validierung fürs Setup-Fenster. Baut das JSON-Payload für
/// `dmarcwatch setup --from-stdin-json` (siehe DmarcwatchCLI.runSetup) und
/// ruft es asynchron auf - alle eigentlichen Schreibzugriffe (config.json,
/// Schlüsselbund, LaunchAgent) passieren dort in der Python-Implementierung,
/// nicht hier.
final class SetupViewModel: ObservableObject {
    @Published var imapHost = "imap.mailbox.org"
    @Published var imapPort = "993"
    @Published var imapUser = ""
    @Published var imapFolder = "INBOX/DMARC"
    @Published var ownDomains = ""
    // Optional, bewusst ohne Default und ohne Pflichtfeld-Validierung (siehe
    // config.py DEFAULT_CONFIG-Kommentar zu own_ip_networks): leer = jede IP
    // gilt als unbekannt, ein sicherer, sichtbarer Zustand statt eines
    // stillen Falsch-negativs. CIDR-Validierung passiert serverseitig in
    // Config.__post_init__ (cli.py fängt ValueError ab und zeigt den Fehler
    // hier an) - keine doppelte ipaddress-Validierung in Swift.
    @Published var ownIpNetworks = ""
    @Published var password = ""
    // Uhrzeit als Date statt zweier String-Felder: ein DatePicker mit
    // .hourAndMinute ist die native macOS-Kontrolle dafür und vermeidet die
    // eigene Zahl-Validierung. (Zwei TextFields nebeneinander in einem
    // HStack innerhalb eines Form-Abschnitts hatten außerdem ein Rendering-
    // Problem: macOS' automatische Form-Beschriftung pro Kontrolle ließ die
    // Werte selbst leer erscheinen.)
    @Published var scheduleTime: Date = SetupViewModel.defaultScheduleTime
    @Published var isSaving = false
    @Published var isResolvingSpf = false
    @Published var errorMessage: String?

    var onSaved: (() -> Void)?
    var onCancel: (() -> Void)?

    /// 07:30 als Datum ohne festes Kalenderdatum - derselbe Default wie
    /// zuvor beim interaktiven CLI-Prompt (_prompt_schedule in cli.py).
    /// config.json speichert die geplante Uhrzeit nicht (nur die bereits
    /// installierte LaunchAgent-plist tut das), daher gibt es hier keinen
    /// aus der bestehenden Konfiguration vorausgefüllten Wert.
    private static var defaultScheduleTime: Date {
        Calendar.current.date(from: DateComponents(hour: 7, minute: 30)) ?? Date()
    }

    /// Werte aus der bestehenden config.json übernehmen (falls vorhanden),
    /// Passwort- und Fehlerfeld zurücksetzen - wird bei jedem Öffnen des
    /// Fensters neu aufgerufen, nicht nur einmal bei App-Start.
    func reload() {
        if let cfg = ConfigStore.loadCurrent() {
            imapHost = cfg.imapHost ?? imapHost
            if let port = cfg.imapPort { imapPort = String(port) }
            imapUser = cfg.imapUser ?? imapUser
            imapFolder = cfg.imapFolder ?? imapFolder
            if let domains = cfg.ownDomains, !domains.isEmpty {
                ownDomains = domains.joined(separator: ", ")
            }
            if let networks = cfg.ownIpNetworks, !networks.isEmpty {
                ownIpNetworks = networks.joined(separator: ", ")
            }
        }
        password = ""
        errorMessage = nil
    }

    private func currentDomains() -> [String] {
        ownDomains
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    /// Löst SPF für alle aktuell im Domain-Feld eingetragenen Domains auf
    /// und trägt das Ergebnis als Vorschlag ins Netz-Feld ein (ersetzt den
    /// bisherigen Inhalt - der Nutzer sieht das Ergebnis vor dem Speichern
    /// und kann es noch anpassen, nichts wird ungesehen übernommen).
    func resolveFromSPF() {
        errorMessage = nil
        let domains = currentDomains()
        guard !domains.isEmpty else {
            errorMessage = "Erst eine eigene Domain eintragen, dann SPF auflösen."
            return
        }

        isResolvingSpf = true
        DmarcwatchCLI.runResolveSpf(domains: domains) { [weak self] result in
            guard let self = self else { return }
            self.isResolvingSpf = false
            switch result {
            case .success(let networks):
                self.ownIpNetworks = networks.joined(separator: ", ")
            case .failure(let error):
                self.errorMessage = Self.describe(error)
            }
        }
    }

    func save() {
        errorMessage = nil

        guard let port = Int(imapPort) else {
            errorMessage = "IMAP-Port muss eine Zahl sein."
            return
        }
        let scheduleComponents = Calendar.current.dateComponents([.hour, .minute], from: scheduleTime)
        guard let hourInt = scheduleComponents.hour, let minuteInt = scheduleComponents.minute else {
            errorMessage = "Uhrzeit für den täglichen Abruf ist ungültig."
            return
        }
        let host = imapHost.trimmingCharacters(in: .whitespaces)
        let user = imapUser.trimmingCharacters(in: .whitespaces)
        let folder = imapFolder.trimmingCharacters(in: .whitespaces)
        guard !host.isEmpty, !user.isEmpty, !folder.isEmpty else {
            errorMessage = "IMAP-Server, -Login und -Ordner sind erforderlich."
            return
        }
        let domains = currentDomains()
        guard !domains.isEmpty else {
            errorMessage = "Mindestens eine eigene Domain angeben."
            return
        }
        // Leer ist ein gültiger, bewusst sicherer Zustand (siehe
        // own_ip_networks-Kommentar oben) - anders als bei own_domains hier
        // keine Pflichtfeld-Prüfung.
        let networks = ownIpNetworks
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }

        var payload: [String: Any] = [
            "imap_host": host,
            "imap_port": port,
            "imap_user": user,
            "imap_folder": folder,
            "own_domains": domains,
            "own_ip_networks": networks,
        ]
        // Leeres Feld = Passwort unverändert lassen (bereits im
        // Schlüsselbund gespeichert) statt versehentlich zu löschen.
        if !password.isEmpty {
            payload["password"] = password
        }

        isSaving = true
        DmarcwatchCLI.runSetup(payload: payload, hour: hourInt, minute: minuteInt) { [weak self] result in
            guard let self = self else { return }
            self.isSaving = false
            switch result {
            case .success:
                self.onSaved?()
            case .failure(let error):
                self.errorMessage = Self.describe(error)
            }
        }
    }

    private static func describe(_ error: Error) -> String {
        switch error {
        case CLIError.binaryNotFound(let path):
            return "dmarcwatch nicht gefunden: \(path)"
        case CLIError.processFailed(_, let stderr):
            return stderr.isEmpty ? "Speichern fehlgeschlagen." : stderr
        case CLIError.decodingFailed(let message):
            return "Antwort konnte nicht gelesen werden: \(message)"
        default:
            return error.localizedDescription
        }
    }
}
