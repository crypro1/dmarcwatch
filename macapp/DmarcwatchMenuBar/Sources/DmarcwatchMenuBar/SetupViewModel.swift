import Foundation

/// Zustand + Validierung fürs Setup-Fenster. Baut das JSON-Payload für
/// `dmarcwatch setup --from-stdin-json` (siehe DmarcwatchCLI.runSetup) und
/// ruft es asynchron auf - alle eigentlichen Schreibzugriffe (config.json,
/// Schlüsselbund, LaunchAgent) passieren dort in der Python-Implementierung,
/// nicht hier.
final class SetupViewModel: ObservableObject {
    // Kein Default: dmarcwatch ist ein öffentliches Projekt für beliebige
    // IMAP-Anbieter, nicht nur mailbox.org (siehe DEFAULT_CONFIG-Kommentar
    // in config.py) - ein vorbelegter fremder Hostname würde ohne genaues
    // Lesen zu einem verwirrenden Verbindungsfehler führen.
    @Published var imapHost = ""
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
    // TLS-RPT (RFC 8460) ist opt-in (siehe DEFAULT_CONFIG-Kommentar in
    // config.py): erst wenn im Postfach eine Filterregel für die
    // TLS-RPT-rua-Adresse in einen eigenen Ordner eingerichtet ist, macht
    // das Aktivieren hier Sinn - deshalb Default aus, nicht automatisch an.
    @Published var enableTlsRpt = false
    @Published var tlsrptImapFolder = "INBOX/TLS-RPT"
    // Periodischer automatischer DNS-Check (DMARC/SPF/DKIM) - Default aus,
    // das Aktivieren hier ist die einmalige Zustimmung dazu, siehe
    // enable_auto_dns_check-Kommentar in config.py.
    @Published var enableAutoDnsCheck = false
    // Als Int statt String: über einen Stepper verstellbar (wie die
    // Uhrzeit beim täglichen Abruf per DatePicker), nicht per Freitext-
    // Eingabe - Bereich 1...31 direkt über den Stepper erzwungen, keine
    // separate Validierung nötig.
    @Published var autoDnsCheckIntervalDays = 7
    // Kein config.json-Feld - direkt über SMAppService (LoginItemManager),
    // vormals ein Menüpunkt in der Statusleiste, jetzt hierher verschoben,
    // um das Menü zu entschlacken. Wendet sich sofort an, nicht erst beim
    // Speichern des restlichen Formulars (siehe applyStartAtLogin) - war
    // vorher auch ein sofort wirksamer Klick, kein Teil einer
    // Speichern/Abbrechen-Transaktion.
    @Published var startAtLogin = LoginItemManager.isEnabled
    @Published var password = ""
    // Stunde/Minute als zwei einfache Int statt eines DatePicker(Date):
    // die native .hourAndMinute-Kontrolle hat auf macOS einen Rendering-Bug
    // (die letzte Ziffer wird innerhalb der eigenen Pille abgeschnitten,
    // unabhängig von jeder SwiftUI-seitigen Breitenvorgabe) und wirkt
    // dazu inkonsistent neben dem Tage-Stepper beim DNS-Check. Zwei
    // Stepper statt dessen - gleiche Kontrolle, gleiches Aussehen.
    // 07:30 als Default - derselbe wie zuvor beim interaktiven
    // CLI-Prompt (_prompt_schedule in cli.py). config.json speichert die
    // geplante Uhrzeit nicht (nur die bereits installierte
    // LaunchAgent-plist tut das), daher kein aus der bestehenden
    // Konfiguration vorausgefüllter Wert.
    @Published var scheduleHour = 7
    @Published var scheduleMinute = 30
    @Published var isSaving = false
    @Published var isResolvingSpf = false
    @Published var errorMessage: String?

    var onSaved: (() -> Void)?
    var onCancel: (() -> Void)?

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
            enableTlsRpt = cfg.enableTlsRpt ?? enableTlsRpt
            tlsrptImapFolder = cfg.tlsrptImapFolder ?? tlsrptImapFolder
            enableAutoDnsCheck = cfg.enableAutoDnsCheck ?? enableAutoDnsCheck
            if let interval = cfg.autoDnsCheckIntervalDays { autoDnsCheckIntervalDays = min(max(interval, 1), 365) }
        }
        // Frisch von SMAppService lesen statt eines zwischengespeicherten
        // Werts - kann sich extern geändert haben (z. B. Systemeinstellungen
        // > Anmeldeobjekte).
        startAtLogin = LoginItemManager.isEnabled
        password = ""
        errorMessage = nil
    }

    /// Wendet die Login-Item-Registrierung sofort an, unabhängig vom
    /// restlichen Speichern/Abbrechen-Formular - war vorher ein einzelner
    /// Klick im Menü, kein Teil einer Transaktion. Bei Fehlschlag wird der
    /// Schalter auf den tatsächlichen Systemzustand zurückgesetzt statt auf
    /// einen zwischengespeicherten alten Wert.
    func applyStartAtLogin(_ enabled: Bool) {
        do {
            try LoginItemManager.setEnabled(enabled)
        } catch {
            errorMessage = "Anmeldeobjekt konnte nicht geändert werden: \(error)"
            startAtLogin = LoginItemManager.isEnabled
        }
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

        let tlsrptFolder = tlsrptImapFolder.trimmingCharacters(in: .whitespaces)
        if enableTlsRpt && tlsrptFolder.isEmpty {
            errorMessage = "TLS-RPT-Ordner ist erforderlich, wenn TLS-RPT-Auswertung aktiv ist."
            return
        }
        var payload: [String: Any] = [
            "imap_host": host,
            "imap_port": port,
            "imap_user": user,
            "imap_folder": folder,
            "own_domains": domains,
            "own_ip_networks": networks,
            "enable_tls_rpt": enableTlsRpt,
            "tlsrpt_imap_folder": tlsrptFolder,
            "enable_auto_dns_check": enableAutoDnsCheck,
            "auto_dns_check_interval_days": autoDnsCheckIntervalDays,
        ]
        // Leeres Feld = Passwort unverändert lassen (bereits im
        // Schlüsselbund gespeichert) statt versehentlich zu löschen.
        if !password.isEmpty {
            payload["password"] = password
        }

        isSaving = true
        DmarcwatchCLI.runSetup(payload: payload, hour: scheduleHour, minute: scheduleMinute) { [weak self] result in
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
