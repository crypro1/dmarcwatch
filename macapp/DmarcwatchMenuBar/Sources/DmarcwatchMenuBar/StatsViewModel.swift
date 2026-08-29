import Foundation

/// Zustand fürs Statistik-Fenster. Ruft `dmarcwatch stats --json` auf
/// (siehe DmarcwatchCLI.runStats) - reines Lesen der lokalen DB, kein
/// Netzzugriff, deshalb ohne Bestätigungsdialog beim Öffnen (anders als
/// DNSVerifyViewModel).
final class StatsViewModel: ObservableObject {
    @Published var response: StatsResponse?
    @Published var isLoading = false
    @Published var errorMessage: String?
    // 30 statt 7 Tage - für eine sinnvolle Verschärfungs-Einschätzung
    // braucht es mehr als eine Woche Beobachtungszeitraum, gleicher
    // Default wie beim `stats`-CLI-Befehl selbst.
    @Published var days = 30

    func run() {
        isLoading = true
        errorMessage = nil
        DmarcwatchCLI.runStats(days: days) { [weak self] result in
            guard let self = self else { return }
            self.isLoading = false
            switch result {
            case .success(let decoded):
                self.response = decoded
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
            return stderr.isEmpty ? "Statistik konnte nicht geladen werden." : stderr
        case CLIError.decodingFailed(let message):
            return "Antwort konnte nicht gelesen werden: \(message)"
        default:
            return error.localizedDescription
        }
    }
}
