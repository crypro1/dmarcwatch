import Foundation

/// Zustand fürs DNS-Prüfen-Fenster. Ruft `dmarcwatch verify-dns --json`
/// auf (siehe DmarcwatchCLI.runVerifyDNS) - nur nach Bestätigung im Dialog
/// ausgelöst (siehe StatusBarController.verifyDNS), nie automatisch.
final class DNSVerifyViewModel: ObservableObject {
    @Published var results: [DomainVerificationResponse] = []
    @Published var isLoading = false
    @Published var errorMessage: String?

    func run() {
        isLoading = true
        errorMessage = nil
        results = []
        DmarcwatchCLI.runVerifyDNS { [weak self] result in
            guard let self = self else { return }
            self.isLoading = false
            switch result {
            case .success(let decoded):
                self.results = decoded
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
            return stderr.isEmpty ? "Prüfung fehlgeschlagen." : stderr
        case CLIError.decodingFailed(let message):
            return "Antwort konnte nicht gelesen werden: \(message)"
        default:
            return error.localizedDescription
        }
    }
}
