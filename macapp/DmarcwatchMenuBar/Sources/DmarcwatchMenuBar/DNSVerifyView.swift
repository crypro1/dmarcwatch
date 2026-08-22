import SwiftUI

// Bewusst kein Form (siehe SetupView.swift-Kommentar zu den zwei Layout-
// Bugs dort) - ein einfacher, selbst gebauter, scrollbarer Bericht statt
// eines Formulars, da hier nichts eingegeben wird, nur Ergebnisse
// angezeigt werden.
struct DNSVerifyView: View {
    @ObservedObject var viewModel: DNSVerifyViewModel
    var onClose: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("DNS-Prüfung")
                .font(.headline)

            Group {
                if viewModel.isLoading {
                    HStack(spacing: 8) {
                        ProgressView().controlSize(.small)
                        Text("Prüft DMARC/SPF/DKIM…")
                    }
                } else if let error = viewModel.errorMessage {
                    Text(error)
                        .foregroundColor(.red)
                        .font(.callout)
                        .fixedSize(horizontal: false, vertical: true)
                } else if viewModel.results.isEmpty {
                    Text("Keine Ergebnisse.")
                        .foregroundStyle(.secondary)
                } else {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 20) {
                            // Trennlinie nur ZWISCHEN Domains, nicht nach der
                            // letzten (sonst hängt sie vor dem
                            // "Schließen"-Knopf frei in der Luft).
                            ForEach(Array(viewModel.results.enumerated()), id: \.element.domain) { index, result in
                                domainSection(result)
                                if index < viewModel.results.count - 1 {
                                    Divider()
                                }
                            }
                        }
                        .padding(.trailing, 4)
                    }
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)

            HStack {
                Spacer()
                Button("Schließen") { onClose() }
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 520, height: 480)
    }

    @ViewBuilder
    private func domainSection(_ result: DomainVerificationResponse) -> some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(result.domain)
                .font(.title3.bold())

            group("DMARC") {
                if result.dmarc.exists {
                    detail("Policy", result.dmarc.policy ?? "-")
                    if let sp = result.dmarc.subdomainPolicy {
                        detail("Subdomain", sp)
                    }
                    if let pct = result.dmarc.pct {
                        detail("Prozent", "\(pct)")
                    }
                    detail("rua", result.dmarc.rua ?? "(nicht gesetzt)")
                    detail("ruf", result.dmarc.ruf ?? "(nicht gesetzt)")
                }
                warnings(result.dmarc.warnings)
            }

            group("SPF") {
                if result.spf.exists {
                    detail("Eintrag", result.spf.record ?? "-")
                    detail("DNS-Lookups", "\(result.spf.lookupCount)/10")
                } else if let error = result.spf.error {
                    detail("Fehler", error)
                }
                warnings(result.spf.warnings)
            }

            group("DKIM") {
                if result.dkim.isEmpty {
                    Text(
                        "Keine bekannten Selektoren - werden aus bereits abgerufenen " +
                        "Reports gelernt (dmarcwatch fetch), noch keine vorhanden."
                    )
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                }
                ForEach(result.dkim, id: \.selector) { dkim in
                    VStack(alignment: .leading, spacing: 2) {
                        HStack(spacing: 4) {
                            Image(systemName: dkim.exists ? "checkmark.circle" : "exclamationmark.triangle.fill")
                                .foregroundStyle(dkim.exists ? Color.secondary : Color.orange)
                            Text(dkim.selector + (dkim.keyType.map { " (\($0))" } ?? ""))
                                .font(.callout)
                        }
                        warnings(dkim.warnings)
                    }
                }
            }
        }
    }

    @ViewBuilder
    private func group<Content: View>(_ title: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.subheadline.bold())
            content()
        }
    }

    private func detail(_ label: String, _ value: String) -> some View {
        HStack(alignment: .top, spacing: 4) {
            Text(label + ":").foregroundStyle(.secondary)
            Text(value)
                .fixedSize(horizontal: false, vertical: true)
                .textSelection(.enabled)
        }
        .font(.callout)
    }

    @ViewBuilder
    private func warnings(_ items: [String]) -> some View {
        ForEach(items, id: \.self) { warning in
            HStack(alignment: .top, spacing: 4) {
                Text("⚠").foregroundColor(.orange)
                Text(warning)
                    .font(.caption)
                    .foregroundColor(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}
