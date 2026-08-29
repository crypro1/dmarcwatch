import SwiftUI

// Bewusst kein Form (siehe SetupView.swift-Kommentar zu den zwei Layout-
// Bugs dort) - ein einfacher, selbst gebauter, scrollbarer Bericht statt
// eines Formulars, da hier nichts eingegeben wird, nur Ergebnisse
// angezeigt werden.
struct DNSVerifyView: View {
    @ObservedObject var viewModel: DNSVerifyViewModel
    var onClose: () -> Void

    var body: some View {
        // Padding bewusst NICHT auf das ganze VStack, sondern nur auf
        // Titel/Fehlerzustände/Knopfzeile - die ScrollView selbst bleibt
        // ungepolstert und geht bis an den Fensterrand, sonst hängt ihre
        // eigene Scrollbar sichtbar vom rechten Rand abgesetzt in der Luft
        // statt bündig daran zu liegen. Die Content-VStack innerhalb der
        // ScrollView bekommt ihr eigenes Padding stattdessen.
        VStack(alignment: .leading, spacing: 16) {
            Text("DNS-Prüfung")
                .font(.headline)
                .padding(.horizontal, 20)
                .padding(.top, 20)

            Group {
                if viewModel.isLoading {
                    HStack(spacing: 8) {
                        ProgressView().controlSize(.small)
                        Text("Prüft DMARC/SPF/DKIM…")
                    }
                    .padding(.horizontal, 20)
                } else if let error = viewModel.errorMessage {
                    Text(error)
                        .foregroundColor(.red)
                        .font(.callout)
                        .fixedSize(horizontal: false, vertical: true)
                        .padding(.horizontal, 20)
                } else if viewModel.results.isEmpty {
                    Text("Keine Ergebnisse.")
                        .foregroundStyle(.secondary)
                        .padding(.horizontal, 20)
                } else {
                    ScrollView {
                        // Jede Domain jetzt eine eigene Karte (siehe
                        // domainSection()/group() unten) statt nur einer
                        // Trennlinie zwischen ihnen - die Karte selbst trennt
                        // schon klar genug, eine zusätzliche Divider() wäre
                        // doppelt gemoppelt.
                        VStack(alignment: .leading, spacing: 16) {
                            ForEach(viewModel.results, id: \.domain) { result in
                                domainSection(result)
                            }
                        }
                        .padding(.leading, 20)
                        .padding(.trailing, 12)
                    }
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)

            HStack {
                Spacer()
                Button("Schließen") { onClose() }
                    .keyboardShortcut(.defaultAction)
            }
            .padding(.horizontal, 20)
            .padding(.bottom, 20)
        }
        .frame(width: 700, height: 920)
    }

    @ViewBuilder
    private func domainSection(_ result: DomainVerificationResponse) -> some View {
        VStack(alignment: .leading, spacing: 11) {
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
                        let selectorLabel = dkim.selector + (dkim.keyType.map { " (\($0))" } ?? "")
                        HStack(spacing: 4) {
                            // Das Icon ist die einzige visuelle Stelle, die
                            // gefunden/nicht gefunden zeigt (kein Textwort
                            // dafür daneben) - ohne accessibilityHidden
                            // würde VoiceOver nur den rohen SF-Symbol-Namen
                            // vorlesen ("Haken Kreis") statt eines
                            // verständlichen Zustands. Das Label unten
                            // ersetzt das durch ein echtes Wort.
                            Image(systemName: dkim.exists ? "checkmark.circle" : "exclamationmark.triangle.fill")
                                .foregroundStyle(dkim.exists ? Color.secondary : Color.orange)
                                .accessibilityHidden(true)
                            Text(selectorLabel)
                                .font(.callout)
                        }
                        .accessibilityElement(children: .ignore)
                        .accessibilityLabel("\(selectorLabel), \(dkim.exists ? "gefunden" : "nicht gefunden")")
                        warnings(dkim.warnings)
                    }
                }
            }

            // MTA-STS/TLS-RPT-DNS/Wildcard-SPF sind optional - nur
            // anzeigen, wenn die Domain das überhaupt konfiguriert hat,
            // sonst unnötiges Rauschen für die meisten Domains.
            if result.mtaSts.configured {
                group("MTA-STS") {
                    detail("Ziel", result.mtaSts.cnameTarget ?? "(A/AAAA statt CNAME)")
                    detail("Policy-Eintrag", result.mtaSts.policyTxt ?? "(nicht gefunden)")
                    if let reachable = result.mtaSts.policyReachable {
                        statusPill(label: reachable ? "MTA-STS UP" : "MTA-STS DOWN", isUp: reachable)
                    }
                    warnings(result.mtaSts.warnings)
                }
            }

            if result.tlsrptDns.configured {
                group("TLS-RPT-DNS") {
                    detail("Eintrag", result.tlsrptDns.record ?? "-")
                    warnings(result.tlsrptDns.warnings)
                }
            }

            if result.wildcardSpf.configured {
                group("Wildcard-SPF") {
                    detail("Eintrag", result.wildcardSpf.record ?? "-")
                    warnings(result.wildcardSpf.warnings)
                }
            }

            // checked statt configured - kein MX heißt meist einfach, dass
            // die Domain selbst keine Mail empfängt, keine Warnung.
            if result.mxBlacklist.checked {
                group("Mailserver-Blacklist (Spamhaus ZEN)") {
                    detail("MX-Server", result.mxBlacklist.mxHosts.joined(separator: ", "))
                    statusPill(
                        label: result.mxBlacklist.listed.isEmpty ? "Spamhaus sauber" : "Spamhaus gelistet",
                        isUp: result.mxBlacklist.listed.isEmpty
                    )
                    warnings(result.mxBlacklist.warnings)
                }
            }

            if result.dnssec.configured {
                group("DNSSEC") {
                    if let validated = result.dnssec.validated {
                        statusPill(label: validated ? "DNSSEC gültig" : "DNSSEC ungültig", isUp: validated)
                    }
                    warnings(result.dnssec.warnings)
                }
            }

            if result.dane.configured {
                group("DANE/TLSA") {
                    detail("MX mit TLSA", result.dane.mxHostsWithTlsa.joined(separator: ", "))
                    // Keine eigene "validated"-Angabe wie bei DNSSEC - die
                    // Pille leitet sich direkt aus warnings ab (leer heißt
                    // hier: TLSA vorhanden UND DNSSEC validiert für alle
                    // betroffenen Hosts, siehe dns_verify.py:check_dane).
                    statusPill(
                        label: result.dane.warnings.isEmpty ? "DANE abgesichert" : "DANE eingeschränkt",
                        isUp: result.dane.warnings.isEmpty
                    )
                    warnings(result.dane.warnings)
                }
            }

            if result.bimi.configured {
                group("BIMI") {
                    detail("Eintrag", result.bimi.record ?? "-")
                    // NSImage rendert SVG-Daten direkt (empirisch mit dem
                    // echten BIMI-Logo geprüft) - so lässt sich tatsächlich
                    // sehen, ob das richtige Logo hinterlegt ist, statt nur
                    // die rohe URL zu lesen.
                    if let logoSvg = result.bimi.logoSvg,
                       let data = logoSvg.data(using: .utf8),
                       let nsImage = NSImage(data: data) {
                        Image(nsImage: nsImage)
                            .resizable()
                            .aspectRatio(contentMode: .fit)
                            .frame(width: 48, height: 48)
                            .clipShape(RoundedRectangle(cornerRadius: 6))
                    } else if result.bimi.logoReachable == false {
                        Text("Logo-Datei nicht erreichbar oder ungültig.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    warnings(result.bimi.warnings)
                }
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 10)
                .fill(Color(nsColor: .controlBackgroundColor))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 10)
                .strokeBorder(Color(nsColor: .separatorColor), lineWidth: 0.5)
        )
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
        // Ohne das liest VoiceOver Label und Wert als zwei getrennte
        // Stopps ("Policy:" - Pause - "quarantine") statt eines
        // zusammenhängenden Satzes.
        .accessibilityElement(children: .combine)
    }

    /// Grüne/rote Pille für den Ergebnis-Kurzstatus - Ergebnis eines
    /// direkten HTTPS-Abrufs der eigenen Policy-Datei (siehe
    /// dns_verify.py: _fetch_mta_sts_policy), nicht der Status eines
    /// bestimmten Hosting-Anbieters.
    private func statusPill(label: String, isUp: Bool) -> some View {
        Text(label)
            .font(.caption.bold())
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background(
                Capsule().fill(isUp ? Color.green.opacity(0.2) : Color.red.opacity(0.2))
            )
            .foregroundStyle(isUp ? Color.green : Color.red)
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
            // Gleicher Grund wie bei detail() oben - sonst liest VoiceOver
            // "Warnzeichen" und den eigentlichen Text als zwei getrennte
            // Stopps statt einer zusammenhängenden Warnung.
            .accessibilityElement(children: .combine)
        }
    }
}
