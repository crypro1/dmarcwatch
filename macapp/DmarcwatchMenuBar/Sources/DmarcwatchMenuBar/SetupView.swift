import SwiftUI

// Bewusst KEIN Form/Section/LabeledContent: macOS' automatische
// Form-Beschriftungsspalte hat hier zweimal zu Layout-Bugs geführt (Uhrzeit-
// Felder, die leer wirkten; ein zu langer Feld-Titel, der das ganze Fenster
// inklusive Titelleiste abschnitt) - beide Male, weil Form intern Annahmen
// über Spaltenbreite/Beschriftung trifft, die sich nicht vorhersagbar
// verhalten, sobald Zusatztext (Hinweise, Knöpfe) neben einem Feld steht.
// Stattdessen: ein einfacher, selbst gebauter Aufbau mit Label über Feld -
// jede Zeile ist ein VStack(alignment: .leading), alle also garantiert
// bündig am selben linken Rand, ohne verstecktes Spalten-Layout.
struct SetupView: View {
    @ObservedObject var viewModel: SetupViewModel
    @State private var showSPFConfirmation = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("dmarcwatch einrichten")
                .font(.headline)

            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    group("IMAP") {
                        field("Server", text: $viewModel.imapHost)
                        field("Port", text: $viewModel.imapPort)
                        field(
                            "Login", text: $viewModel.imapUser,
                            hint: "Echtes Postfach, nicht die rua-Alias-Adresse aus dem DMARC-DNS-Eintrag."
                        )
                        secureField(
                            "Passwort", text: $viewModel.password,
                            hint: "Leer lassen, um das gespeicherte Passwort zu behalten."
                        )
                        field("Ordner", text: $viewModel.imapFolder)
                    }

                    group("Domain & Sende-Netze") {
                        field(
                            "Eigene Domain(s)", text: $viewModel.ownDomains,
                            hint: "Kommagetrennt, z. B. example.com, example.org"
                        )
                        field(
                            "Eigene Sende-Netze (optional)", text: $viewModel.ownIpNetworks,
                            hint: "CIDR, kommagetrennt - z. B. 192.0.2.0/24"
                        )
                        Button(viewModel.isResolvingSpf ? "Fragt SPF ab…" : "Aus SPF ermitteln…") {
                            showSPFConfirmation = true
                        }
                        .disabled(viewModel.isResolvingSpf)
                    }

                    group("Täglicher Abruf") {
                        DatePicker(
                            "Uhrzeit", selection: $viewModel.scheduleTime,
                            displayedComponents: .hourAndMinute
                        )
                        // Wirkt sofort (SMAppService), nicht erst beim
                        // Speichern des restlichen Formulars - siehe
                        // applyStartAtLogin-Kommentar im ViewModel.
                        Toggle("Automatisch bei Anmeldung starten", isOn: $viewModel.startAtLogin)
                            .onChange(of: viewModel.startAtLogin) { newValue in
                                viewModel.applyStartAtLogin(newValue)
                            }
                    }

                    group("TLS-RPT (optional)") {
                        Toggle("TLS-RPT-Auswertung aktivieren", isOn: $viewModel.enableTlsRpt)
                        // Ordnerfeld bewusst IMMER sichtbar, nicht erst nach
                        // dem Einschalten: die Postfach-Filterregel muss
                        // zuerst eingerichtet werden, dafür muss man den
                        // Ordnernamen schon vorher kennen/bestätigen können,
                        // nicht erst danach.
                        field(
                            "TLS-RPT-Ordner", text: $viewModel.tlsrptImapFolder,
                            hint: "Zuerst im Postfach eine Filterregel einrichten, die Mail an die " +
                                "TLS-RPT-rua-Adresse in genau diesen Ordner einsortiert - dann hier " +
                                "aktivieren."
                        )
                    }

                    group("DNS-Check (optional)") {
                        Toggle("Automatischen DNS-Check aktivieren", isOn: $viewModel.enableAutoDnsCheck)
                        Text(
                            "Prüft periodisch die eigenen DMARC-/SPF-/DKIM-DNS-Einträge, huckepack im " +
                            "ohnehin täglichen Abruf - dasselbe wie \"DNS prüfen…\" im Menü, nur " +
                            "automatisch statt nur auf Klick."
                        )
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                        // Stepper statt Freitext - wie die Uhrzeit beim
                        // täglichen Abruf per DatePicker verstellbar, ohne
                        // künstliche Obergrenze (ein Tageslimit wäre für ein
                        // Intervall willkürlich) - nur ein großzügiger
                        // Rahmen (1...365) statt einer eigenen Zahl-
                        // Validierung.
                        Stepper(
                            "Intervall: alle \(viewModel.autoDnsCheckIntervalDays) Tage",
                            value: $viewModel.autoDnsCheckIntervalDays, in: 1...365
                        )
                    }
                }
                .padding(.trailing, 4)  // Platz für die Scrollbar, nichts wird davon verdeckt
            }

            if let error = viewModel.errorMessage {
                Text(error)
                    .foregroundColor(.red)
                    .font(.callout)
                    .fixedSize(horizontal: false, vertical: true)
            }

            HStack {
                Spacer()
                Button("Abbrechen") { viewModel.onCancel?() }
                    .keyboardShortcut(.cancelAction)
                Button(viewModel.isSaving ? "Speichert…" : "Speichern") { viewModel.save() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(viewModel.isSaving)
            }
        }
        .padding(20)
        .frame(width: 480, height: 560)
        // Wie beim WHOIS-Knopf im Menü: DNS-Abfrage geht wirklich nach
        // außen, deshalb erst nach expliziter Bestätigung, nie automatisch
        // beim Eintippen der Domain.
        .alert("SPF-Einträge abfragen?", isPresented: $showSPFConfirmation) {
            Button("Abbrechen", role: .cancel) {}
            Button("Abfragen") { viewModel.resolveFromSPF() }
        } message: {
            Text(
                "Fragt den SPF-DNS-Eintrag der eingetragenen Domain(s) ab - das verlässt dein " +
                "Gerät. Das Ergebnis wird nur als Vorschlag eingetragen, du kannst es vor dem " +
                "Speichern noch anpassen."
            )
        }
    }

    /// Eine Gruppe von Feldern mit gemeinsamer Überschrift - rein visuell,
    /// kein Form-Section mit eigener Spaltenlogik.
    @ViewBuilder
    private func group<Content: View>(_ title: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(title)
                .font(.subheadline.bold())
                .foregroundStyle(.secondary)
            content()
        }
    }

    /// Label über dem Feld statt daneben - vermeidet jede Spaltenbreiten-
    /// Berechnung komplett. `.fixedSize` auf dem Hinweistext erzwingt
    /// Zeilenumbruch statt Abschneiden mit "…" bei längeren Erklärungen.
    private func field(_ label: String, text: Binding<String>, hint: String? = nil) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label).font(.callout)
            TextField("", text: text)
                .textFieldStyle(.roundedBorder)
            if let hint {
                Text(hint)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private func secureField(_ label: String, text: Binding<String>, hint: String? = nil) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label).font(.callout)
            SecureField("", text: text)
                .textFieldStyle(.roundedBorder)
            if let hint {
                Text(hint)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}
