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
                        // Zwei Stepper statt DatePicker - siehe Kommentar
                        // bei scheduleHour/scheduleMinute im ViewModel.
                        // Gleicher Aufbau wie "Intervall: alle X Tage" beim
                        // DNS-Check unten, für ein einheitliches Bild statt
                        // einer nativen Pille an nur dieser einen Stelle.
                        HStack(spacing: 20) {
                            Stepper(
                                "Stunde: \(String(format: "%02d", viewModel.scheduleHour))",
                                value: $viewModel.scheduleHour, in: 0...23
                            )
                            Stepper(
                                "Minute: \(String(format: "%02d", viewModel.scheduleMinute))",
                                value: $viewModel.scheduleMinute, in: 0...59
                            )
                        }
                        // Wirkt sofort (SMAppService), nicht erst beim
                        // Speichern des restlichen Formulars - siehe
                        // applyStartAtLogin-Kommentar im ViewModel.
                        Toggle("Automatisch bei Anmeldung starten", isOn: $viewModel.startAtLogin)
                            .onChange(of: viewModel.startAtLogin) {
                                viewModel.applyStartAtLogin(viewModel.startAtLogin)
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
        .frame(width: 520, height: 580)
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

    /// Eine Gruppe von Feldern mit gemeinsamer Überschrift, als abgesetzte
    /// Karte (wie die gruppierten Boxen in System Settings.app seit
    /// Ventura) statt reiner Überschrift-mit-Einzug - rein visuell über
    /// background/overlay auf dem bestehenden VStack, KEIN Form/Section
    /// (siehe Kommentar oben zu den zwei echten Layout-Bugs damit).
    @ViewBuilder
    private func group<Content: View>(_ title: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(title)
                .font(.subheadline.bold())
                .foregroundStyle(.secondary)
            content()
        }
        .padding(14)
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

    /// Label über dem Feld statt daneben - vermeidet jede Spaltenbreiten-
    /// Berechnung komplett. `.fixedSize` auf dem Hinweistext erzwingt
    /// Zeilenumbruch statt Abschneiden mit "…" bei längeren Erklärungen.
    private func field(_ label: String, text: Binding<String>, hint: String? = nil) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label).font(.callout)
            // Ohne dieses Label liest VoiceOver hier nur "Textfeld" vor -
            // der leere Platzhalter ("") in TextField selbst reicht dafür
            // nicht, das sichtbare Text(label) darüber ist rein visuell
            // ohne diese explizite Verknüpfung.
            TextField("", text: text)
                .textFieldStyle(.roundedBorder)
                .accessibilityLabel(label)
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
                .accessibilityLabel(label)
            if let hint {
                Text(hint)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}
