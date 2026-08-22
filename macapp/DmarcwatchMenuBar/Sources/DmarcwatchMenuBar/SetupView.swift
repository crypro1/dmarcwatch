import SwiftUI

struct SetupView: View {
    @ObservedObject var viewModel: SetupViewModel
    @State private var showSPFConfirmation = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("dmarcwatch einrichten")
                .font(.headline)

            Form {
                Section("IMAP") {
                    TextField("Server", text: $viewModel.imapHost)
                    TextField("Port", text: $viewModel.imapPort)
                    LabeledContent("Login") {
                        VStack(alignment: .leading, spacing: 2) {
                            TextField("", text: $viewModel.imapUser)
                            hint("Echtes Postfach, nicht die rua-Alias-Adresse aus dem DMARC-DNS-Eintrag.")
                        }
                    }
                    LabeledContent("Passwort") {
                        VStack(alignment: .leading, spacing: 2) {
                            SecureField("", text: $viewModel.password)
                            hint("Leer lassen, um das gespeicherte Passwort zu behalten.")
                        }
                    }
                    TextField("Ordner", text: $viewModel.imapFolder)
                }
                Section("Eigene Domain(s)") {
                    LabeledContent("Domain(s)") {
                        VStack(alignment: .leading, spacing: 2) {
                            TextField("", text: $viewModel.ownDomains)
                            hint("Kommagetrennt, z. B. example.com, example.org")
                        }
                    }
                }
                Section("Eigene Sende-Netze (optional)") {
                    LabeledContent("Sende-Netze") {
                        VStack(alignment: .leading, spacing: 6) {
                            TextField("", text: $viewModel.ownIpNetworks)
                            hint("CIDR, kommagetrennt - z. B. 80.241.56.0/21")
                            Button(viewModel.isResolvingSpf ? "Fragt SPF ab…" : "Aus SPF ermitteln…") {
                                showSPFConfirmation = true
                            }
                            .disabled(viewModel.isResolvingSpf)
                        }
                    }
                }
                Section("Täglicher Abruf") {
                    DatePicker(
                        "Uhrzeit", selection: $viewModel.scheduleTime, displayedComponents: .hourAndMinute
                    )
                }
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
        .frame(width: 480)
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

    /// Erklärtext unter einem Feld statt in dessen Titel - der TextField-Titel
    /// wird in einem macOS-Form zur linken Beschriftungsspalte, ein langer
    /// String dort (z. B. "CIDR, kommagetrennt - z. B. 80.241.56.0/21")
    /// sprengt die Spaltenbreite und lässt das ganze Fenster (inklusive
    /// Titelleiste) abgeschnitten wirken. Wird zusammen mit dem Feld in ein
    /// LabeledContent + VStack gepackt (siehe oben), statt als eigene
    /// Form-Zeile - sonst würde die Zeile bündig am linken Fensterrand
    /// beginnen statt unter dem Feld, das sie erklärt.
    private func hint(_ text: String) -> some View {
        Text(text)
            .font(.caption)
            .foregroundStyle(.secondary)
    }
}
