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
                    TextField("Login (echtes Postfach)", text: $viewModel.imapUser)
                    SecureField("App-Passwort (leer = unverändert)", text: $viewModel.password)
                    TextField("Ordner", text: $viewModel.imapFolder)
                }
                Section("Eigene Domain(s)") {
                    TextField("kommagetrennt", text: $viewModel.ownDomains)
                }
                Section("Eigene Sende-Netze (optional)") {
                    TextField("CIDR, kommagetrennt - z. B. 80.241.56.0/21", text: $viewModel.ownIpNetworks)
                    Button(viewModel.isResolvingSpf ? "Fragt SPF ab…" : "Aus SPF ermitteln…") {
                        showSPFConfirmation = true
                    }
                    .disabled(viewModel.isResolvingSpf)
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
        .frame(width: 440)
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
}
