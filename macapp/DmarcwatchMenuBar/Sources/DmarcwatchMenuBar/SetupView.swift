import SwiftUI

struct SetupView: View {
    @ObservedObject var viewModel: SetupViewModel

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
    }
}
