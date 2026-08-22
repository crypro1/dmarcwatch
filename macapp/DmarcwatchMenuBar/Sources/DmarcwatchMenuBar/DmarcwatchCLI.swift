import Foundation

// Bruecke zum Python-CLI. Diese App liest nur lokal (menubar-json liest die
// bereits von `dmarcwatch fetch` gefuellte SQLite-DB, keine eigene
// IMAP-Verbindung) und stoesst optional manuell einen `fetch`-Lauf an.
// runInspectWhois() ist die einzige Ausnahme, bei der ein Klick tatsaechlich
// eine Netzwerkanfrage nach aussen ausloest (RDAP an rdap.org) - immer erst
// nach einer expliziten Bestaetigung im Dialog (siehe
// StatusBarController.lookupWhois), nie automatisch im Hintergrund.
// Bewusst kein App Sandbox: die App muss einen beliebigen lokalen Pfad
// (die Python-venv) ausfuehren koennen, das steht im Widerspruch zu
// Sandbox-Restriktionen fuer Kindprozesse. Siehe README dieses Ordners.

enum CLIError: Error {
    case binaryNotFound(String)
    case processFailed(Int32, String)
    case decodingFailed(String)
}

enum DmarcwatchCLI {
    /// Pfad zur installierten dmarcwatch-venv. Ueberschreibbar per
    /// DMARCWATCH_HOME env var, gleiche Konvention wie das SwiftBar-Plugin
    /// (swiftbar/dmarcwatch.10m.sh).
    static func resolveBinaryPath() -> String {
        if let override = ProcessInfo.processInfo.environment["DMARCWATCH_HOME"], !override.isEmpty {
            return override + "/.venv/bin/dmarcwatch"
        }
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        return home + "/dmarcwatch/.venv/bin/dmarcwatch"
    }

    static func run(
        arguments: [String], stdinData: Data? = nil
    ) throws -> (exitCode: Int32, stdout: String, stderr: String) {
        let binaryPath = resolveBinaryPath()
        guard FileManager.default.isExecutableFile(atPath: binaryPath) else {
            throw CLIError.binaryNotFound(binaryPath)
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: binaryPath)
        process.arguments = arguments

        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        let stdinPipe = Pipe()
        if stdinData != nil {
            process.standardInput = stdinPipe
        }

        try process.run()
        if let stdinData = stdinData {
            // Erst schreiben, dann schließen (EOF) - sonst blockiert der
            // Python-seitige sys.stdin.read() unbegrenzt.
            stdinPipe.fileHandleForWriting.write(stdinData)
            stdinPipe.fileHandleForWriting.closeFile()
        }
        process.waitUntilExit()

        let stdoutData = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
        let stderrData = stderrPipe.fileHandleForReading.readDataToEndOfFile()

        let stdout = String(data: stdoutData, encoding: .utf8) ?? ""
        let stderr = String(data: stderrData, encoding: .utf8) ?? ""

        return (process.terminationStatus, stdout, stderr)
    }

    static func fetchMenubarReport() throws -> MenubarReport {
        let result = try run(arguments: ["menubar-json"])
        guard result.exitCode == 0 else {
            throw CLIError.processFailed(result.exitCode, result.stderr)
        }
        guard let data = result.stdout.data(using: .utf8) else {
            throw CLIError.decodingFailed("Ausgabe war kein gültiges UTF-8")
        }
        do {
            return try JSONDecoder().decode(MenubarReport.self, from: data)
        } catch {
            throw CLIError.decodingFailed("\(error)")
        }
    }

    /// Ruft `dmarcwatch setup --from-stdin-json --install-agent` auf: die
    /// Setup-GUI schickt Konfiguration + optionales Passwort als ein
    /// JSON-Objekt ueber stdin, nie als Kommandozeilenargument (gleiche
    /// Begruendung wie beim interaktiven CLI-Passwort-Prompt: Prozesslisten
    /// sind fuer andere lokale Nutzer sichtbar). Alle Schreibzugriffe
    /// (config.json, Schluesselbund, LaunchAgent-Plist) bleiben dadurch in
    /// der bereits gehaerteten Python-Implementierung, nicht dupliziert.
    static func runSetup(
        payload: [String: Any], hour: Int, minute: Int,
        completion: @escaping (Result<String, Error>) -> Void
    ) {
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let jsonData = try JSONSerialization.data(withJSONObject: payload)
                let arguments = [
                    "setup", "--from-stdin-json",
                    "--install-agent", "--hour", "\(hour)", "--minute", "\(minute)",
                ]
                let result = try run(arguments: arguments, stdinData: jsonData)
                if result.exitCode == 0 {
                    DispatchQueue.main.async { completion(.success(result.stdout)) }
                } else {
                    DispatchQueue.main.async {
                        completion(.failure(CLIError.processFailed(result.exitCode, result.stderr)))
                    }
                }
            } catch {
                DispatchQueue.main.async { completion(.failure(error)) }
            }
        }
    }

    /// Nutzerausgeloeste WHOIS-Abfrage fuer genau eine IP, aus dem Dropdown
    /// eines auffaelligen Records - erst nach Bestaetigung im Dialog. Speichert
    /// das Ergebnis ueber denselben Weg wie die manuelle Terminal-Nutzung
    /// (set_cached_whois in der lokalen DB), die App liest es beim naechsten
    /// Refresh einfach mit.
    static func runInspectWhois(ip: String, completion: @escaping (Result<String, Error>) -> Void) {
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let result = try run(arguments: ["inspect", ip, "--whois"])
                if result.exitCode == 0 {
                    DispatchQueue.main.async { completion(.success(result.stdout)) }
                } else {
                    DispatchQueue.main.async {
                        completion(.failure(CLIError.processFailed(result.exitCode, result.stderr)))
                    }
                }
            } catch {
                DispatchQueue.main.async { completion(.failure(error)) }
            }
        }
    }

    /// `fetch` verbindet sich per IMAP und kann mehrere Sekunden dauern -
    /// laeuft deshalb im Hintergrund, die Menuleiste blockiert nicht.
    ///
    /// skipIfAlreadyRunToday: von main.swift beim App-Start genutzt, um
    /// einen wegen ausgeschaltetem Mac verpassten taeglichen Abruf
    /// nachzuholen (launchd holt einen verpassten StartCalendarInterval-
    /// Termin NICHT von selbst nach) - ohne dafuer den fetch-LaunchAgent
    /// selbst per RunAtLoad als unbeschriftetes "python3"-Anmeldeobjekt in
    /// den Systemeinstellungen auftauchen zu lassen (siehe launchd.py).
    /// "Jetzt abrufen" im Menu laesst das Flag weg und prueft immer
    /// tatsaechlich.
    static func runFetchAsync(
        skipIfAlreadyRunToday: Bool = false, completion: @escaping (Result<String, Error>) -> Void
    ) {
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                var arguments = ["fetch"]
                if skipIfAlreadyRunToday {
                    arguments.append("--skip-if-already-run-today")
                }
                let result = try run(arguments: arguments)
                // Exit-Code 0 = sauber, 1 = neue Auffaelligkeiten gefunden -
                // beides ein erfolgreicher Lauf, kein Fehlerzustand.
                if result.exitCode == 0 || result.exitCode == 1 {
                    DispatchQueue.main.async { completion(.success(result.stdout)) }
                } else {
                    DispatchQueue.main.async {
                        completion(.failure(CLIError.processFailed(result.exitCode, result.stderr)))
                    }
                }
            } catch {
                DispatchQueue.main.async { completion(.failure(error)) }
            }
        }
    }
}
