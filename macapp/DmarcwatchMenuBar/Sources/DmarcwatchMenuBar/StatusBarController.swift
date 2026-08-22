import AppKit

final class StatusBarController: NSObject {
    private let statusItem: NSStatusItem
    private var refreshTimer: Timer?
    // 10 Minuten, gleiche Konvention wie SwiftBars "10m"-Dateinamenssuffix.
    private let refreshIntervalSeconds: TimeInterval = 600

    override init() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        super.init()
        statusItem.button?.image = Self.symbol("ellipsis.circle")
        refresh(nil)
        refreshTimer = Timer.scheduledTimer(withTimeInterval: refreshIntervalSeconds, repeats: true) { [weak self] _ in
            self?.refresh(nil)
        }
    }

    deinit {
        refreshTimer?.invalidate()
    }

    // Nicht mehr "private": AppDelegate ruft das nach dem
    // Start-Nachhol-Abruf auf (siehe main.swift).
    @objc func refresh(_ sender: Any?) {
        do {
            let report = try DmarcwatchCLI.fetchMenubarReport()
            render(report: report, error: nil)
        } catch {
            render(report: nil, error: error)
        }
    }

    @objc private func fetchNow(_ sender: Any?) {
        statusItem.button?.image = Self.symbol("arrow.triangle.2.circlepath")
        DmarcwatchCLI.runFetchAsync { [weak self] result in
            switch result {
            case .success:
                self?.refresh(nil)
            case .failure(let error):
                self?.render(report: nil, error: error)
            }
        }
    }

    @objc private func quit(_ sender: Any?) {
        NSApp.terminate(nil)
    }

    @objc private func openSetup(_ sender: Any?) {
        SetupWindowController.shared.show { [weak self] in
            self?.refresh(nil)
        }
    }

    @objc private func verifyDNS(_ sender: Any?) {
        let confirm = NSAlert()
        confirm.alertStyle = .informational
        confirm.messageText = "Eigene DNS-Einträge prüfen?"
        confirm.informativeText = """
        Fragt DMARC-, SPF- und DKIM-DNS-Einträge der eigenen Domain(s) ab - das \
        verlässt dein Gerät. Reine Diagnose, ändert nichts an Konfiguration oder \
        Auffälligkeits-Einstufung.
        """
        confirm.addButton(withTitle: "Prüfen")
        confirm.addButton(withTitle: "Abbrechen")
        guard confirm.runModal() == .alertFirstButtonReturn else { return }

        DNSVerifyWindowController.shared.show()
    }

    @objc private func toggleLoginItem(_ sender: Any?) {
        do {
            try LoginItemManager.setEnabled(!LoginItemManager.isEnabled)
        } catch {
            let alert = NSAlert()
            alert.alertStyle = .warning
            alert.messageText = "Anmeldeobjekt konnte nicht geändert werden"
            alert.informativeText = "\(error)"
            alert.runModal()
        }
        // Menü neu aufbauen, damit die Checkbox den tatsächlichen Status
        // zeigt (z. B. falls die Registrierung fehlgeschlagen ist).
        refresh(nil)
    }

    @objc private func lookupWhois(_ sender: NSMenuItem) {
        guard let ip = sender.representedObject as? String else { return }

        let confirm = NSAlert()
        confirm.alertStyle = .informational
        confirm.messageText = "WHOIS-Organisation abfragen?"
        confirm.informativeText = """
        Fragt die Organisation hinter \(ip) bei rdap.org ab - das verlässt dein \
        Gerät. Rein informativ: ändert nichts an der Einstufung als auffällig, \
        auch große Anbieter betreiben für jeden mietbare Cloud-Bereiche.
        """
        confirm.addButton(withTitle: "Abfragen")
        confirm.addButton(withTitle: "Abbrechen")
        guard confirm.runModal() == .alertFirstButtonReturn else { return }

        DmarcwatchCLI.runInspectWhois(ip: ip) { [weak self] result in
            if case .failure(let error) = result {
                let errorAlert = NSAlert()
                errorAlert.alertStyle = .warning
                errorAlert.messageText = "WHOIS-Abfrage fehlgeschlagen"
                errorAlert.informativeText = "\(error)"
                errorAlert.runModal()
            }
            // Neu laden, unabhängig vom Ergebnis: bei Erfolg zeigt das
            // Untermenü jetzt die Organisation, bei einem (nicht gecachten)
            // Fehlschlag bleibt einfach "WHOIS abrufen…" für einen
            // erneuten Versuch stehen.
            self?.refresh(nil)
        }
    }

    // MARK: - Rendering

    private func render(report: MenubarReport?, error: Error?) {
        let menu = NSMenu()

        if let report = report {
            let isFlagged = report.flaggedCount > 0
            // Gleiche Icons wie bei den einzelnen Tagen/Records im Dropdown
            // (checkmark.circle / Warndreieck), nicht nur ein Unicode-Glyph
            // im Titeltext - und okCount statt totalCount neben dem
            // Häkchen, sonst ergibt "9 ⚠1" bei 8 sauberen + 1 auffälligem
            // Eintrag keine korrekte Rechnung. In der Statusleiste bleiben
            // beide Symbole schwarz/Template wie sonst übliche
            // Menüleisten-Icons (WLAN, Bluetooth, Batterie) - Farbe ist nur
            // im aufgeklappten Menü sinnvoll, dort unverändert orange.
            let okCount = report.totalCount - report.flaggedCount
            let title = NSMutableAttributedString()
            title.append(Self.iconText(symbol: "checkmark.circle", count: okCount))
            if isFlagged {
                title.append(NSAttributedString(string: "  "))
                title.append(Self.iconText(symbol: "exclamationmark.triangle.fill", count: report.flaggedCount))
            }
            statusItem.button?.image = nil
            statusItem.button?.attributedTitle = title

            let header = NSMenuItem(
                title: "DMARC · letzte \(report.days) Tage",
                action: nil, keyEquivalent: ""
            )
            header.attributedTitle = NSAttributedString(
                string: header.title,
                attributes: [.font: NSFont.boldSystemFont(ofSize: NSFont.systemFontSize)]
            )
            header.isEnabled = false
            menu.addItem(header)

            let summary = disabledItem(
                "\(report.totalCount) Einträge, \(report.flaggedCount) auffällig",
                secondary: true
            )
            menu.addItem(summary)
            menu.addItem(NSMenuItem.separator())

            if report.daysGrouped.isEmpty {
                menu.addItem(disabledItem("Keine Reports im Zeitraum", secondary: true))
            }

            for day in report.daysGrouped {
                menu.addItem(dayMenuItem(for: day))
            }
        } else {
            statusItem.button?.image = Self.symbol("questionmark.circle")
            statusItem.button?.title = ""
            menu.addItem(disabledItem(describeError(error), secondary: true))
        }

        menu.addItem(NSMenuItem.separator())

        let fetchItem = NSMenuItem(title: "Jetzt abrufen", action: #selector(fetchNow(_:)), keyEquivalent: "r")
        fetchItem.image = Self.symbol("tray.and.arrow.down")
        fetchItem.target = self
        menu.addItem(fetchItem)

        let refreshItem = NSMenuItem(title: "Aktualisieren", action: #selector(refresh(_:)), keyEquivalent: "")
        refreshItem.image = Self.symbol("arrow.clockwise")
        refreshItem.target = self
        menu.addItem(refreshItem)

        menu.addItem(NSMenuItem.separator())

        let setupItem = NSMenuItem(title: "Einstellungen…", action: #selector(openSetup(_:)), keyEquivalent: ",")
        setupItem.image = Self.symbol("gearshape")
        setupItem.target = self
        menu.addItem(setupItem)

        let verifyDNSItem = NSMenuItem(
            title: "DNS prüfen…", action: #selector(verifyDNS(_:)), keyEquivalent: ""
        )
        verifyDNSItem.image = Self.symbol("checkmark.seal")
        verifyDNSItem.target = self
        menu.addItem(verifyDNSItem)

        let loginItem = NSMenuItem(
            title: "Bei Anmeldung starten", action: #selector(toggleLoginItem(_:)), keyEquivalent: ""
        )
        loginItem.target = self
        loginItem.state = LoginItemManager.isEnabled ? .on : .off
        menu.addItem(loginItem)

        menu.addItem(NSMenuItem.separator())

        let quitItem = NSMenuItem(title: "Beenden", action: #selector(quit(_:)), keyEquivalent: "q")
        quitItem.target = self
        menu.addItem(quitItem)

        statusItem.menu = menu
    }

    /// Ein Tag als eigener Menüpunkt mit Submenu für die einzelnen Records -
    /// verschachtelte Menüs statt einer Textwand, wie bei Bluetooth-Geräten
    /// oder Wi-Fi-Netzwerken in der System-Menüleiste.
    private func dayMenuItem(for day: DayGroup) -> NSMenuItem {
        let dayItem = NSMenuItem(title: "", action: nil, keyEquivalent: "")
        let countLabel = day.records.count == 1 ? "1 Eintrag" : "\(day.records.count) Einträge"
        let title = day.flaggedCount > 0 ? "\(day.date) — \(day.flaggedCount) auffällig" : "\(day.date) — \(countLabel)"
        dayItem.title = title
        if day.flaggedCount > 0 {
            dayItem.image = Self.symbol("exclamationmark.triangle.fill")
        } else {
            dayItem.image = Self.symbol("checkmark.circle")
        }

        let submenu = NSMenu()
        for record in day.records {
            submenu.addItem(recordMenuItem(for: record))
        }
        dayItem.submenu = submenu
        return dayItem
    }

    /// Jeder Record bekommt ein eigenes Untermenü mit den Detailfeldern als
    /// eigene, immer sichtbare Zeilen - nicht als Tooltip (der braucht
    /// Hover und wird leicht übersehen; "da kann man nichts aufklappen"
    /// war berechtigte Kritik daran).
    private func recordMenuItem(for record: ReportRecord) -> NSMenuItem {
        let title: String
        if record.isFlagged {
            title = "\(record.sourceIp) — " + record.flagLabels.joined(separator: ", ")
        } else {
            title = "\(record.sourceIp) — \(record.orgName)"
        }

        let item = NSMenuItem(title: title, action: nil, keyEquivalent: "")

        if record.isFlagged {
            item.image = Self.symbol("exclamationmark.triangle.fill")
            item.attributedTitle = NSAttributedString(
                string: title,
                attributes: [.foregroundColor: NSColor.systemOrange]
            )
        } else {
            item.image = Self.symbol("checkmark.circle")
        }

        let submenu = NSMenu()
        submenu.addItem(disabledDetailLine("Melder", record.orgName))
        submenu.addItem(disabledDetailLine("Quell-IP", record.sourceIp))
        submenu.addItem(disabledDetailLine("Empfänger (envelope_to)", record.envelopeTo.isEmpty ? "—" : record.envelopeTo))
        submenu.addItem(disabledDetailLine("Anzahl", "\(record.count)"))
        submenu.addItem(disabledDetailLine("Disposition", record.disposition))
        submenu.addItem(disabledDetailLine("DKIM", record.dkim))
        submenu.addItem(disabledDetailLine("SPF", record.spf))
        if record.isFlagged {
            submenu.addItem(NSMenuItem.separator())
            submenu.addItem(disabledDetailLine("Grund", record.flagLabels.joined(separator: ", ")))
        }
        // Zeigt nur, was `dmarcwatch inspect --whois` vorher schon lokal
        // abgelegt hat - die App fragt selbst nie bei rdap.org an (siehe
        // DmarcwatchCLI.swift-Kommentar zu bewusst fehlendem App Sandbox /
        // Netzverkehr). Ohne Cache-Eintrag nur ein Hinweis, wie man ihn
        // bekommt, kein automatischer Lookup.
        if let org = record.whoisOrganization {
            submenu.addItem(disabledDetailLine("WHOIS (nur Hinweis)", org))
        } else if record.isFlagged {
            // Einzige Stelle, an der ein Klick in dieser App tatsächlich
            // eine Netzwerkanfrage (RDAP an rdap.org) auslösen kann - immer
            // erst nach Bestätigung im Dialog, nie automatisch. Entspricht
            // einem manuellen `dmarcwatch inspect <ip> --whois` im
            // Terminal, nur bequemer erreichbar.
            let whoisItem = NSMenuItem(
                title: "WHOIS abrufen…", action: #selector(lookupWhois(_:)), keyEquivalent: ""
            )
            whoisItem.image = Self.symbol("network")
            whoisItem.target = self
            whoisItem.representedObject = record.sourceIp
            submenu.addItem(whoisItem)
        }
        item.submenu = submenu

        return item
    }

    private func disabledDetailLine(_ label: String, _ value: String) -> NSMenuItem {
        return disabledItem("\(label): \(value)")
    }

    private func disabledItem(_ text: String, secondary: Bool = false) -> NSMenuItem {
        let item = NSMenuItem(title: text, action: nil, keyEquivalent: "")
        item.isEnabled = false
        if secondary {
            item.attributedTitle = NSAttributedString(
                string: text,
                attributes: [
                    .font: NSFont.systemFont(ofSize: NSFont.smallSystemFontSize),
                    .foregroundColor: NSColor.secondaryLabelColor,
                ]
            )
        }
        return item
    }

    private func describeError(_ error: Error?) -> String {
        guard let error = error else { return "Unbekannter Fehler" }
        switch error {
        case CLIError.binaryNotFound(let path):
            return "dmarcwatch nicht gefunden: \(path)"
        case CLIError.processFailed(let code, let stderr):
            return "Fehler (Code \(code)): \(stderr.isEmpty ? "unbekannt" : stderr)"
        case CLIError.decodingFailed(let message):
            return "Antwort konnte nicht gelesen werden: \(message)"
        default:
            return error.localizedDescription
        }
    }

    /// Monochromes Template-Symbol wie bei den übrigen System-Statusitems
    /// (WLAN, Bluetooth, Batterie) - keine Farb-Icons/Emoji in der
    /// Menüleiste selbst. Farbe (z. B. für Warnungen) ist nur innerhalb der
    /// aufgeklappten Menüinhalte sinnvoll, nicht im Statusleisten-Icon.
    private static func symbol(_ name: String, color: NSColor? = nil, pointSize: CGFloat? = nil) -> NSImage? {
        let image = NSImage(systemSymbolName: name, accessibilityDescription: name)
        var config = pointSize.map { NSImage.SymbolConfiguration(pointSize: $0, weight: .regular) }
        if let color = color {
            let paletteConfig = NSImage.SymbolConfiguration(paletteColors: [color])
            config = config.map { $0.applying(paletteConfig) } ?? paletteConfig
        }
        let result = config.flatMap { image?.withSymbolConfiguration($0) } ?? image
        if color == nil {
            result?.isTemplate = true
        }
        return result
    }

    /// Icon + Zahl als ein zusammenhängendes Attributed-String-Fragment,
    /// für die Statusleiste, wo mehrere Icon/Zahl-Paare nebeneinander
    /// stehen sollen (checkmark.circle 8, Warndreieck 1) - ein einzelnes
    /// NSButton.image reicht dafür nicht, das kann nur ein Icon.
    ///
    /// pointSize wird hier explizit an withSymbolConfiguration übergeben,
    /// statt das Bild in Standardgröße zu holen und erst danach über
    /// NSTextAttachment.bounds zu skalieren - Letzteres hat das
    /// Ausrufezeichen im gefüllten Warndreieck-Symbol verschluckt
    /// (vermutlich ein Rasterisierungsartefakt beim nachträglichen Resize
    /// eines mehrschichtigen SF-Symbols).
    private static func iconText(symbol name: String, count: Int, color: NSColor? = nil) -> NSAttributedString {
        let result = NSMutableAttributedString()
        if let image = Self.symbol(name, color: color, pointSize: NSFont.systemFontSize) {
            let attachment = NSTextAttachment()
            attachment.image = image
            let size = image.size
            attachment.bounds = CGRect(x: 0, y: (NSFont.systemFontSize - size.height) / 2 - 1, width: size.width, height: size.height)
            result.append(NSAttributedString(attachment: attachment))
        }
        result.append(NSAttributedString(string: " \(count)"))
        return result
    }
}
