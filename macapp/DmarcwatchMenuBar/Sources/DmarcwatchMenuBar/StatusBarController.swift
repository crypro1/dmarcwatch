import AppKit

/// Inhalt für den Info-Alert hinter dem ⓘ-Symbol an DMARC/TLS-RPT-
/// Überschriften (siehe showInfo(_:)) - als representedObject am jeweiligen
/// NSMenuItem hinterlegt, da ein Menüpunkt nur eine action, aber beliebige
/// Nutzdaten tragen kann.
private struct InfoPopover {
    let headline: String
    let text: String
}

final class StatusBarController: NSObject {
    private let statusItem: NSStatusItem
    private var refreshTimer: Timer?
    // 10 Minuten, gleiche Konvention wie SwiftBars "10m"-Dateinamenssuffix -
    // die Hauptauffrischung passiert inzwischen beim Hovern übers Icon
    // (mouseEntered unten), der Timer ist nur noch das Sicherheitsnetz für
    // "App läuft lange im Hintergrund, ohne dass je gehovert wird".
    private let refreshIntervalSeconds: TimeInterval = 600

    override init() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        super.init()
        statusItem.button?.image = Self.symbol("ellipsis.circle")
        if let button = statusItem.button {
            // Aktualisiert schon beim Hovern, nicht erst beim Klick - beim
            // üblichen "kurz drüber, dann klicken" ist der Inhalt dann
            // schon fertig geladen, wenn das Menü tatsächlich aufklappt.
            // Sicher, weil render() unten bei jedem Aufruf eine KOMPLETT
            // NEUE NSMenu-Instanz baut und erst am Ende per
            // statusItem.menu = menu zuweist - im Unterschied zu einer
            // früheren Zwischenversion, die stattdessen eine einzige
            // langlebige NSMenu-Instanz per removeAllItems() in-place neu
            // befüllt hat. Das hatte, ausgelöst über NSMenuDelegate.
            // menuWillOpen(_:) direkt vor dem Aufklappen, dazu geführt,
            // dass praktisch kein Menüpunkt im gesamten Dropdown mehr auf
            // Klicks reagierte, obwohl der Inhalt weiterhin korrekt
            // sichtbar war (AppKits interne Klick-Weiterleitung verliert
            // offenbar den Bezug, wenn genau die Instanz, die gerade zum
            // Anzeigen/Tracking vorbereitet wird, in-place mutiert wird).
            // Ein komplett neues Objekt zuzuweisen, während das alte
            // (falls gerade offen) unangetastet bleibt, hat dieses
            // Problem nicht - das gilt für jeden refresh()-Aufruf,
            // egal ob durch Hovern, den Timer oder App-Start ausgelöst.
            button.addTrackingArea(
                NSTrackingArea(
                    rect: button.bounds,
                    options: [.mouseEnteredAndExited, .activeAlways, .inVisibleRect],
                    owner: self, userInfo: nil
                )
            )
        }
        refresh(nil)
        refreshTimer = Timer.scheduledTimer(withTimeInterval: refreshIntervalSeconds, repeats: true) { [weak self] _ in
            self?.refresh(nil)
        }
    }

    deinit {
        refreshTimer?.invalidate()
    }

    // WICHTIG: @objc(mouseEntered:) explizit angeben, nicht nur @objc.
    // Swifts automatische Selektor-Erzeugung für eine SELBST GESCHRIEBENE
    // Methode mit dieser Signatur ergibt "mouseEnteredWith:", nicht
    // "mouseEntered:" (das "with" fällt nur bei ECHTEN NSResponder-
    // Overrides weg, per Apple-eigenem Objective-C-Import-Mapping - nicht
    // bei einer neuen, eigenen Methode gleichen Namens). NSTrackingArea
    // ruft aber zwingend den wörtlichen Selektor "mouseEntered:" auf.
    // Ohne die explizite Angabe hier fand AppKit die Methode nie und warf
    // bei JEDER Mausbewegung übers Icon (rein/raus) eine "unrecognized
    // selector"-Exception - das hat reihenweise Menüaktionen im gesamten
    // Dropdown verschluckt, nicht nur die neuen DNS-Einträge. Empirisch
    // verifiziert mit einem eigenen Testskript (NSStringFromSelector).
    @objc(mouseEntered:) func mouseEntered(with event: NSEvent) {
        refresh(nil)
    }

    @objc(mouseExited:) func mouseExited(with event: NSEvent) {}

    // Nicht mehr "private": AppDelegate ruft das nach dem
    // Start-Nachhol-Abruf auf (siehe main.swift).
    @objc func refresh(_ sender: Any?) {
        // TLS-RPT wird mit abgefragt, auch wenn enable_tls_rpt (noch) aus
        // ist - tls-report liest nur die schon vorhandene DB, unabhängig
        // vom Fetch-Flag. `try?` statt eigener Fehlerbehandlung: schlägt
        // das fehl (z. B. Binary kaputt), zeigt render() einfach keinen
        // TLS-RPT-Abschnitt an, statt den ganzen DMARC-Bericht mit
        // durchfallen zu lassen.
        let tlsReport = try? DmarcwatchCLI.fetchTLSReport()
        do {
            let report = try DmarcwatchCLI.fetchMenubarReport()
            render(report: report, error: nil, tlsReport: tlsReport)
        } catch {
            render(report: nil, error: error, tlsReport: tlsReport)
        }
    }

    @objc private func fetchNow(_ sender: Any?) {
        statusItem.button?.image = Self.symbol("arrow.triangle.2.circlepath")
        DmarcwatchCLI.runFetchAsync { [weak self] result in
            switch result {
            case .success:
                self?.refresh(nil)
            case .failure(let error):
                self?.render(report: nil, error: error, tlsReport: nil)
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

    @objc private func openStats(_ sender: Any?) {
        StatsWindowController.shared.show()
    }

    // Reine UI-Präferenz (kein Sicherheits-/Konfigurationswert), deshalb in
    // UserDefaults statt in config.json - "Nicht mehr fragen" unten setzt
    // das einmalig, ohne den Python-CLI-Umweg für ein reines Anzeigedetail.
    private static let skipDNSVerifyConfirmationKey = "skipDNSVerifyConfirmation"

    @objc private func verifyDNS(_ sender: Any?) {
        NSApp.activate(ignoringOtherApps: true)

        if !UserDefaults.standard.bool(forKey: Self.skipDNSVerifyConfirmationKey) {
            let confirm = NSAlert()
            confirm.alertStyle = .informational
            confirm.messageText = "Eigene DNS-Einträge prüfen?"
            confirm.informativeText = """
            Fragt DMARC-, SPF- und DKIM-DNS-Einträge der eigenen Domain(s) ab - das \
            verlässt dein Gerät. Reine Diagnose, ändert nichts an Konfiguration oder \
            Auffälligkeits-Einstufung.

            Symbol und die Fläche oben in der Statusleiste färben sich rot, sobald \
            mindestens eine Warnung gefunden wurde (z. B. fehlendes DMARC, p=none, \
            SPF über dem Lookup-Limit) - im Menü erscheint die betroffene Domain dann \
            als eigene Zeile mit den konkreten Gründen darunter.
            """
            confirm.showsSuppressionButton = true
            confirm.suppressionButton?.title = "Nicht mehr fragen"
            confirm.addButton(withTitle: "Prüfen")
            confirm.addButton(withTitle: "Abbrechen")
            let response = confirm.runModal()
            if confirm.suppressionButton?.state == .on {
                UserDefaults.standard.set(true, forKey: Self.skipDNSVerifyConfirmationKey)
            }
            guard response == .alertFirstButtonReturn else { return }
        }

        DNSVerifyWindowController.shared.show()
    }

    /// Reine Info-Anzeige, kein Netzzugriff, keine Bestätigung nötig -
    /// deshalb ein schlichter Alert mit nur einem Knopf statt der
    /// Ja/Abbrechen-Bestätigungsdialoge, die tatsächlich etwas auslösen
    /// (WHOIS/DNS-Prüfung/SPF).
    @objc private func showInfo(_ sender: NSMenuItem) {
        guard let info = sender.representedObject as? InfoPopover else { return }
        let alert = NSAlert()
        alert.alertStyle = .informational
        alert.messageText = info.headline
        alert.informativeText = info.text
        alert.addButton(withTitle: "Verstanden")
        alert.runModal()
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
                errorAlert.informativeText = self?.describeError(error) ?? "\(error)"
                errorAlert.runModal()
            }
            // Neu laden, unabhängig vom Ergebnis: bei Erfolg zeigt das
            // Untermenü jetzt die Organisation, bei einem (nicht gecachten)
            // Fehlschlag bleibt einfach "WHOIS abrufen…" für einen
            // erneuten Versuch stehen.
            self?.refresh(nil)
        }
    }

    /// Gleiches Muster wie lookupWhois() oben, nur gegen Spamhaus ZEN statt
    /// RDAP.
    @objc private func lookupBlacklist(_ sender: NSMenuItem) {
        guard let ip = sender.representedObject as? String else { return }

        let confirm = NSAlert()
        confirm.alertStyle = .informational
        confirm.messageText = "Spamhaus-Status abfragen?"
        confirm.informativeText = """
        Fragt, ob \(ip) bei Spamhaus ZEN gelistet ist - das verlässt dein \
        Gerät. Rein informativ: ändert nichts an der Einstufung als auffällig.
        """
        confirm.addButton(withTitle: "Abfragen")
        confirm.addButton(withTitle: "Abbrechen")
        guard confirm.runModal() == .alertFirstButtonReturn else { return }

        DmarcwatchCLI.runInspectBlacklist(ip: ip) { [weak self] result in
            if case .failure(let error) = result {
                let errorAlert = NSAlert()
                errorAlert.alertStyle = .warning
                errorAlert.messageText = "Spamhaus-Abfrage fehlgeschlagen"
                errorAlert.informativeText = self?.describeError(error) ?? "\(error)"
                errorAlert.runModal()
            }
            self?.refresh(nil)
        }
    }

    // MARK: - Rendering

    private func render(report: MenubarReport?, error: Error?, tlsReport: TLSReportResponse?) {
        let menu = NSMenu()
        // Nur anzeigen, wenn TLS-RPT tatsächlich aktiviert UND mindestens
        // ein Eintrag vorhanden ist. Beide Bedingungen nötig: tls-report
        // liest unabhängig vom Schalter, was schon in der DB steht (siehe
        // cmd_tls_report) - ohne die Flag-Prüfung hier würde die Sektion
        // nach einem "kurz ausprobiert, dann wieder deaktiviert" weiter mit
        // alten Daten auftauchen, obwohl die Funktion inzwischen aus ist.
        let tlsRptEnabled = ConfigStore.loadCurrent()?.enableTlsRpt ?? false
        let hasTLSData = tlsRptEnabled && !(tlsReport?.policies.isEmpty ?? true)

        // Letztes bekanntes verify-dns-Ergebnis (Klick auf "DNS prüfen…"
        // oder periodischer automatischer Check) - rein lesend aus der
        // schon vorhandenen menubar-json-Antwort, kein eigener DNS-Aufruf
        // hier. dnsCheck kann auch dann vorhanden sein, wenn `report`
        // selbst fehlschlägt (unwahrscheinlich, da beides aus demselben
        // Prozess kommt), deshalb per optional chaining statt im
        // `if let report`-Zweig.
        let dnsCheck = report?.dnsCheck
        let dnsWarnedDomains = dnsCheck?.domains.filter { $0.hasWarnings } ?? []
        let dnsHasWarnings = !dnsWarnedDomains.isEmpty

        // Rote, leicht durchsichtige "Pille" hinter den Statusleisten-
        // Icons, wenn die eigene DNS-Konfiguration Auffälligkeiten hat -
        // deutlich sichtbar, ohne die Icons selbst einzufärben (die
        // bleiben bewusst monochrom/Template, siehe iconText-Kommentar).
        if let button = statusItem.button {
            button.wantsLayer = true
            button.layer?.backgroundColor = dnsHasWarnings
                ? NSColor.systemRed.withAlphaComponent(0.25).cgColor
                : nil
            button.layer?.cornerRadius = 9
        }

        if let report = report {
            let isFlagged = report.flaggedCount > 0
            // Gleiche Icons wie bei den einzelnen Tagen/Records im Dropdown
            // (checkmark.circle / Warndreieck), nicht nur ein Unicode-Glyph
            // im Titeltext - und okCount statt totalCount neben dem
            // Häkchen, sonst ergibt "9 ⚠1" bei 8 sauberen + 1 auffälligem
            // Eintrag keine korrekte Rechnung. In der Statusleiste bleiben
            // alle Symbole schwarz/Template wie sonst übliche
            // Menüleisten-Icons (WLAN, Bluetooth, Batterie) - Farbe ist nur
            // im aufgeklappten Menü sinnvoll, dort unverändert orange.
            let okCount = report.totalCount - report.flaggedCount
            // Referenzhöhe von checkmark.circle - alle Symbole in der
            // Statusleiste werden auf genau diese Höhe angeglichen (siehe
            // iconText/symbolMatchingHeight), nicht nur auf denselben
            // pointSize-Parameter. Verschiedene SF-Symbole haben bei
            // gleichem pointSize unterschiedliche native Seitenverhältnisse
            // (key.fill z. B. breiter/diagonal), dadurch wirken sie trotz
            // identischem pointSize optisch unterschiedlich groß.
            let iconHeight = Self.symbol("checkmark.circle", pointSize: NSFont.systemFontSize)?.size.height
                ?? NSFont.systemFontSize
            let title = NSMutableAttributedString()
            title.append(Self.iconText(symbol: "checkmark.circle", count: okCount, targetHeight: iconHeight))
            if isFlagged {
                title.append(NSAttributedString(string: "  "))
                title.append(
                    Self.iconText(
                        symbol: "exclamationmark.triangle.fill", count: report.flaggedCount, targetHeight: iconHeight
                    )
                )
            }
            // Gleiches Muster wie exclamationmark.triangle.fill oben - nur
            // bei tatsächlichen Fehlschlägen zeigen, nicht schon bei bloß
            // vorhandenen TLS-RPT-Daten (die Statusleiste ist sonst voller
            // "0", obwohl gar nichts auffällig ist).
            if hasTLSData, let failureCount = tlsReport?.totalFailureCount, failureCount > 0 {
                title.append(NSAttributedString(string: "  "))
                title.append(
                    Self.iconText(
                        symbol: "key.fill", count: failureCount, targetHeight: iconHeight
                    )
                )
            }
            statusItem.button?.image = nil
            statusItem.button?.attributedTitle = title

            let header = NSMenuItem(
                title: "DMARC · letzte \(report.days) Tage",
                action: #selector(showInfo(_:)), keyEquivalent: ""
            )
            header.attributedTitle = Self.compactHeaderTitle(
                header.title, subtitle: "\(report.totalCount) Einträge, \(report.flaggedCount) auffällig",
                icon: "info.circle"
            )
            header.target = self
            header.representedObject = InfoPopover(
                headline: "DMARC",
                text: "DMARC (Domain-based Message Authentication, Reporting & Conformance) prüft, ob Mails " +
                    "von deiner Domain wirklich von autorisierten Servern stammen (SPF/DKIM), und legt fest, " +
                    "was Empfänger mit nicht-autorisierten Mails tun sollen.\n\n" +
                    "Diese Liste zeigt die täglichen Sammelreports (rua), die andere Mailanbieter dir " +
                    "darüber schicken: pro Tag, wie viele Mails geprüft wurden, von welcher Quell-IP, und " +
                    "ob SPF/DKIM oder die angewendete Disposition (z. B. \"quarantine\"/\"reject\") auffällig waren."
            )
            menu.addItem(header)
            menu.addItem(NSMenuItem.separator())

            if report.daysGrouped.isEmpty {
                menu.addItem(disabledItem("Keine Reports im Zeitraum", secondary: true))
            }

            for day in report.daysGrouped {
                menu.addItem(dayMenuItem(for: day))
            }

            // TLS-RPT direkt im selben Dropdown, unterhalb des ältesten
            // DMARC-Eintrags - gleiches Prinzip wie bei DMARC (Tag ->
            // Untermenü mit den Einzeleinträgen), kein eigenes Fenster mehr.
            if let tlsReport = tlsReport, hasTLSData {
                menu.addItem(NSMenuItem.separator())
                let tlsHeader = NSMenuItem(
                    title: "TLS-RPT · letzte \(tlsReport.days) Tage",
                    action: #selector(showInfo(_:)), keyEquivalent: ""
                )
                tlsHeader.attributedTitle = Self.compactHeaderTitle(
                    tlsHeader.title,
                    subtitle: "\(tlsReport.policies.count) Eintrag/Einträge, \(tlsReport.totalFailureCount) Fehlschläge",
                    icon: "info.circle"
                )
                tlsHeader.target = self
                tlsHeader.representedObject = InfoPopover(
                    headline: "TLS-RPT",
                    text: "TLS-RPT (SMTP TLS Reporting, RFC 8460) meldet, wenn andere Mailserver beim " +
                        "Versand an dich keine verschlüsselte Verbindung (TLS) aufbauen konnten - z. B. " +
                        "wegen eines abgelaufenen Zertifikats oder eines DNS-Konfigurationsfehlers bei " +
                        "MTA-STS/DANE. Reine Diagnose der Zustellsicherheit, unabhängig von DMARC.\n\n" +
                        "Diese Liste zeigt pro Tag und Domain, wie viele TLS-Verbindungen erfolgreich " +
                        "waren und wie viele fehlgeschlagen sind, inklusive der gemeldeten Fehlertypen " +
                        "(z. B. \"certificate-expired\", \"starttls-not-supported\")."
                )
                menu.addItem(tlsHeader)
                menu.addItem(NSMenuItem.separator())

                for (date, entries) in Self.groupedByDateDescending(tlsReport.policies) {
                    menu.addItem(tlsDayMenuItem(date: date, entries: entries))
                }
            }

            // Nur sichtbar, wenn beim letzten Abruf tatsächlich etwas
            // übersprungen wurde (z. B. eine abgelehnte Dekompressionsbombe
            // oder ein zu großer Anhang) - unsichtbar im Normalfall, statt
            // eine leere Sektion dauerhaft im Menü zu zeigen.
            if !report.skippedItems.isEmpty {
                menu.addItem(NSMenuItem.separator())
                let skippedHeader = NSMenuItem(
                    title: "Übersprungen · letzter Abruf", action: #selector(showInfo(_:)), keyEquivalent: ""
                )
                skippedHeader.attributedTitle = Self.compactHeaderTitle(
                    skippedHeader.title, subtitle: Self.skippedItemsSummary(report.skippedItems),
                    icon: "info.circle"
                )
                skippedHeader.target = self
                skippedHeader.representedObject = InfoPopover(
                    headline: "Übersprungen",
                    text: "Diese Nachrichten oder Anhänge wurden beim letzten Abruf abgelehnt und nicht " +
                        "verarbeitet - z. B. weil sie eine Größengrenze überschritten haben oder als " +
                        "beschädigt/böswillig erkannt wurden (etwa eine Dekompressionsbombe). Ein " +
                        "einzelner solcher Fund unterbricht den Lauf nicht, alle übrigen Nachrichten " +
                        "werden trotzdem normal weiterverarbeitet."
                )
                menu.addItem(skippedHeader)
                menu.addItem(NSMenuItem.separator())

                for reason in report.skippedItems {
                    menu.addItem(skippedItemMenuItem(reason))
                }
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

        menu.addItem(NSMenuItem.separator())

        // Flacher Aufbau wie bei DMARC/TLS-RPT/Übersprungen: Kopfzeile mit
        // Info-Klick (showInfo) als eigenständiger Menüpunkt, "Jetzt
        // prüfen…" und die Domain-Ergebnisse als eigene Geschwister-
        // Einträge direkt darunter - NICHT als Untermenü der Kopfzeile
        // selbst. Ein NSMenuItem mit eigenem Untermenü kann laut AppKit
        // beim Klick nur das Untermenü öffnen, nie gleichzeitig eine eigene
        // action feuern - das hatte "Jetzt prüfen…" als verschachtelten
        // Untermenüpunkt zuvor unzuverlässig gemacht und hätte hier auch
        // den Info-Klick auf der Kopfzeile selbst unmöglich gemacht.
        // Ein einzelner klickbarer Eintrag - klickt man drauf, läuft (nach
        // Bestätigung) eine frische Prüfung und das Ergebnisfenster öffnet
        // sich, genau wie vor dem DNS-Status-Feature. Titel + Zusammen-
        // fassung in einem kompakten, zweizeiligen attributedTitle wie bei
        // den anderen Kopfzeilen.
        let dnsItem = NSMenuItem(title: "DNS prüfen…", action: #selector(verifyDNS(_:)), keyEquivalent: "")
        let dnsSubtitle: String
        if let dnsCheck = dnsCheck {
            let checkedAt = Self.germanDate(dnsCheck.checkedAt)
            dnsSubtitle = dnsHasWarnings
                ? "Zuletzt geprüft: \(checkedAt) - \(dnsWarnedDomains.count) auffällig"
                : "Zuletzt geprüft: \(checkedAt) - keine Auffälligkeiten"
        } else {
            dnsSubtitle = "Noch nicht geprüft"
        }
        dnsItem.attributedTitle = Self.compactHeaderTitle(
            dnsItem.title, subtitle: dnsSubtitle, icon: nil
        )
        // Nur die Farbe wechselt (rot statt Template-Weiß/Schwarz), nicht
        // das Symbol selbst (kein .fill) - dieselbe Kontur wie im Normalfall.
        dnsItem.image = Self.symbol("checkmark.seal", color: dnsHasWarnings ? .systemRed : nil)
        dnsItem.target = self
        menu.addItem(dnsItem)

        // Nur auffällige Domains bekommen eine eigene, aufklappbare Zeile -
        // bei einer sauberen Domain gibt's nichts Zusätzliches zu zeigen,
        // die Unterzeile an "DNS prüfen…" ("keine Auffälligkeiten") reicht
        // dafür bereits.
        for domainResult in dnsWarnedDomains {
            menu.addItem(dnsDomainMenuItem(domainResult))
        }

        // Reines Lesen der lokalen DB wie "TLS-RPT-Bericht…"/menubar-json,
        // deshalb ohne Bestätigungsdialog (anders als "DNS prüfen…", das
        // tatsächlich nach außen geht).
        let statsItem = NSMenuItem(title: "Statistik…", action: #selector(openStats(_:)), keyEquivalent: "")
        statsItem.image = Self.symbol("chart.line.uptrend.xyaxis")
        statsItem.target = self
        menu.addItem(statsItem)

        let setupItem = NSMenuItem(title: "Einstellungen…", action: #selector(openSetup(_:)), keyEquivalent: ",")
        setupItem.image = Self.symbol("gearshape")
        setupItem.target = self
        menu.addItem(setupItem)

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
        let displayDate = Self.germanDate(day.date)
        let title = day.flaggedCount > 0 ? "\(displayDate) — \(day.flaggedCount) auffällig" : "\(displayDate) — \(countLabel)"
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
        // Gleiches Muster wie WHOIS oben, nur gegen Spamhaus ZEN statt RDAP -
        // und nur für IPv4 (Doppelpunkt = IPv6), da blacklist.py IPv6 nicht
        // unterstützt (siehe blacklist.py-Modul-Docstring). Der Knopf wird
        // für IPv6-Quell-IPs deshalb gar nicht erst angeboten, statt einen
        // Klick anzubieten, der garantiert immer scheitert - `inspect
        // --blacklist` beendet sich dabei mit Exit-Code 0 (Fehler steht nur
        // inline im Text, wie bei WHOIS), der Knopf würde also nach Klick
        // einfach kommentarlos wieder in seinem Ausgangszustand erscheinen.
        if let listed = record.blacklistListed {
            let status = listed ? "gelistet - " + record.blacklistReasons.joined(separator: "; ") : "nicht gelistet"
            submenu.addItem(disabledDetailLine("Spamhaus (nur Hinweis)", status))
        } else if record.isFlagged && !record.sourceIp.contains(":") {
            let blacklistItem = NSMenuItem(
                title: "Blacklist abrufen…", action: #selector(lookupBlacklist(_:)), keyEquivalent: ""
            )
            blacklistItem.image = Self.symbol("shield.slash")
            blacklistItem.target = self
            blacklistItem.representedObject = record.sourceIp
            submenu.addItem(blacklistItem)
        }
        item.submenu = submenu

        return item
    }

    /// Gruppiert TLS-RPT-Policy-Einträge nach Datum, neueste zuerst - analog
    /// zu report.to_json_dict()s days_grouped für DMARC, nur hier auf der
    /// Swift-Seite gebildet, weil to_tls_json_dict() bewusst eine flache
    /// Liste liefert (siehe report.py-Kommentar dort).
    private static func groupedByDateDescending(_ policies: [TLSPolicyEntry]) -> [(String, [TLSPolicyEntry])] {
        var byDate: [String: [TLSPolicyEntry]] = [:]
        for entry in policies {
            byDate[entry.date, default: []].append(entry)
        }
        return byDate.keys.sorted(by: >).map { ($0, byDate[$0]!) }
    }

    /// Ein TLS-RPT-Tag als eigener Menüpunkt mit Untermenü der
    /// Policy-Einträge - gleiches Muster wie dayMenuItem() für DMARC.
    private func tlsDayMenuItem(date: String, entries: [TLSPolicyEntry]) -> NSMenuItem {
        let failureCount = entries.reduce(0) { $0 + $1.failureCount }
        let dayItem = NSMenuItem(title: "", action: nil, keyEquivalent: "")
        let countLabel = entries.count == 1 ? "1 Eintrag" : "\(entries.count) Einträge"
        let displayDate = Self.germanDate(date)
        dayItem.title = failureCount > 0
            ? "\(displayDate) — \(failureCount) Fehlschläge" : "\(displayDate) — \(countLabel)"
        dayItem.image = Self.symbol(failureCount > 0 ? "exclamationmark.triangle.fill" : "checkmark.circle")

        let submenu = NSMenu()
        for entry in entries {
            submenu.addItem(tlsPolicyMenuItem(entry))
        }
        dayItem.submenu = submenu
        return dayItem
    }

    /// Ein Policy-Eintrag mit den Detailfeldern als eigene Zeilen im
    /// Untermenü - gleiches Muster wie recordMenuItem() für DMARC.
    private func tlsPolicyMenuItem(_ entry: TLSPolicyEntry) -> NSMenuItem {
        let title: String
        if entry.failureCount > 0 {
            title = "\(entry.policyDomain) (\(entry.policyType)) — \(entry.failureCount) Fehlschläge"
        } else {
            title = "\(entry.policyDomain) (\(entry.policyType))"
        }

        let item = NSMenuItem(title: title, action: nil, keyEquivalent: "")
        if entry.failureCount > 0 {
            item.image = Self.symbol("exclamationmark.triangle.fill")
            item.attributedTitle = NSAttributedString(
                string: title,
                attributes: [.foregroundColor: NSColor.systemOrange]
            )
        } else {
            item.image = Self.symbol("checkmark.circle")
        }

        let submenu = NSMenu()
        submenu.addItem(disabledDetailLine("Melder", entry.organizationName))
        submenu.addItem(disabledDetailLine("Erfolgreiche Sitzungen", "\(entry.successfulSessionCount)"))
        submenu.addItem(disabledDetailLine("Fehlschläge", "\(entry.failureCount)"))
        if !entry.failureResultTypes.isEmpty {
            submenu.addItem(NSMenuItem.separator())
            submenu.addItem(disabledDetailLine("Fehlertyp(en)", entry.failureResultTypes.joined(separator: ", ")))
        }
        item.submenu = submenu
        return item
    }

    /// Zerlegt einen Eintrag aus MenubarReport.skippedItems in Quelle
    /// ("DMARC"/"TLS-RPT") und Grund - fetch.py stellt dem Grund das Tag
    /// immer als "<Quelle>: " voran (siehe _process_dmarc_folder/
    /// _process_tlsrpt_folder in fetch.py). Unbekanntes Format (z. B. eine
    /// ältere CLI-Version ohne das Tag) fällt auf "Unbekannt" zurück, statt
    /// falsch zu raten.
    private static func parseSkippedItem(_ raw: String) -> (source: String, detail: String) {
        for source in ["DMARC", "TLS-RPT"] {
            let prefix = "\(source): "
            if raw.hasPrefix(prefix) {
                return (source, String(raw.dropFirst(prefix.count)))
            }
        }
        return ("Unbekannt", raw)
    }

    /// "1 DMARC-Eintrag, 2 TLS-RPT-Einträge" statt nur einer Gesamtzahl -
    /// gleiche Aufschlüsselung wie die separaten DMARC-/TLS-RPT-Sektionen
    /// selbst, damit direkt erkennbar ist, wo etwas übersprungen wurde.
    private static func skippedItemsSummary(_ items: [String]) -> String {
        var counts: [String: Int] = [:]
        for item in items {
            let source = Self.parseSkippedItem(item).source
            counts[source, default: 0] += 1
        }
        let parts = ["DMARC", "TLS-RPT", "Unbekannt"].compactMap { source -> String? in
            guard let count = counts[source], count > 0 else { return nil }
            return count == 1 ? "1 \(source)-Eintrag" : "\(count) \(source)-Einträge"
        }
        return parts.joined(separator: ", ")
    }

    /// Ein übersprungener Eintrag mit Quelle+Grund im Untermenü - gleiches
    /// Muster wie dayMenuItem()/tlsDayMenuItem() statt einer einzelnen,
    /// potenziell langen Textzeile direkt im Hauptmenü.
    private func skippedItemMenuItem(_ raw: String) -> NSMenuItem {
        let (source, detail) = Self.parseSkippedItem(raw)
        let item = NSMenuItem(title: "\(source) — übersprungen", action: nil, keyEquivalent: "")
        item.image = Self.symbol("exclamationmark.shield.fill")

        let submenu = NSMenu()
        submenu.addItem(disabledDetailLine("Quelle", source))
        submenu.addItem(disabledDetailLine("Grund", detail))
        item.submenu = submenu
        return item
    }

    /// Ein Domain-Ergebnis der letzten DNS-Prüfung mit den konkreten
    /// DMARC-/SPF-/DKIM-Warnungen im Untermenü - gleiches Muster wie
    /// skippedItemMenuItem()/tlsPolicyMenuItem().
    /// Nur für auffällige Domains aufgerufen (siehe Aufrufer, gefiltert auf
    /// dnsWarnedDomains) - eine saubere Domain bekommt gar keine eigene
    /// Zeile mehr, die Unterzeile an "DNS prüfen…" reicht dafür.
    private func dnsDomainMenuItem(_ result: DNSCheckDomainResult) -> NSMenuItem {
        let item = NSMenuItem(title: result.domain, action: nil, keyEquivalent: "")
        item.image = Self.symbol("exclamationmark.triangle.fill")
        item.attributedTitle = NSAttributedString(
            string: result.domain, attributes: [.foregroundColor: NSColor.systemOrange]
        )

        let submenu = NSMenu()
        for warning in result.dmarc.warnings {
            submenu.addItem(disabledDetailLine("DMARC", warning))
        }
        for warning in result.spf.warnings {
            submenu.addItem(disabledDetailLine("SPF", warning))
        }
        if let error = result.spf.error {
            submenu.addItem(disabledDetailLine("SPF-Fehler", error))
        }
        for dkim in result.dkim {
            for warning in dkim.warnings {
                submenu.addItem(disabledDetailLine("DKIM (\(dkim.selector))", warning))
            }
        }
        for warning in result.mtaSts.warnings {
            submenu.addItem(disabledDetailLine("MTA-STS", warning))
        }
        for warning in result.tlsrptDns.warnings {
            submenu.addItem(disabledDetailLine("TLS-RPT-DNS", warning))
        }
        for warning in result.wildcardSpf.warnings {
            submenu.addItem(disabledDetailLine("Wildcard-SPF", warning))
        }
        for warning in result.mxBlacklist.warnings {
            submenu.addItem(disabledDetailLine("Spamhaus", warning))
        }
        for warning in result.dnssec.warnings {
            submenu.addItem(disabledDetailLine("DNSSEC", warning))
        }
        for warning in result.dane.warnings {
            submenu.addItem(disabledDetailLine("DANE", warning))
        }
        for warning in result.bimi.warnings {
            submenu.addItem(disabledDetailLine("BIMI", warning))
        }
        item.submenu = submenu
        return item
    }

    // Breit genug für das längste tatsächlich vorkommende Label
    // ("Empfänger (envelope_to):", ca. 157pt in der Menü-Schrift, empirisch
    // gemessen statt geraten) plus etwas Luft - ein echter Tab-Stopp statt
    // Leerzeichen-Auffüllung, weil die System-Schrift nicht monospaced ist
    // und Leerzeichen deshalb je nach Label unterschiedlich breit wirken.
    private static let detailLineValueColumn: CGFloat = 168

    private func disabledDetailLine(_ label: String, _ value: String) -> NSMenuItem {
        let paragraphStyle = NSMutableParagraphStyle()
        paragraphStyle.tabStops = [NSTextTab(textAlignment: .left, location: Self.detailLineValueColumn)]
        paragraphStyle.defaultTabInterval = Self.detailLineValueColumn

        let text = "\(label):\t\(value)"
        let item = NSMenuItem(title: text, action: nil, keyEquivalent: "")
        item.isEnabled = false
        item.attributedTitle = NSAttributedString(
            string: text,
            attributes: [.font: NSFont.menuFont(ofSize: 0), .paragraphStyle: paragraphStyle]
        )
        return item
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
        case CLIError.inspectLookupFailed(let message):
            return message.isEmpty ? "Abfrage fehlgeschlagen" : message
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
    private static func iconText(
        symbol name: String, count: Int, color: NSColor? = nil, targetHeight: CGFloat? = nil
    ) -> NSAttributedString {
        let result = NSMutableAttributedString()
        let image = targetHeight.map { Self.symbolMatchingHeight(name, color: color, targetHeight: $0) }
            ?? Self.symbol(name, color: color, pointSize: NSFont.systemFontSize)
        if let image = image {
            let attachment = NSTextAttachment()
            attachment.image = image
            let size = image.size
            attachment.bounds = CGRect(x: 0, y: (NSFont.systemFontSize - size.height) / 2 - 1, width: size.width, height: size.height)
            result.append(NSAttributedString(attachment: attachment))
        }
        result.append(NSAttributedString(string: " \(count)"))
        return result
    }

    /// Rendert ein SF-Symbol bei genau der Höhe `targetHeight`, statt sich
    /// auf einen einheitlichen pointSize-Parameter zu verlassen - dieselbe
    /// pointSize führt bei unterschiedlichen Symbolen zu unterschiedlichen
    /// Bildhöhen (key.fill z. B. ist breiter/diagonal, checkmark.circle/das
    /// Warndreieck eher quadratisch). Erst-Render bei einem Basiswert, dann
    /// - falls die Höhe erkennbar abweicht - ein zweiter Render-Durchlauf
    /// mit proportional angepasstem pointSize. Bewusst kein nachträgliches
    /// Strecken über NSTextAttachment.bounds (das hatte beim gefüllten
    /// Warndreieck schon einmal das Ausrufezeichen verschluckt, siehe
    /// iconText-Kommentar) - hier wird stattdessen jedes Mal echt neu bei
    /// der jeweils passenden pointSize gerendert.
    private static func symbolMatchingHeight(_ name: String, color: NSColor?, targetHeight: CGFloat) -> NSImage? {
        let basePointSize = NSFont.systemFontSize
        guard let baseImage = Self.symbol(name, color: color, pointSize: basePointSize), baseImage.size.height > 0
        else { return nil }

        let ratio = targetHeight / baseImage.size.height
        guard abs(ratio - 1) > 0.02 else { return baseImage }  // schon nah genug dran

        return Self.symbol(name, color: color, pointSize: basePointSize * ratio) ?? baseImage
    }

    /// Fetter Titel + Info-Symbol am Zeilenende + kleine graue Unterzeile
    /// (Zusammenfassung), alles in EINEM NSMenuItem statt zwei separaten
    /// Zeilen - jede NSMenuItem-Zeile hat eine feste Mindesthöhe, zwei
    /// Zeilen für Überschrift+Zusammenfassung nehmen also unnötig viel
    /// Platz weg. Ein eingebettetes "\n" in einem NSMenuItem-attributedTitle
    /// erzeugt zuverlässig eine zweite, kompaktere Zeile innerhalb
    /// derselben Zeilenhöhen-Berechnung.
    /// Einzeilig, mit einem kleinen Info-Symbol am Zeilenende - zeigt an,
    /// dass die ganze Zeile anklickbar ist und eine Erklärung öffnet
    /// (showInfo(_:)). WICHTIG: bewusst einzeilig, kein eingebettetes "\n"
    /// mehr. Ein früherer Versuch, Überschrift+Zusammenfassung platzsparend
    /// in EINEM NSMenuItem mit zweizeiligem attributedTitle
    /// unterzubringen, hat dazu geführt, dass praktisch der gesamte
    /// Menüpunkt nicht mehr auf Klicks reagierte - sichtbar korrekt
    /// gerendert, aber nicht mehr klickbar. Reproduziert an mehreren
    /// unabhängigen Stellen (DMARC-/TLS-RPT-/Übersprungen-Kopfzeile, DNS-
    /// Prüfen-Zeile), während normale einzeilige Menüpunkte (z. B. "Jetzt
    /// abrufen", "Einstellungen…") die ganze Zeit zuverlässig funktioniert
    /// haben - NSMenuItem unterstützt mehrzeilige attributedTitle-Inhalte
    /// offenbar nur fürs Rendering, nicht fürs Hit-Testing/Klick-Routing.
    /// Titel+Zusammenfassung stehen deshalb wieder in zwei separaten
    /// NSMenuItems (siehe Aufrufer), nicht mehr in einem gemeinsamen.
    private static func titleWithTrailingIcon(_ title: String, symbol name: String) -> NSAttributedString {
        let result = NSMutableAttributedString(
            string: title + "  ",
            attributes: [.font: NSFont.boldSystemFont(ofSize: NSFont.systemFontSize)]
        )
        if let image = Self.symbol(name, pointSize: NSFont.systemFontSize * 0.85) {
            let attachment = NSTextAttachment()
            attachment.image = image
            let size = image.size
            attachment.bounds = CGRect(
                x: 0, y: (NSFont.systemFontSize - size.height) / 2 - 1, width: size.width, height: size.height
            )
            result.append(NSAttributedString(attachment: attachment))
        }
        return result
    }

    /// Kompakte Variante: Titel (+ optionales Trailing-Symbol) und eine
    /// kleine graue Unterzeile in EINEM NSMenuItem statt zwei separaten
    /// Zeilen. War fälschlich als Ursache eines Klick-Bugs verdächtigt
    /// worden (siehe mouseEntered/mouseExited-Kommentar oben) - der
    /// eigentliche Fehler lag an einer falschen @objc-Selektor-Erzeugung
    /// für die Hover-Tracking-Area, nicht an mehrzeiligen attributedTitle-
    /// Inhalten. Mehrzeilige Titel funktionieren in NSMenuItem einwandfrei,
    /// sobald Klicks im Rest der App wieder normal ankommen.
    private static func compactHeaderTitle(_ title: String, subtitle: String, icon: String?) -> NSAttributedString {
        let result = NSMutableAttributedString(
            string: title + (icon != nil ? "  " : ""),
            attributes: [.font: NSFont.systemFont(ofSize: NSFont.systemFontSize)]
        )
        if let icon, let image = Self.symbol(icon, pointSize: NSFont.systemFontSize * 0.85) {
            let attachment = NSTextAttachment()
            attachment.image = image
            let size = image.size
            attachment.bounds = CGRect(
                x: 0, y: (NSFont.systemFontSize - size.height) / 2 - 1, width: size.width, height: size.height
            )
            result.append(NSAttributedString(attachment: attachment))
        }
        result.append(NSAttributedString(string: "\n"))
        result.append(
            NSAttributedString(
                string: subtitle,
                attributes: [
                    .font: NSFont.systemFont(ofSize: NSFont.smallSystemFontSize),
                    .foregroundColor: NSColor.secondaryLabelColor,
                ]
            )
        )
        return result
    }

    private static let isoDateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd"
        formatter.locale = Locale(identifier: "en_US_POSIX")
        return formatter
    }()

    private static let germanDateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "dd.MM.yyyy"
        formatter.locale = Locale(identifier: "de_DE")
        return formatter
    }()

    /// config.py schreibt checked_at als reines ISO-Datum ("yyyy-MM-dd",
    /// siehe cli.py `time.strftime("%Y-%m-%d")`) - hier fürs Menü ins
    /// gewohnte deutsche Format (TT.MM.JJJJ) umgewandelt. Fällt bei einem
    /// unerwarteten Format auf den Rohwert zurück statt auf einen Absturz
    /// oder eine leere Anzeige.
    private static func germanDate(_ isoDate: String) -> String {
        guard let date = isoDateFormatter.date(from: isoDate) else { return isoDate }
        return germanDateFormatter.string(from: date)
    }
}
