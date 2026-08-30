import Charts
import SwiftUI

/// Kompakter Statistik-Überblick - bewusst nicht Form/Section (siehe
/// SetupView.swift-Kommentar zu den zwei echten Layout-Bugs damit),
/// gleicher selbst gebauter Karten-Stil wie SetupView/DNSVerifyView.
/// Nur zwei Zustände statt einer dreistufigen Bewertung (sauber/auffällig,
/// keine eigene "Warnung"-Stufe) - dmarcwatch klassifiziert Records
/// ohnehin nur binär (siehe anomaly.py), eine zusätzliche Stufe nur für
/// diese eine Ansicht wäre eine eigene, größere Bewertungslogik statt
/// einer einfachen neuen Sicht auf schon vorhandene Daten.
struct StatsView: View {
    @ObservedObject var viewModel: StatsViewModel
    var onClose: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Text("Statistik")
                    .font(.headline)
                Spacer()
                Picker("", selection: $viewModel.days) {
                    Text("7 Tage").tag(7)
                    Text("30 Tage").tag(30)
                    Text("90 Tage").tag(90)
                }
                .pickerStyle(.segmented)
                .frame(width: 220)
                .onChange(of: viewModel.days) { viewModel.run() }
            }
            .padding(.horizontal, 20)
            .padding(.top, 20)

            Group {
                if viewModel.isLoading {
                    HStack(spacing: 8) {
                        ProgressView().controlSize(.small)
                        Text("Lädt…")
                    }
                    .padding(.horizontal, 20)
                } else if let error = viewModel.errorMessage {
                    Text(error)
                        .foregroundColor(.red)
                        .font(.callout)
                        .fixedSize(horizontal: false, vertical: true)
                        .padding(.horizontal, 20)
                } else if let response = viewModel.response {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 16) {
                            dmarcOverviewCard(response)
                            if !response.mtaStsReadiness.isEmpty {
                                tlsOverviewCard(response)
                            }
                            trendCard(response)
                            Text(
                                "Hinweis: basiert nur auf bisher gemeldeten Reports - DMARC-/TLS-RPT-Reporting "
                                + "ist branchenweit lückenhaft (nicht jeder Empfänger meldet), keine Garantie."
                            )
                            .font(.caption2).foregroundStyle(.secondary)
                            dmarcReadinessCard(response)
                            mtaStsReadinessCard(response)
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
        .frame(width: 640, height: 1000)
    }

    private func dmarcOverviewCard(_ response: StatsResponse) -> some View {
        let clean = response.daily.reduce(0) { $0 + $1.cleanCount }
        let flagged = response.daily.reduce(0) { $0 + $1.flaggedCount }
        return donutCard(
            title: "DMARC-Überblick · letzte \(response.days) Tage",
            segments: [("sauber", clean, Color.green), ("auffällig", flagged, Color.red)]
        )
    }

    private func tlsOverviewCard(_ response: StatsResponse) -> some View {
        let successful = response.tlsDaily.reduce(0) { $0 + $1.successfulCount }
        let failures = response.tlsDaily.reduce(0) { $0 + $1.failureCount }
        // Orange statt Rot für Fehlschläge - dieselbe Farbe wie die
        // TLS-RPT-Linie im Tagestrend darunter, damit beide als
        // zusammengehörig erkennbar sind (DMARC bleibt Grün/Rot).
        return donutCard(
            title: "TLS-RPT-Überblick · letzte \(response.days) Tage",
            segments: [("erfolgreich", successful, Color.green), ("fehlgeschlagen", failures, Color.orange)]
        )
    }

    /// Gemeinsamer Ring+Legende-Aufbau für DMARC- und TLS-RPT-Überblick -
    /// dieselbe Struktur, nur andere Segmente/Farben.
    private func donutCard(title: String, segments: [(label: String, count: Int, color: Color)]) -> some View {
        let total = segments.reduce(0) { $0 + $1.count }
        return card {
            Text(title).font(.subheadline.bold()).foregroundStyle(.secondary)
            if total == 0 {
                Text("Keine Daten im Zeitraum.").font(.callout).foregroundStyle(.secondary)
            } else {
                HStack(spacing: 20) {
                    Chart {
                        ForEach(segments, id: \.label) { segment in
                            SectorMark(angle: .value(segment.label, segment.count), innerRadius: .ratio(0.65), angularInset: 1.5)
                                .foregroundStyle(segment.color)
                        }
                    }
                    .frame(width: 64, height: 64)

                    VStack(alignment: .leading, spacing: 4) {
                        ForEach(segments, id: \.label) { segment in
                            HStack(spacing: 6) {
                                Circle().fill(segment.color).frame(width: 8, height: 8)
                                Text("\(segment.count) \(segment.label)")
                            }
                        }
                        Text("\(total) insgesamt").foregroundStyle(.secondary)
                    }
                    .font(.callout)
                }
            }
        }
    }

    private func trendCard(_ response: StatsResponse) -> some View {
        card {
            Text("Tagestrend").font(.subheadline.bold()).foregroundStyle(.secondary)
            if response.daily.isEmpty && response.tlsDaily.isEmpty {
                Text("Keine Daten für eine Trendlinie.").font(.callout).foregroundStyle(.secondary)
            } else {
                // Echte Zeit-x-Achse (Date) statt roher ISO-Strings als
                // Text-Kategorien - eine Text-Achse würde JEDEN Tag einzeln
                // und ungekürzt beschriften, egal wie viele es sind (siehe
                // dateValue-Kommentar in Models.swift). Deutsches
                // Kurzformat (TT.MM.) über die FormatStyle statt einer
                // rohen ISO-Zeichenkette.
                //
                // TLS-RPT-Fehlschläge als dritte Linie im selben Chart statt
                // einer eigenen Karte - zwei ForEach-Blöcke statt
                // Chart(data:), da DMARC- und TLS-RPT-Tage aus zwei
                // unterschiedlichen Arrays kommen, sich aber x-/y-Achse
                // teilen sollen. Nur Fehlschläge, nicht erfolgreiche
                // Sitzungen - deren Anzahl läge typischerweise weit über
                // den DMARC-Zahlen und würde die gemeinsame y-Achse verzerren.
                //
                // foregroundStyle(by:)/symbol(by:) statt direkter
                // .foregroundStyle(Color...) pro Linie - nur so erzeugt
                // Swift Charts automatisch eine Legende (chartForegroundStyleScale
                // ordnet den Seriennamen dabei die gewünschten Farben zu).
                Chart {
                    ForEach(response.daily) { day in
                        LineMark(x: .value("Tag", day.dateValue), y: .value("Anzahl", day.cleanCount))
                            .foregroundStyle(by: .value("Serie", "DMARC sauber"))
                            .symbol(by: .value("Serie", "DMARC sauber"))
                        LineMark(x: .value("Tag", day.dateValue), y: .value("Anzahl", day.flaggedCount))
                            .foregroundStyle(by: .value("Serie", "DMARC auffällig"))
                            .symbol(by: .value("Serie", "DMARC auffällig"))
                    }
                    ForEach(response.tlsDaily) { day in
                        LineMark(x: .value("Tag", day.dateValue), y: .value("Anzahl", day.failureCount))
                            .foregroundStyle(by: .value("Serie", "TLS-RPT Fehlschläge"))
                            .symbol(by: .value("Serie", "TLS-RPT Fehlschläge"))
                    }
                }
                .chartForegroundStyleScale([
                    "DMARC sauber": Color.green,
                    "DMARC auffällig": Color.red,
                    "TLS-RPT Fehlschläge": Color.orange,
                ])
                .chartXAxis {
                    AxisMarks(values: .automatic(desiredCount: 5)) { value in
                        AxisGridLine()
                        AxisTick()
                        if let date = value.as(Date.self) {
                            AxisValueLabel(date.formatted(.dateTime.day(.twoDigits).month(.twoDigits).locale(Locale(identifier: "de_DE"))))
                        }
                    }
                }
                .frame(height: 160)
            }
        }
    }

    // Mindest-Stichprobengröße - gespiegelt aus report.py:MIN_SAMPLE_SIZE
    // (kein JSON-Feld, da nur für die Erklärtexte hier gebraucht, nicht
    // Teil der eigentlichen Berechnung, die immer schon serverseitig
    // passiert ist).
    private static let minSampleSize = 10

    @ViewBuilder
    private func dmarcReadinessCard(_ response: StatsResponse) -> some View {
        card {
            Text("DMARC-Verschärfung").font(.subheadline.bold()).foregroundStyle(.secondary)
            if response.dmarcReadiness.isEmpty {
                Text("Keine Reports im Zeitraum, keine Einschätzung möglich.")
                    .font(.callout).foregroundStyle(.secondary)
            }
            ForEach(response.dmarcReadiness) { r in
                VStack(alignment: .leading, spacing: 4) {
                    Text(r.domain).font(.callout.bold())
                    Text("Aktuelle Policy: p=\(r.currentPolicy ?? "?"), pct=\(r.currentPct.map(String.init) ?? "?")")
                        .font(.caption).foregroundStyle(.secondary)
                    Text("\(r.totalCount) E-Mails, davon \(r.unknownIpFailures) von unbekannten IPs")
                        .font(.caption).foregroundStyle(.secondary)
                    if r.hasReportingGap {
                        Text("⚠ Lücke von \(r.reportingGapDays) Tagen ohne jeden Report - vermutlich zwischenzeitlich ausgefallener Abruf.")
                            .font(.caption2).foregroundStyle(.orange)
                    }
                    if r.needsRecheck {
                        Text("⚠ Bereits bei p=reject, aber own_ip_auth_fail zuletzt am \(r.lastFailureDate ?? "?") - own_ip_networks/SPF/DKIM prüfen (zählt erst ab neuen Reports).")
                            .font(.caption2).foregroundStyle(.orange)
                    }
                    if r.fullyEnforced {
                        readinessPill(label: "Vollständig durchgesetzt (p=reject, pct=100)", isReady: true)
                    } else if r.readyForNextStep {
                        readinessPill(
                            label: "Bereit für p=\(r.nextRecommendedPolicy ?? "?"), pct=\(r.nextRecommendedPct.map(String.init) ?? "?")",
                            isReady: true
                        )
                    } else {
                        VStack(alignment: .leading, spacing: 2) {
                            readinessPill(
                                label: "Noch nicht bereit für p=\(r.nextRecommendedPolicy ?? "?"), pct=\(r.nextRecommendedPct.map(String.init) ?? "?")",
                                isReady: false
                            )
                            if r.ownIpAuthFailures > 0 && r.cleanDays < r.recommendedObservationDays {
                                Text("Own-IP-Fehlschlag zuletzt am \(r.lastFailureDate ?? "?").")
                                    .font(.caption2).foregroundStyle(.secondary)
                            } else if r.cleanDays < r.recommendedObservationDays {
                                Text(
                                    String(
                                        format: "Bei %.1f E-Mails/Tag werden mind. %d Tage seit dem letzten Fehlschlag empfohlen, bisher %d Tage sauber.",
                                        r.avgDailyVolume, r.recommendedObservationDays, r.cleanDays
                                    )
                                )
                                .font(.caption2).foregroundStyle(.secondary)
                            }
                            if r.totalCount < Self.minSampleSize {
                                Text("Erst \(r.totalCount) E-Mails insgesamt beobachtet (mind. \(Self.minSampleSize) empfohlen).")
                                    .font(.caption2).foregroundStyle(.secondary)
                            }
                        }
                    }
                }
            }
        }
    }

    @ViewBuilder
    private func mtaStsReadinessCard(_ response: StatsResponse) -> some View {
        card {
            Text("MTA-STS-Verschärfung").font(.subheadline.bold()).foregroundStyle(.secondary)
            if response.mtaStsReadiness.isEmpty {
                Text("Keine TLS-RPT-Reports im Zeitraum, keine Einschätzung möglich.")
                    .font(.callout).foregroundStyle(.secondary)
            }
            ForEach(response.mtaStsReadiness) { m in
                VStack(alignment: .leading, spacing: 4) {
                    Text(m.domain).font(.callout.bold())
                    if m.totalFailureCount > 0 {
                        let types = m.failureTypes.sorted { $0.key < $1.key }
                            .map { "\($0.key) (\($0.value))" }.joined(separator: ", ")
                        Text("\(m.totalFailureCount) TLS-Fehlschläge" + (types.isEmpty ? "" : " - \(types)"))
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    if m.hasReportingGap {
                        Text("⚠ Lücke von \(m.reportingGapDays) Tagen ohne jeden Report - vermutlich zwischenzeitlich ausgefallener Abruf.")
                            .font(.caption2).foregroundStyle(.orange)
                    }
                    if m.readyForEnforce {
                        readinessPill(label: "Bereit für mode=enforce", isReady: true)
                    } else {
                        VStack(alignment: .leading, spacing: 2) {
                            readinessPill(label: "Noch nicht bereit", isReady: false)
                            if m.totalFailureCount > 0 && m.cleanDays < m.recommendedObservationDays {
                                Text("Letzter TLS-Fehlschlag am \(m.lastFailureDate ?? "?").")
                                    .font(.caption2).foregroundStyle(.secondary)
                            } else if m.cleanDays < m.recommendedObservationDays {
                                Text(
                                    String(
                                        format: "Bei %.1f TLS-Sitzungen/Tag werden mind. %d Tage seit dem letzten Fehlschlag empfohlen, bisher %d Tage sauber.",
                                        m.avgDailyVolume, m.recommendedObservationDays, m.cleanDays
                                    )
                                )
                                .font(.caption2).foregroundStyle(.secondary)
                            }
                            if m.totalSessions < Self.minSampleSize {
                                Text("Erst \(m.totalSessions) TLS-Sitzungen insgesamt beobachtet (mind. \(Self.minSampleSize) empfohlen).")
                                    .font(.caption2).foregroundStyle(.secondary)
                            }
                        }
                    }
                }
            }
        }
    }

    private func readinessPill(label: String, isReady: Bool) -> some View {
        Text(label)
            .font(.caption.bold())
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background(Capsule().fill((isReady ? Color.green : Color.orange).opacity(0.2)))
            .foregroundStyle(isReady ? Color.green : Color.orange)
    }

    @ViewBuilder
    private func card<Content: View>(@ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            content()
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 10).fill(Color(nsColor: .controlBackgroundColor)))
        .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Color(nsColor: .separatorColor), lineWidth: 0.5))
    }
}
