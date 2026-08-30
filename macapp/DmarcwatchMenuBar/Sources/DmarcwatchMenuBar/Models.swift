import Foundation

// Spiegelt report.to_json_dict() aus dem Python-Paket
// (dmarcwatch menubar-json). Feldnamen dort sind snake_case, hier
// camelCase über CodingKeys gemappt.

struct MenubarReport: Decodable {
    let days: Int
    let totalCount: Int
    let flaggedCount: Int
    let daysGrouped: [DayGroup]
    // Gründe, warum im letzten `fetch`-Lauf Nachrichten/Anhänge übersprungen
    // wurden (z. B. eine abgelehnte Dekompressionsbombe) - kommt aus
    // config.read_skipped_items(), bereits serverseitig sanitisiert.
    let skippedItems: [String]
    // Ergebnis der letzten verify-dns-Prüfung (Klick auf "DNS prüfen…" oder
    // periodischer automatischer Check) - nil, wenn noch nie geprüft wurde.
    let dnsCheck: DNSCheckSummary?

    enum CodingKeys: String, CodingKey {
        case days
        case totalCount = "total_count"
        case flaggedCount = "flagged_count"
        case daysGrouped = "days_grouped"
        case skippedItems = "skipped_items"
        case dnsCheck = "dns_check"
    }

    // decodeIfPresent statt der automatisch generierten Synthese: eine
    // synthetisierte Codable-Konformität würde bei fehlendem
    // "skipped_items"-Schlüssel (z. B. venv und App-Bundle kurzzeitig auf
    // unterschiedlichem Stand während eines Updates) die komplette
    // Dekodierung scheitern lassen, nicht nur dieses eine Feld leer lassen.
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        days = try container.decode(Int.self, forKey: .days)
        totalCount = try container.decode(Int.self, forKey: .totalCount)
        flaggedCount = try container.decode(Int.self, forKey: .flaggedCount)
        daysGrouped = try container.decode([DayGroup].self, forKey: .daysGrouped)
        skippedItems = try container.decodeIfPresent([String].self, forKey: .skippedItems) ?? []
        dnsCheck = try container.decodeIfPresent(DNSCheckSummary.self, forKey: .dnsCheck)
    }
}

/// Spiegelt config.read_dns_check_result() aus dem Python-Paket - egal ob
/// durch Klick auf "DNS prüfen…" oder den periodischen automatischen Check
/// (enable_auto_dns_check) befüllt.
struct DNSCheckSummary: Decodable {
    let checkedAt: String
    let domains: [DNSCheckDomainResult]

    enum CodingKeys: String, CodingKey {
        case checkedAt = "checked_at"
        case domains
    }
}

struct DNSCheckDomainResult: Decodable {
    let domain: String
    let dmarc: DMARCCheck
    let spf: SPFCheck
    let dkim: [DKIMCheck]
    let mtaSts: MTASTSCheck
    let tlsrptDns: TLSRPTDNSCheck
    let wildcardSpf: WildcardSPFCheck
    let mxBlacklist: MXBlacklistCheck
    let dnssec: DNSSECCheck
    let dane: DANECheck
    let bimi: BIMICheck
    let hasWarnings: Bool

    enum CodingKeys: String, CodingKey {
        case domain, dmarc, spf, dkim, dnssec, dane, bimi
        case mtaSts = "mta_sts"
        case tlsrptDns = "tlsrpt_dns"
        case wildcardSpf = "wildcard_spf"
        case mxBlacklist = "mx_blacklist"
        case hasWarnings = "has_warnings"
    }

    // decodeIfPresent für mxBlacklist/dnssec/dane/bimi statt synthetisierter
    // Konformität: last_dns_check.json ist ein von einem FRÜHEREN
    // `verify-dns`-Lauf persistierter, roher Dict-Schnappschuss (siehe
    // config.py read_dns_check_result) - eine bereits vorhandene Datei aus
    // der Zeit vor einem dieser Felder hätte sonst beim nächsten
    // App-Start/Hover die komplette Dekodierung von MenubarReport zum
    // Scheitern gebracht (nicht nur dieses eine Feld leer gelassen), bis
    // der nächste verify-dns-Lauf die Datei überschreibt. Gleiche
    // Begründung wie bei MenubarReport.skippedItems/dnsCheck oben.
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        domain = try container.decode(String.self, forKey: .domain)
        dmarc = try container.decode(DMARCCheck.self, forKey: .dmarc)
        spf = try container.decode(SPFCheck.self, forKey: .spf)
        dkim = try container.decode([DKIMCheck].self, forKey: .dkim)
        mtaSts = try container.decode(MTASTSCheck.self, forKey: .mtaSts)
        tlsrptDns = try container.decode(TLSRPTDNSCheck.self, forKey: .tlsrptDns)
        wildcardSpf = try container.decode(WildcardSPFCheck.self, forKey: .wildcardSpf)
        mxBlacklist = try container.decodeIfPresent(MXBlacklistCheck.self, forKey: .mxBlacklist)
            ?? MXBlacklistCheck(checked: false, mxHosts: [], listed: [], warnings: [])
        dnssec = try container.decodeIfPresent(DNSSECCheck.self, forKey: .dnssec)
            ?? DNSSECCheck(configured: false, validated: nil, warnings: [])
        dane = try container.decodeIfPresent(DANECheck.self, forKey: .dane)
            ?? DANECheck(configured: false, mxHostsWithTlsa: [], warnings: [])
        bimi = try container.decodeIfPresent(BIMICheck.self, forKey: .bimi)
            ?? BIMICheck(configured: false, record: nil, logoSvg: nil, logoReachable: nil, warnings: [])
        hasWarnings = try container.decode(Bool.self, forKey: .hasWarnings)
    }
}

/// Spamhaus-ZEN-Prüfung der eigenen MX-Server-IP(s) (siehe blacklist.py) -
/// checked ist false, wenn kein MX gefunden wurde oder die Abfrage
/// fehlschlug, dann gibt es nichts anzuzeigen (kein MX heißt meist einfach,
/// dass die Domain selbst keine Mail empfängt).
struct MXBlacklistCheck: Decodable {
    let checked: Bool
    let mxHosts: [String]
    let listed: [String]
    let warnings: [String]

    enum CodingKeys: String, CodingKey {
        case checked, warnings, listed
        case mxHosts = "mx_hosts"
    }
}

/// DNSSEC - schützt die Integrität aller anderen hier geprüften
/// DNS-Einträge. Optional wie MTA-STS/TLS-RPT-DNS/Wildcard-SPF, keine
/// Warnung bei komplettem Fehlen. validated ist nil, solange nicht
/// configured, sonst das Ergebnis einer echten Validierung über einen
/// extern bekannt validierenden Resolver (siehe dns_verify.py).
struct DNSSECCheck: Decodable {
    let configured: Bool
    let validated: Bool?
    let warnings: [String]
}

/// DANE/TLSA für SMTP - Sicherheit hängt vollständig von DNSSEC ab, siehe
/// dns_verify.py-Kommentar. Optional, keine Warnung bei komplettem Fehlen.
struct DANECheck: Decodable {
    let configured: Bool
    let mxHostsWithTlsa: [String]
    let warnings: [String]

    enum CodingKeys: String, CodingKey {
        case configured, warnings
        case mxHostsWithTlsa = "mx_hosts_with_tlsa"
    }
}

/// BIMI (Markenlogo in unterstützenden Mail-Clients) - optional, keine
/// Warnung bei komplettem Fehlen. Braucht bei den meisten Anbietern eine
/// durchgesetzte DMARC-Policy, sonst wird trotz korrektem Eintrag kein
/// Logo angezeigt (siehe dns_verify.py check_bimi).
struct BIMICheck: Decodable {
    let configured: Bool
    let record: String?
    // Der tatsächlich abgerufene SVG-Inhalt der Logo-Datei (siehe
    // dns_verify.py:check_bimi/_fetch_bimi_logo) - nil, wenn kein
    // 'l='-Tag da ist oder der Abruf fehlschlägt. Optional-typisierte
    // Felder werden von Swifts synthetisierter Decodable-Konformität
    // automatisch mit decodeIfPresent behandelt, deshalb kein eigener
    // init(from:) nötig wie bei DNSCheckDomainResult oben.
    let logoSvg: String?
    let logoReachable: Bool?
    let warnings: [String]

    enum CodingKeys: String, CodingKey {
        case configured, record, warnings
        case logoSvg = "logo_svg"
        case logoReachable = "logo_reachable"
    }
}

/// Optional/fortgeschritten (siehe dns_verify.py-Kommentare) - `configured`
/// ist false, wenn die Domain das gar nicht nutzt, dann sind `warnings`
/// immer leer (kein Fehlen-Hinweis, nur ein angefangenes, kaputtes Setup
/// erzeugt Warnungen).
struct MTASTSCheck: Decodable {
    let configured: Bool
    let cnameTarget: String?
    let policyTxt: String?
    // nil, solange kein HTTPS-Abruf versucht wurde (z. B. weil noch nicht
    // mal der Hostname konfiguriert ist) - sonst das tatsächliche Ergebnis
    // des Abrufs der eigenen Policy-Datei (anbieterunabhängig).
    let policyReachable: Bool?
    let warnings: [String]

    enum CodingKeys: String, CodingKey {
        case configured, warnings
        case cnameTarget = "cname_target"
        case policyTxt = "policy_txt"
        case policyReachable = "policy_reachable"
    }
}

struct TLSRPTDNSCheck: Decodable {
    let configured: Bool
    let record: String?
    let warnings: [String]
}

struct WildcardSPFCheck: Decodable {
    let configured: Bool
    let record: String?
    let warnings: [String]
}

struct DayGroup: Codable {
    let date: String
    let flaggedCount: Int
    let records: [ReportRecord]

    enum CodingKeys: String, CodingKey {
        case date
        case flaggedCount = "flagged_count"
        case records
    }
}

struct ReportRecord: Codable {
    let orgName: String
    let sourceIp: String
    let count: Int
    let disposition: String
    let dkim: String
    let spf: String
    let envelopeTo: String
    let isFlagged: Bool
    let flagLabels: [String]
    // Nur gesetzt, wenn vorher per `dmarcwatch inspect --whois` explizit
    // nachgeschlagen und lokal gecacht - die App fragt selbst nie bei
    // rdap.org an. Rein informativ, keine Sicherheitseinstufung.
    let whoisOrganization: String?
    // Analog zu whoisOrganization, nur per `inspect --blacklist` gegen
    // Spamhaus ZEN statt RDAP. nil, solange nie geprüft.
    let blacklistListed: Bool?
    let blacklistReasons: [String]

    enum CodingKeys: String, CodingKey {
        case orgName = "org_name"
        case sourceIp = "source_ip"
        case count, disposition, dkim, spf
        case envelopeTo = "envelope_to"
        case isFlagged = "is_flagged"
        case flagLabels = "flag_labels"
        case whoisOrganization = "whois_organization"
        case blacklistListed = "blacklist_listed"
        case blacklistReasons = "blacklist_reasons"
    }
}

/// Nur die Felder, die die Setup-GUI zum Vorausfüllen braucht - kein
/// Passwort darin, das liegt ausschließlich im Schlüsselbund (siehe
/// config.py-Modul-Docstring im Python-Paket).
struct LocalConfig: Decodable {
    let imapHost: String?
    let imapPort: Int?
    let imapUser: String?
    let imapFolder: String?
    let ownDomains: [String]?
    let ownIpNetworks: [String]?
    let enableTlsRpt: Bool?
    let tlsrptImapFolder: String?
    let enableAutoDnsCheck: Bool?
    let autoDnsCheckIntervalDays: Int?

    enum CodingKeys: String, CodingKey {
        case imapHost = "imap_host"
        case imapPort = "imap_port"
        case imapUser = "imap_user"
        case imapFolder = "imap_folder"
        case ownDomains = "own_domains"
        case ownIpNetworks = "own_ip_networks"
        case enableTlsRpt = "enable_tls_rpt"
        case tlsrptImapFolder = "tlsrpt_imap_folder"
        case enableAutoDnsCheck = "enable_auto_dns_check"
        case autoDnsCheckIntervalDays = "auto_dns_check_interval_days"
    }
}

/// Antwort von `dmarcwatch resolve-spf <domain>` (siehe DmarcwatchCLI.runResolveSpf).
struct SPFResolveResponse: Decodable {
    let domain: String?
    let networks: [String]?
    let error: String?
}

/// Spiegelt _verification_to_dict() aus cli.py
/// (`dmarcwatch verify-dns --json`) - für das DNS-Prüfen-Fenster
/// (DNSVerifyView.swift).

struct DomainVerificationResponse: Decodable {
    let domain: String
    let dmarc: DMARCCheck
    let spf: SPFCheck
    let dkim: [DKIMCheck]
    let mtaSts: MTASTSCheck
    let tlsrptDns: TLSRPTDNSCheck
    let wildcardSpf: WildcardSPFCheck
    let mxBlacklist: MXBlacklistCheck
    let dnssec: DNSSECCheck
    let dane: DANECheck
    let bimi: BIMICheck

    enum CodingKeys: String, CodingKey {
        case domain, dmarc, spf, dkim, dnssec, dane, bimi
        case mtaSts = "mta_sts"
        case tlsrptDns = "tlsrpt_dns"
        case wildcardSpf = "wildcard_spf"
        case mxBlacklist = "mx_blacklist"
    }
}

struct DMARCCheck: Decodable {
    let exists: Bool
    let record: String?
    let policy: String?
    let subdomainPolicy: String?
    let pct: Int?
    let rua: String?
    let ruf: String?
    let adkim: String?
    let aspf: String?
    let warnings: [String]

    enum CodingKeys: String, CodingKey {
        case exists, record, policy, pct, rua, ruf, adkim, aspf, warnings
        case subdomainPolicy = "subdomain_policy"
    }
}

struct SPFCheck: Decodable {
    let exists: Bool
    let record: String?
    let lookupCount: Int
    let lookupLimitOk: Bool
    let warnings: [String]
    let error: String?

    enum CodingKeys: String, CodingKey {
        case exists, record, warnings, error
        case lookupCount = "lookup_count"
        case lookupLimitOk = "lookup_limit_ok"
    }
}

struct DKIMCheck: Decodable {
    let selector: String
    let exists: Bool
    let keyType: String?
    let warnings: [String]

    enum CodingKeys: String, CodingKey {
        case selector, exists, warnings
        case keyType = "key_type"
    }
}

/// Spiegelt to_tls_json_dict() aus report.py (`dmarcwatch tls-report --json`)
/// - für das TLS-RPT-Berichtsfenster (TLSReportView.swift). Rein lesend aus
/// der lokalen DB, kein Netzzugriff (anders als DNS-Prüfung/WHOIS).
struct TLSReportResponse: Decodable {
    let days: Int
    let totalFailureCount: Int
    let policies: [TLSPolicyEntry]

    enum CodingKeys: String, CodingKey {
        case days
        case totalFailureCount = "total_failure_count"
        case policies
    }
}

struct TLSPolicyEntry: Decodable {
    let date: String
    let organizationName: String
    let policyDomain: String
    let policyType: String
    let successfulSessionCount: Int
    let failureCount: Int
    let failureResultTypes: [String]

    enum CodingKeys: String, CodingKey {
        case date
        case organizationName = "organization_name"
        case policyDomain = "policy_domain"
        case policyType = "policy_type"
        case successfulSessionCount = "successful_session_count"
        case failureCount = "failure_count"
        case failureResultTypes = "failure_result_types"
    }
}

/// Spiegelt to_stats_json_dict() aus report.py (`dmarcwatch stats --json`)
/// - für das Statistik-Fenster (StatsView.swift). Rein lesend aus der
/// lokalen DB, kein Netzzugriff.
struct StatsResponse: Decodable {
    let days: Int
    let daily: [DayStatEntry]
    let tlsDaily: [TLSDayStatEntry]
    let dmarcReadiness: [DMARCReadinessEntry]
    let mtaStsReadiness: [MTASTSReadinessEntry]

    enum CodingKeys: String, CodingKey {
        case days, daily
        case tlsDaily = "tls_daily"
        case dmarcReadiness = "dmarc_readiness"
        case mtaStsReadiness = "mta_sts_readiness"
    }
}

struct DayStatEntry: Decodable, Identifiable {
    let date: String
    let cleanCount: Int
    let flaggedCount: Int

    var id: String { date }

    enum CodingKeys: String, CodingKey {
        case date
        case cleanCount = "clean_count"
        case flaggedCount = "flagged_count"
    }

    private static let isoFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd"
        formatter.locale = Locale(identifier: "en_US_POSIX")
        return formatter
    }()

    /// Für einen echten Zeit-x-Achsen in StatsView (statt einer rein
    /// kategorialen Text-Achse, die jedes Datum einzeln und ungekürzt
    /// beschriftet, egal wie viele Tage im Zeitraum liegen) - report.py
    /// liefert das Datum als reinen ISO-String ("yyyy-MM-dd").
    var dateValue: Date {
        Self.isoFormatter.date(from: date) ?? Date()
    }
}

struct TLSDayStatEntry: Decodable, Identifiable {
    let date: String
    let successfulCount: Int
    let failureCount: Int

    var id: String { date }

    enum CodingKeys: String, CodingKey {
        case date
        case successfulCount = "successful_count"
        case failureCount = "failure_count"
    }

    private static let isoFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd"
        formatter.locale = Locale(identifier: "en_US_POSIX")
        return formatter
    }()

    var dateValue: Date {
        Self.isoFormatter.date(from: date) ?? Date()
    }
}

/// Einschätzung pro Domain, ob der nächste Schritt einer gestaffelten
/// DMARC-Verschärfung (p=none -> quarantine 25/50/75/100 -> reject
/// 25/50/75/100, siehe report.py:_next_dmarc_rollout_step) im
/// Beobachtungszeitraum sicher gewesen wäre - unknownIpFailures zählt
/// bewusst NICHT gegen die Bereitschaft (potenzielle Spoofing-Versuche,
/// genau die soll eine schärfere Policy ja abfangen). cleanDays ist die
/// Zeit seit dem JÜNGSTEN ownIpAuthFailures-Vorfall (nicht "keiner
/// irgendwo im Fenster") - ein alter Vorfall heilt, sobald seitdem genug
/// Zeit vergangen ist. needsRecheck warnt unabhängig davon, wenn eine
/// bereits bei p=reject stehende Domain einen FRISCHEN own_ip_auth_fail
/// bekommt (siehe report.py:DMARCReadiness-Docstring für die volle
/// Begründung inkl. der own_ip_networks-Einschränkung).
struct DMARCReadinessEntry: Decodable, Identifiable {
    let domain: String
    let currentPolicy: String?
    let currentPct: Int?
    let totalCount: Int
    let unknownIpFailures: Int
    let ownIpAuthFailures: Int
    let avgDailyVolume: Double
    let recommendedObservationDays: Int
    let observedDays: Int
    let cleanDays: Int
    let lastFailureDate: String?
    let hasReportingGap: Bool
    let reportingGapDays: Int
    let nextRecommendedPolicy: String?
    let nextRecommendedPct: Int?
    let fullyEnforced: Bool
    let readyForNextStep: Bool
    let needsRecheck: Bool

    var id: String { domain }

    enum CodingKeys: String, CodingKey {
        case domain
        case currentPolicy = "current_policy"
        case currentPct = "current_pct"
        case totalCount = "total_count"
        case unknownIpFailures = "unknown_ip_failures"
        case ownIpAuthFailures = "own_ip_auth_failures"
        case avgDailyVolume = "avg_daily_volume"
        case recommendedObservationDays = "recommended_observation_days"
        case observedDays = "observed_days"
        case cleanDays = "clean_days"
        case lastFailureDate = "last_failure_date"
        case hasReportingGap = "has_reporting_gap"
        case reportingGapDays = "reporting_gap_days"
        case nextRecommendedPolicy = "next_recommended_policy"
        case nextRecommendedPct = "next_recommended_pct"
        case fullyEnforced = "fully_enforced"
        case readyForNextStep = "ready_for_next_step"
        case needsRecheck = "needs_recheck"
    }
}

/// Pendant zu DMARCReadinessEntry für MTA-STS, jetzt pro Domain (siehe
/// report.py:MTASTSReadiness-Docstring) - kein fullyEnforced/needsRecheck-
/// Pendant, da `stats` nicht wissen kann, ob mode=enforce live in der Zone
/// aktiv ist (nur der Live-Check in verify-dns weiß das). failureTypes
/// schlüsselt gemeldete TLS-Fehlschläge nach RFC-8460-Ergebnistyp auf,
/// gewichtet mit echten fehlgeschlagenen Sitzungen.
struct MTASTSReadinessEntry: Decodable, Identifiable {
    let domain: String
    let totalSessions: Int
    let totalFailureCount: Int
    let failureTypes: [String: Int]
    let avgDailyVolume: Double
    let recommendedObservationDays: Int
    let observedDays: Int
    let cleanDays: Int
    let lastFailureDate: String?
    let hasReportingGap: Bool
    let reportingGapDays: Int
    let readyForEnforce: Bool

    var id: String { domain }

    enum CodingKeys: String, CodingKey {
        case domain
        case totalSessions = "total_sessions"
        case totalFailureCount = "total_failure_count"
        case failureTypes = "failure_types"
        case avgDailyVolume = "avg_daily_volume"
        case recommendedObservationDays = "recommended_observation_days"
        case observedDays = "observed_days"
        case cleanDays = "clean_days"
        case lastFailureDate = "last_failure_date"
        case hasReportingGap = "has_reporting_gap"
        case reportingGapDays = "reporting_gap_days"
        case readyForEnforce = "ready_for_enforce"
    }
}

enum ConfigStore {
    /// Liest config.json direkt (kein Passwort enthalten, daher unbedenklich
    /// ohne Umweg über den Python-CLI-Subprozess) - für das einmalige
    /// Vorausfüllen des Setup-Formulars beim Öffnen.
    static func loadCurrent() -> LocalConfig? {
        let path = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/dmarcwatch/config.json")
        guard let data = try? Data(contentsOf: path) else { return nil }
        return try? JSONDecoder().decode(LocalConfig.self, from: data)
    }
}
