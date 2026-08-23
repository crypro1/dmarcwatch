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
    let hasWarnings: Bool

    enum CodingKeys: String, CodingKey {
        case domain, dmarc, spf, dkim
        case mtaSts = "mta_sts"
        case tlsrptDns = "tlsrpt_dns"
        case wildcardSpf = "wildcard_spf"
        case mxBlacklist = "mx_blacklist"
        case hasWarnings = "has_warnings"
    }

    // decodeIfPresent für mxBlacklist statt synthetisierter Konformität:
    // last_dns_check.json ist ein von einem FRÜHEREN `verify-dns`-Lauf
    // persistierter, roher Dict-Schnappschuss (siehe config.py
    // read_dns_check_result) - eine bereits vorhandene Datei aus der Zeit
    // vor diesem Feld hätte sonst beim nächsten App-Start/Hover die
    // komplette Dekodierung von MenubarReport zum Scheitern gebracht (nicht
    // nur dieses eine Feld leer gelassen), bis der nächste verify-dns-Lauf
    // die Datei überschreibt. Gleiche Begründung wie bei
    // MenubarReport.skippedItems/dnsCheck oben.
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

    enum CodingKeys: String, CodingKey {
        case domain, dmarc, spf, dkim
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
