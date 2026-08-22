import Foundation

// Spiegelt report.to_json_dict() aus dem Python-Paket
// (dmarcwatch menubar-json). Feldnamen dort sind snake_case, hier
// camelCase über CodingKeys gemappt.

struct MenubarReport: Codable {
    let days: Int
    let totalCount: Int
    let flaggedCount: Int
    let daysGrouped: [DayGroup]

    enum CodingKeys: String, CodingKey {
        case days
        case totalCount = "total_count"
        case flaggedCount = "flagged_count"
        case daysGrouped = "days_grouped"
    }
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

    enum CodingKeys: String, CodingKey {
        case orgName = "org_name"
        case sourceIp = "source_ip"
        case count, disposition, dkim, spf
        case envelopeTo = "envelope_to"
        case isFlagged = "is_flagged"
        case flagLabels = "flag_labels"
        case whoisOrganization = "whois_organization"
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

    enum CodingKeys: String, CodingKey {
        case imapHost = "imap_host"
        case imapPort = "imap_port"
        case imapUser = "imap_user"
        case imapFolder = "imap_folder"
        case ownDomains = "own_domains"
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
