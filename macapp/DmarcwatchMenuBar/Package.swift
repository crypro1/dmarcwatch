// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "DmarcwatchMenuBar",
    // v14 (Sonoma): SectorMark (Swift Charts, StatsView.swift) gibt es erst
    // ab macOS 14 - v13 hätte hier nur die Balkendiagramm-Variante ohne
    // Kreisdiagramm erlaubt. SMAppService (LoginItemManager.swift) selbst
    // bräuchte nur v13.
    platforms: [.macOS(.v14)],
    targets: [
        .executableTarget(
            name: "DmarcwatchMenuBar",
            path: "Sources/DmarcwatchMenuBar"
        )
    ]
)
