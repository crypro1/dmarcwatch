// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "DmarcwatchMenuBar",
    // v13 (Ventura): SMAppService (LoginItemManager.swift) gibt es erst ab
    // macOS 13 - vorher nur die alte, jetzt entfernte plist-Installation.
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(
            name: "DmarcwatchMenuBar",
            path: "Sources/DmarcwatchMenuBar"
        )
    ]
)
