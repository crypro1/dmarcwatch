// Einmaliges Hilfsskript: erzeugt AppIcon.iconset (alle von iconutil
// geforderten Größen) aus einem SF Symbol auf einem abgerundeten
// Farbverlaufs-Hintergrund. Kein Teil des eigentlichen App-Targets, nur
// per `swift generate_icon.swift` von Hand ausgeführt, wenn sich das Icon
// mal ändern soll.
import AppKit

let sizes: [(name: String, px: Int)] = [
    ("icon_16x16", 16),
    ("icon_16x16@2x", 32),
    ("icon_32x32", 32),
    ("icon_32x32@2x", 64),
    ("icon_128x128", 128),
    ("icon_128x128@2x", 256),
    ("icon_256x256", 256),
    ("icon_256x256@2x", 512),
    ("icon_512x512", 512),
    ("icon_512x512@2x", 1024),
]

let outputDir = "AppIcon.iconset"
try? FileManager.default.createDirectory(atPath: outputDir, withIntermediateDirectories: true)

func renderIcon(pixelSize: Int) -> NSBitmapImageRep {
    let size = CGFloat(pixelSize)
    let rep = NSBitmapImageRep(
        bitmapDataPlanes: nil,
        pixelsWide: pixelSize,
        pixelsHigh: pixelSize,
        bitsPerSample: 8,
        samplesPerPixel: 4,
        hasAlpha: true,
        isPlanar: false,
        colorSpaceName: .deviceRGB,
        bytesPerRow: 0,
        bitsPerPixel: 0
    )!
    rep.size = NSSize(width: size, height: size)

    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)

    // Abgerundetes Quadrat als Hintergrund, wie bei macOS-App-Icons üblich
    // (Apple maskiert Drittanbieter-Icons nicht automatisch in die
    // "Squircle" - das Icon muss die Form schon mitbringen).
    let cornerRadius = size * 0.225
    let backgroundRect = NSRect(x: 0, y: 0, width: size, height: size)
    let path = NSBezierPath(roundedRect: backgroundRect, xRadius: cornerRadius, yRadius: cornerRadius)

    let topColor = NSColor(calibratedRed: 0.20, green: 0.47, blue: 0.98, alpha: 1.0)
    let bottomColor = NSColor(calibratedRed: 0.11, green: 0.29, blue: 0.75, alpha: 1.0)
    let gradient = NSGradient(starting: topColor, ending: bottomColor)
    path.addClip()
    gradient?.draw(in: backgroundRect, angle: -90)

    // Weißes Schild-Symbol zentriert, mit Rand passend zum macOS-Icon-Raster.
    // Zwei Palettenfarben statt einer: der Haken in "checkmark.shield.fill"
    // ist ein transparenter Ausschnitt im Schild, keine eigene Ebene - mit
    // nur einer Farbe verschwindet er beim Rendern in eine Bitmap
    // (dieselbe Ursache wie beim Warndreieck in der Statusleiste). Erste
    // Farbe = Haken, zweite = Schild-Füllung.
    let symbolConfig = NSImage.SymbolConfiguration(pointSize: size * 0.52, weight: .medium)
        .applying(NSImage.SymbolConfiguration(paletteColors: [topColor, .white]))
    if let symbol = NSImage(systemSymbolName: "checkmark.shield.fill", accessibilityDescription: nil)?
        .withSymbolConfiguration(symbolConfig) {
        let symbolSize = symbol.size
        let origin = NSPoint(x: (size - symbolSize.width) / 2, y: (size - symbolSize.height) / 2)
        symbol.draw(at: origin, from: .zero, operation: .sourceOver, fraction: 1.0)
    }

    NSGraphicsContext.restoreGraphicsState()
    return rep
}

for (name, px) in sizes {
    let rep = renderIcon(pixelSize: px)
    guard let data = rep.representation(using: .png, properties: [:]) else { continue }
    let path = "\(outputDir)/\(name).png"
    try? data.write(to: URL(fileURLWithPath: path))
    print("wrote \(path) (\(px)x\(px))")
}
