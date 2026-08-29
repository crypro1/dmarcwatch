import AppKit
import SwiftUI

/// Ein einzelnes, wiederverwendetes Fenster für die Statistik - analog zu
/// DNSVerifyWindowController.swift/SetupWindowController.swift.
final class StatsWindowController: NSWindowController {
    static let shared = StatsWindowController()

    private let viewModel = StatsViewModel()

    private convenience init() {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 600, height: 860),
            styleMask: [.titled, .closable],
            backing: .buffered,
            defer: false
        )
        window.title = "dmarcwatch – Statistik"
        window.isReleasedWhenClosed = false
        self.init(window: window)
    }

    func show() {
        window?.contentViewController = NSHostingController(
            rootView: StatsView(viewModel: viewModel, onClose: { [weak self] in
                self?.window?.close()
            })
        )
        NSApp.activate(ignoringOtherApps: true)
        window?.center()
        window?.makeKeyAndOrderFront(nil)
        viewModel.run()
    }
}
