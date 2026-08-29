import AppKit
import SwiftUI

/// Ein einzelnes, wiederverwendetes Fenster für die DNS-Prüfung - analog
/// zu SetupWindowController.swift.
final class DNSVerifyWindowController: NSWindowController {
    static let shared = DNSVerifyWindowController()

    private let viewModel = DNSVerifyViewModel()

    private convenience init() {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 700, height: 920),
            styleMask: [.titled, .closable],
            backing: .buffered,
            defer: false
        )
        window.title = "dmarcwatch – DNS-Prüfung"
        window.isReleasedWhenClosed = false
        self.init(window: window)
    }

    func show() {
        window?.contentViewController = NSHostingController(
            rootView: DNSVerifyView(viewModel: viewModel, onClose: { [weak self] in
                self?.window?.close()
            })
        )
        NSApp.activate(ignoringOtherApps: true)
        window?.center()
        window?.makeKeyAndOrderFront(nil)
        viewModel.run()
    }
}
