import AppKit
import SwiftUI

/// Ein einzelnes, wiederverwendetes Fenster für die Einrichtung - kein
/// eigenes NSWindowController-Subclassing pro Aufruf nötig, da `show(...)`
/// die Inhalte (und das ViewModel) bei jedem Öffnen neu befüllt.
final class SetupWindowController: NSWindowController {
    static let shared = SetupWindowController()

    private let viewModel = SetupViewModel()

    private convenience init() {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 480, height: 560),
            styleMask: [.titled, .closable],
            backing: .buffered,
            defer: false
        )
        window.title = "dmarcwatch – Einrichtung"
        // Fenster nicht bei jedem Schließen freigeben - der Controller ist
        // ein Singleton und wird über mehrere Öffnungen hinweg wiederverwendet.
        window.isReleasedWhenClosed = false
        self.init(window: window)
    }

    func show(onSaved: @escaping () -> Void) {
        viewModel.reload()
        viewModel.onSaved = { [weak self] in
            onSaved()
            self?.window?.close()
        }
        viewModel.onCancel = { [weak self] in
            self?.window?.close()
        }
        window?.contentViewController = NSHostingController(rootView: SetupView(viewModel: viewModel))
        NSApp.activate(ignoringOtherApps: true)
        window?.center()
        window?.makeKeyAndOrderFront(nil)
    }
}
