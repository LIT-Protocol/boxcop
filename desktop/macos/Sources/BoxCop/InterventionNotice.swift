#if os(macOS)
import AppKit
import SwiftUI

/// An always-visible notice for a contained install script, independent of notification permission.
/// A nonactivating panel keeps the terminal focused.
@MainActor final class InterventionNotice {
    private var panel: NSPanel?
    func dismiss() { panel?.orderOut(nil); panel = nil }
    func show(title: String, message: String, actionTitle: String, allow: (() -> Void)?, details: (() -> Void)? = nil) {
        let panel = self.panel ?? NSPanel(contentRect: NSRect(x: 0, y: 0, width: 380, height: 190),
                                         styleMask: [.borderless, .nonactivatingPanel], backing: .buffered, defer: false)
        panel.level = .popUpMenu
        panel.hidesOnDeactivate = false
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        panel.isOpaque = false
        panel.backgroundColor = .clear
        panel.hasShadow = true
        panel.contentView = NSHostingView(rootView: InterventionNoticeView(title: title, actionTitle: actionTitle, message: message, allow: allow,
            details: details, dismiss: { [weak self] in self?.dismiss() }))
        if self.panel == nil, let screen = NSScreen.screens.first(where: { NSMouseInRect(NSEvent.mouseLocation, $0.frame, false) }) ?? NSScreen.main {
            let frame = screen.visibleFrame
            panel.setFrameOrigin(NSPoint(x: frame.maxX - 400, y: frame.maxY - 210))
        }
        self.panel = panel
        panel.orderFrontRegardless()
    }
}

struct InterventionNoticeView: View {
    let title: String
    let actionTitle: String
    let message: String
    let allow: (() -> Void)?
    let details: (() -> Void)?
    let dismiss: () -> Void
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label(title, systemImage: "hand.raised.fill").font(.headline).foregroundStyle(Palette.ink)
            Text(message).font(.callout).fixedSize(horizontal: false, vertical: true)
            HStack {
                Button("Dismiss", action: dismiss)
                if let details { Button("View details") { dismiss(); details() } }
                Spacer()
                if let allow { Button(actionTitle, action: allow).buttonStyle(.borderedProminent) }
            }
        }
        .padding(20)
        .frame(width: 380, height: 190)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 16))
    }
}
#endif
