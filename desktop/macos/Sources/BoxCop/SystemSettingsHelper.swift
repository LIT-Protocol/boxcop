#if os(macOS)
import AppKit
import SwiftUI
import BoxCopCore

/// Docks one line of guidance under System Settings while a macOS approval is pending.
/// Window bounds and owners are available without Screen Recording; titles and contents are never read.
@MainActor final class SystemSettingsHelper: ObservableObject {
    private static let settingsBundle = "com.apple.systempreferences"
    private var panel: NSPanel?
    private var text: String?
    private var tracking: Task<Void, Never>?

    func show(_ text: String) {
        guard text != self.text else { return }
        self.text = text
        panel?.orderOut(nil)
        panel = makePanel(text)
        tracking?.cancel()
        tracking = Task { [weak self] in
            while !Task.isCancelled {
                self?.position()
                do { try await Task.sleep(nanoseconds: 200_000_000) } catch { return }
            }
        }
    }

    func stop() {
        tracking?.cancel(); tracking = nil
        panel?.orderOut(nil); panel = nil
        text = nil
    }

    private func makePanel(_ text: String) -> NSPanel {
        let content = NSHostingView(rootView: SystemSettingsHelperView(text: text))
        let panel = NSPanel(contentRect: NSRect(origin: .zero, size: content.fittingSize),
                            styleMask: [.borderless, .nonactivatingPanel], backing: .buffered, defer: false)
        panel.contentView = content
        panel.isOpaque = false
        panel.backgroundColor = .clear
        panel.hasShadow = true
        panel.level = .floating
        panel.ignoresMouseEvents = true
        panel.hidesOnDeactivate = false
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        return panel
    }

    private func position() {
        guard let panel else { return }
        guard NSWorkspace.shared.frontmostApplication?.bundleIdentifier == Self.settingsBundle,
              let frame = SettingsHelperPlacement.frame(windows: settingsWindowFrames(), panelSize: panel.frame.size,
                                                        visibleFrames: NSScreen.screens.map(\.visibleFrame)) else {
            panel.orderOut(nil); return
        }
        panel.setFrameOrigin(frame.origin)
        panel.orderFrontRegardless()
    }

    private func settingsWindowFrames() -> [NSRect] {
        let owners = Set(NSRunningApplication.runningApplications(withBundleIdentifier: Self.settingsBundle).map(\.processIdentifier))
        guard let list = CGWindowListCopyWindowInfo([.optionOnScreenOnly, .excludeDesktopElements], kCGNullWindowID) as? [[String: Any]],
              let top = NSScreen.screens.first?.frame.maxY else { return [] }
        return list.compactMap { info in
            guard (info[kCGWindowLayer as String] as? Int) == 0,
                  owners.contains((info[kCGWindowOwnerPID as String] as? pid_t) ?? -1),
                  let bounds = info[kCGWindowBounds as String] as? NSDictionary,
                  let rect = CGRect(dictionaryRepresentation: bounds), !rect.isEmpty else { return nil }
            // Window server coordinates start at the top left of the primary display.
            return NSRect(x: rect.minX, y: top - rect.maxY, width: rect.width, height: rect.height)
        }
    }
}

struct SystemSettingsHelperView: View {
    let text: String
    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "arrow.up").font(.system(size: 16, weight: .bold)).accessibilityHidden(true)
            Text(text).font(.system(size: 14, weight: .medium)).fixedSize()
        }
        .foregroundStyle(AppPalette.ink)
        .padding(.horizontal, 20).frame(height: 56)
        .background(AppPalette.raised, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).strokeBorder(AppPalette.border))
    }
}
#endif
