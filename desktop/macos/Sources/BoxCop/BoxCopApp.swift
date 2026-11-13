#if os(macOS)
import AppKit
import SwiftUI
import Darwin
import UserNotifications
import Combine
import BoxCopCore

@main enum BoxCopMain {
    @MainActor static func main() {
        let arguments = CommandLine.arguments
        let first = arguments.dropFirst().first
        if arguments == [arguments[0], "--check-updater-startup"] {
            do {
                print(try AppUpdater.validateStartup() ? "UPDATER_STARTUP_PASS" : "UPDATER_STARTUP_SKIPPED: no update feed configured")
                exit(0)
            } catch {
                fputs("Updater startup failed: \(error.localizedDescription)\n", stderr)
                exit(1)
            }
        }
        if first == "--export-journal" {
            guard arguments.count == 5 else {
                fputs("Usage: BoxCop --export-journal workflow|network|network-summary SOURCE NEW-OUTPUT-DIRECTORY\n", stderr); exit(64)
            }
            do {
                try JournalExport.run(purpose: arguments[2], source: URL(fileURLWithPath: arguments[3]), destination: URL(fileURLWithPath: arguments[4]))
                print("Private plaintext export complete. Treat the exported files as sensitive.")
            } catch { fputs("Journal export failed; check ownership, Keychain access, and record integrity.\n", stderr); exit(1) }
            return
        }
        let profile = ReleaseProfile.resolve(bundleProfile: Bundle.main.object(forInfoDictionaryKey: "BoxCopReleaseProfile") as? String, arguments: arguments)
        if profile.rejects(arguments: arguments) {
            fputs("Unavailable in this packaged build.\n", stderr)
            exit(64)
        }
        if arguments.contains("--release-channel") {
            print(ReleaseChannel.resolve(bundleChannel: Bundle.main.object(forInfoDictionaryKey: "BoxCopReleaseChannel") as? String).rawValue); return
        }
        if arguments.contains("--release-profile") { print(profile.rawValue); return }
        if first == "--status" { StatusCommand.run(arguments: arguments) }
        if let first, ["--host-agent-hook", "--host-agent-integrations"].contains(first) { HostAgents.run(Array(arguments.dropFirst())) }
        else if arguments.contains("--dev-software-inventory") { SoftwareInventory.run() }
        else if arguments.contains("--dev-network-filter-enable") { NetworkFilterControl.run(enable: true) }
        else if arguments.contains("--dev-network-filter-disable") { NetworkFilterControl.run(enable: false) }
        else if let index = arguments.firstIndex(of: "--dev-interface-preview"), arguments.count > index + 1 {
            do { try InterfacePreview.run(directory: arguments[index + 1]) }
            catch { fputs("Interface preview failed: \(error)\n", stderr); exit(1) }
        }
        else if ApplicationInstall.prepareLaunch() { BoxCopApp.main() }
    }
}

struct BoxCopApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    var body: some Scene {
        MenuBarExtra {
            MenuContent(model: delegate.model, updater: delegate.updater)
        } label: {
            MenuIcon(model: delegate.model)
        }
        .menuBarExtraStyle(.menu)
    }
}

@MainActor final class AppDelegate: NSObject, NSApplicationDelegate, UNUserNotificationCenterDelegate {
    let model = AppModel()
    let updater = AppUpdater()
    private var terminating = false
    private var terminationReplied = false
    private var ownerFD: Int32 = -1
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
        guard acquireOwnership() else {
            // A per-user lock keeps one engine owner, even across concurrent launches.
            if let bundle = Bundle.main.bundleIdentifier {
                NSRunningApplication.runningApplications(withBundleIdentifier: bundle)
                    .first { $0.processIdentifier != ProcessInfo.processInfo.processIdentifier }?
                    .activate()
            }
            let alert = NSAlert(); alert.messageText = "BoxCop is already running"
            alert.informativeText = "Another copy of BoxCop is running, or its data folder cannot be opened. This copy will quit."
            alert.addButton(withTitle: "Quit"); alert.runModal()
            NSApp.terminate(nil); return
        }
        UNUserNotificationCenter.current().delegate = self
        model.updater = updater
        model.activate()
        updater.start()
    }
    // Opening BoxCop again (Finder, Spotlight, Launchpad) must always reach it, even when macOS hides its menu bar icon.
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        model.showWindow(); return true
    }
    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification,
                                             withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([.banner, .list, .sound])
    }
    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse,
                                             withCompletionHandler completionHandler: @escaping () -> Void) {
        let identifier = response.notification.request.identifier
        let event = response.notification.request.content.userInfo["event"] as? String
        let page = response.notification.request.content.userInfo["page"] as? String
        let dismissed = response.actionIdentifier == UNNotificationDismissActionIdentifier
        Task { @MainActor in
            if !dismissed {
                var info: [AnyHashable: Any] = [:]
                if let event { info["event"] = event }
                if let page { info["page"] = page }
                model.openNotification(userInfo: info, identifier: identifier)
            }
            completionHandler()
        }
    }
    private func acquireOwnership() -> Bool {
        let directory = EngineTools.dataDirectory
        do { try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700]) }
        catch { return false }
        let fd = open(directory.appendingPathComponent("native-owner.lock").path, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
        guard fd >= 0 else { return false }
        guard flock(fd, LOCK_EX | LOCK_NB) == 0 else { close(fd); return false }
        ownerFD = fd; return true
    }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard !terminating else { return .terminateLater }
        terminating = true
        Task { @MainActor in
            await model.stopAndWait()
            finishTermination(sender)
        }
        // Quit is bounded: by now the engine has had SIGTERM and, 0.3 s later, SIGKILL.
        Task { @MainActor in
            try? await Task.sleep(nanoseconds: 5_000_000_000)
            finishTermination(sender)
        }
        return .terminateLater
    }
    private func finishTermination(_ sender: NSApplication) {
        guard !terminationReplied else { return }
        terminationReplied = true
        if ownerFD >= 0 { _ = flock(ownerFD, LOCK_UN); close(ownerFD); ownerFD = -1 }
        sender.reply(toApplicationShouldTerminate: true)
    }
}

/// What the menu bar shows. The same lines feed the real menu and its preview.
struct MenuState: Equatable {
    var overall: OverallStatus
    var attention: Bool
    @MainActor init(_ model: AppModel) {
        overall = model.summary.overall; attention = model.attentionNeeded
    }
    var statusLine: String { "BoxCop: " + overall.word }
    var pauseLine: String { overall == .paused ? "Resume Protection" : "Pause Protection" }
    /// The dot appears only when something needs the person.
    var dot: NSColor? {
        if attention { return Palette.nsColor(Palette.amberHex) }
        return overall == .notProtected ? Palette.nsColor(Palette.redHex) : nil
    }
}

@MainActor enum MenuBarImage {
    static func image(_ state: MenuState, dark: Bool) -> NSImage {
        let dot = state.dot
        let image = NSImage(size: NSSize(width: dot == nil ? 18 : 22, height: 18), flipped: true) { _ in
            guard let context = NSGraphicsContext.current?.cgContext else { return false }
            let ink = (dot != nil && dark ? NSColor.white : NSColor.black).cgColor
            BoxCopGlyph.draw(in: context, rect: CGRect(x: 0, y: 0, width: 18, height: 18), color: ink)
            if let dot {
                context.setFillColor(dot.cgColor)
                context.fillEllipse(in: CGRect(x: 16, y: 11.5, width: 6, height: 6))
            }
            return true
        }
        // Template rendering would turn the status dot monochrome.
        image.isTemplate = dot == nil
        image.accessibilityDescription = state.statusLine
        return image
    }
}

/// Publishes only what the icon draws, so it is not redrawn on every model change.
@MainActor final class MenuIconState: ObservableObject {
    @Published private(set) var state: MenuState
    private var observation: AnyCancellable?
    init(model: AppModel) {
        state = MenuState(model)
        // objectWillChange fires before the mutation; read the new values after it commits.
        observation = model.objectWillChange.receive(on: DispatchQueue.main).sink { [weak self, weak model] _ in
            guard let self, let model else { return }
            let next = MenuState(model)
            if next != self.state { self.state = next }
        }
    }
}

struct MenuIcon: View {
    @StateObject private var icon: MenuIconState
    @Environment(\.colorScheme) private var colorScheme
    init(model: AppModel) { _icon = StateObject(wrappedValue: MenuIconState(model: model)) }
    var body: some View {
        Image(nsImage: MenuBarImage.image(icon.state, dark: colorScheme == .dark)).accessibilityLabel(icon.state.statusLine)
    }
}

private struct MenuContent: View {
    @ObservedObject var model: AppModel
    @ObservedObject var updater: AppUpdater
    var body: some View {
        let state = MenuState(model)
        Text(state.statusLine)
        Divider()
        Button("Open BoxCop") { model.showWindow() }
        Button(state.pauseLine) { if model.paused { model.resume() } else { model.pause() } }
        if updater.enabled, let version = updater.availableVersion {
            Button("Update to \(version)…") { updater.checkForUpdates() }
        }
        Divider()
        Button("Quit BoxCop") { NSApp.terminate(nil) }.keyboardShortcut("q")
    }
}
#endif
