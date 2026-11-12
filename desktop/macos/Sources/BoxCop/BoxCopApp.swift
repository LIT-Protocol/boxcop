#if os(macOS)
import AppKit
import SwiftUI
import Darwin
import UserNotifications
import Combine
import BoxCopCore

@main enum BoxCopMain {
    @MainActor static func main() {
        if CommandLine.arguments == [CommandLine.arguments[0], "--check-updater-startup"] {
            do {
                try AppUpdater.validateStartup()
                print("UPDATER_STARTUP_PASS")
                exit(0)
            } catch {
                fputs("Updater startup failed: \(error.localizedDescription)\n", stderr)
                exit(1)
            }
        }
        if CommandLine.arguments.dropFirst().first == "--provision-agent-journal" {
            guard CommandLine.arguments.count == 3 else { exit(64) }
            do { try AgentJournalKey.provision(directory: URL(fileURLWithPath: CommandLine.arguments[2])) }
            catch { fputs("Agent journal key provisioning failed.\n", stderr); exit(1) }
            return
        }
        if CommandLine.arguments.dropFirst().first == "--export-journal" {
            guard CommandLine.arguments.count == 5 else {
                fputs("Usage: BoxCop --export-journal workflow|network|network-summary|development|agent-egress SOURCE NEW-OUTPUT-DIRECTORY\n", stderr); exit(64)
            }
            do {
                try JournalExport.run(purpose: CommandLine.arguments[2], source: URL(fileURLWithPath: CommandLine.arguments[3]),
                                      destination: URL(fileURLWithPath: CommandLine.arguments[4]))
                print("Private plaintext export complete. Treat the exported files as sensitive.")
            } catch { fputs("Journal export failed; check ownership, Keychain access, and record integrity.\n", stderr); exit(1) }
            return
        }
        let profile = ReleaseProfile.resolve(bundleProfile: Bundle.main.object(forInfoDictionaryKey: "BoxCopReleaseProfile") as? String,
                                             arguments: CommandLine.arguments)
        if profile.rejects(arguments: CommandLine.arguments) {
            fputs("Unavailable in this packaged build: privileged development services require a lab build. Keep SIP enabled.\n", stderr)
            exit(64)
        }
        if CommandLine.arguments.contains("--release-channel") {
            print(ReleaseChannel.resolve(bundleChannel: Bundle.main.object(forInfoDictionaryKey: "BoxCopReleaseChannel") as? String).rawValue); return
        }
        if CommandLine.arguments.contains("--release-profile") {
            print(profile.rawValue); return
        }
        if CommandLine.arguments == [CommandLine.arguments[0], "--review-agent-action"] { AgentActionReview.run() }
        if CommandLine.arguments == [CommandLine.arguments[0], "--review-transfer"] { TransferReview.run() }
        if CommandLine.arguments.count > 1, ["--reviewed-transfer", "--host-agent-hook", "--host-agent-integrations", "--provider-integrations",
                                                   "--host-agent-correction", "--agent-corrections"].contains(CommandLine.arguments[1]) { HostAgents.run(Array(CommandLine.arguments.dropFirst())) }
        else if CommandLine.arguments.contains("--dev-software-inventory") { SoftwareInventory.run() }
        else if CommandLine.arguments.contains("--dev-network-filter-enable") { NetworkFilterControl.run(enable: true) }
        else if CommandLine.arguments.contains("--dev-network-filter-disable") { NetworkFilterControl.run(enable: false) }
        else if CommandLine.arguments.contains("--dev-agent-run") { AgentEnforcement.run() }
        else if CommandLine.arguments.contains("--dev-endpoint-security-service") { EndpointSecurityService.run() }
        else if let index = CommandLine.arguments.firstIndex(of: "--dev-endpoint-security-control"), CommandLine.arguments.count > index + 1 { print(EndpointSecurityControl.request(CommandLine.arguments[index + 1])) }
        else if CommandLine.arguments.contains("--dev-endpoint-security-probe") { print(EndpointSecurityProbe.status()) }
        else if CommandLine.arguments.contains("--dev-endpoint-security-test") { EndpointSecuritySelfTest.run() }
        else if CommandLine.arguments.contains("--native-messaging") { CollectorBridge.run(nativeMessaging: true) }
        else if CommandLine.arguments.contains("--collect-event") { CollectorBridge.run(nativeMessaging: false) }
        else if let index = CommandLine.arguments.firstIndex(of: "--dev-interface-preview"), CommandLine.arguments.count > index + 1 {
            do { try InterfacePreview.run(directory: CommandLine.arguments[index + 1]) }
            catch { fputs("Interface preview failed: \(error)\n", stderr); exit(1) }
        }
        else if ApplicationInstall.prepareLaunch() { BoxCopApp.main() }
    }
}

struct BoxCopApp: App {
    @NSApplicationDelegateAdaptor(EndpointDelegate.self) private var delegate
    var body: some Scene {
        MenuBarExtra {
            EndpointMenu(model: delegate.model, updater: delegate.updater)
        } label: {
            EndpointIcon(model: delegate.model)
        }
        .menuBarExtraStyle(.menu)
    }
}

@MainActor final class EndpointDelegate: NSObject, NSApplicationDelegate, UNUserNotificationCenterDelegate {
    let model = EndpointModel()
    let updater = AppUpdater()
    private var terminating = false
    private var terminationReplied = false
    private var ownerFD: Int32 = -1
    private var alertObservation: AnyCancellable?
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
        guard acquireOwnership() else {
            // An advisory, per-user lock enforces one collector/sidecar owner, even across concurrent launches.
            if let bundle = Bundle.main.bundleIdentifier {
                NSRunningApplication.runningApplications(withBundleIdentifier: bundle)
                    .first { $0.processIdentifier != ProcessInfo.processInfo.processIdentifier }?
                    .activate()
            }
            let alert = NSAlert(); alert.messageText = "BoxCop could not take session ownership"
            alert.informativeText = "Another BoxCop may already be running, or its private application-support directory is unavailable. This instance will quit without starting collection."
            alert.addButton(withTitle: "Quit"); alert.runModal()
            NSApp.terminate(nil); return
        }
        UNUserNotificationCenter.current().delegate = self
        model.activateLifecycle()
        // Observe after @Published mutations commit; throttle busy collectors without
        // waiting for a quiet period that may never arrive during active work.
        alertObservation = model.objectWillChange.receive(on: DispatchQueue.main)
            .throttle(for: .milliseconds(250), scheduler: DispatchQueue.main, latest: true)
            .sink { [weak self] _ in self?.refreshActionableAlerts() }
        refreshActionableAlerts()
        updater.start()
    }
    private func refreshActionableAlerts() {
        guard !terminating else { return }
        model.refreshActionableAlerts()
    }
    func application(_ application: NSApplication, open urls: [URL]) {
        // macOS can deliver this before applicationDidFinishLaunching. The model
        // queues it until local mode has loaded and session ownership is acquired.
        guard !terminating else { return }
        for url in urls {
            if let invitation = TeamInvitation(url: url) {
                model.openTeamInvitation(invitation)
                break
            }
        }
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
        Task { @MainActor in
            let identifier = response.notification.request.identifier
            if identifier == "boxcop-notification-test", response.actionIdentifier == UNNotificationDefaultActionIdentifier {
                model.showWindow(page: .settings)
            } else if identifier == "boxcop-software-review", response.actionIdentifier == UNNotificationDefaultActionIdentifier {
                model.showSoftwareReview()
            } else if (identifier == "boxcop-email-review" || identifier.hasPrefix("boxcop-email-review-")), response.actionIdentifier == UNNotificationDefaultActionIdentifier {
                model.showWindow(page: .activity)
            } else if AgentApprovalCopy.requestID(notificationIdentifier: identifier) != nil, response.actionIdentifier == UNNotificationDefaultActionIdentifier {
                model.showWindow(page: .approvals)
                model.approvals.touch()
            } else if let reminder = ReviewPolicy.reminderID(notificationIdentifier: identifier),
                      response.actionIdentifier == UNNotificationDefaultActionIdentifier {
                model.openReviewReminder(reminder)
            } else if (identifier == "boxcop-paste-blocked" || identifier.hasPrefix("boxcop-pdf-review-") || identifier.hasPrefix("boxcop-code-review-")),
                      response.actionIdentifier == UNNotificationDefaultActionIdentifier {
                model.showWindow(page: .activity)
            }
            completionHandler()
        }
    }
    private func acquireOwnership() -> Bool {
        guard let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else { return false }
        let directory = support.appendingPathComponent("BoxCop", isDirectory: true)
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
        alertObservation = nil
        model.closeActionableAlerts()
        Task { @MainActor in
            await model.stopAndWait()
            finishTermination(sender)
        }
        // Quit is bounded: by now the helper has had SIGTERM and, 0.3 s later, SIGKILL.
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

@MainActor private enum BoxCopMenuIcon {
    /// Orange means unavailable protection only. Review counts stay neutral.
    static func image(health: MonitoringHealth, pendingReviews: Int, dark: Bool) -> NSImage {
        let dot: NSColor? = health.needsAttention ? .systemOrange : health == .monitoring ? .systemBlue : nil
        let baseWidth: CGFloat = dot == nil ? 18 : 25
        let count = (pendingReviews > 0 ? (pendingReviews > 99 ? "99+" : String(pendingReviews)) : "") as NSString
        let color: NSColor = dot != nil && dark ? .white : .black
        let attributes: [NSAttributedString.Key: Any] = [.font: NSFont.monospacedDigitSystemFont(ofSize: 12, weight: .medium), .foregroundColor: color]
        let countWidth = pendingReviews > 0 ? ceil(count.size(withAttributes: attributes).width) + 5 : 0
        let image = NSImage(size: NSSize(width: baseWidth + countWidth, height: 18), flipped: true) { _ in
            guard let context = NSGraphicsContext.current?.cgContext else { return false }
            context.setFillColor((dot != nil && dark ? NSColor.white : NSColor.black).cgColor)
            context.addPath(BoxCopMark().path(in: CGRect(x: 0, y: 0, width: 18, height: 18)).cgPath)
            context.fillPath()
            if let dot {
                context.setFillColor(dot.cgColor)
                context.fillEllipse(in: CGRect(x: 20, y: 10, width: 5, height: 5))
            }
            if pendingReviews > 0 { count.draw(at: NSPoint(x: baseWidth + 5, y: 1), withAttributes: attributes) }
            return true
        }
        // Template rendering would turn the status dot monochrome.
        image.isTemplate = dot == nil
        image.accessibilityDescription = "BoxCop — " + health.summary + (pendingReviews > 0 ? " · " + ActionableAlert.countSummary(pendingReviews) : "")
        return image
    }
}

/// Only the inputs the menu-bar icon draws. `EndpointModel` publishes many times
/// per second while collectors run; re-rendering the icon on each change made
/// AppKit re-snapshot the status item constantly on the main thread.
@MainActor final class MenuIconState: ObservableObject {
    struct Snapshot: Equatable { var health: MonitoringHealth; var pendingReviews: Int }
    @Published private(set) var snapshot: Snapshot
    private var observation: AnyCancellable?
    init(model: EndpointModel) {
        snapshot = Snapshot(health: model.health, pendingReviews: model.pendingReviewCount)
        // objectWillChange fires before the mutation; read the new values after it commits.
        observation = model.objectWillChange.receive(on: DispatchQueue.main).sink { [weak self, weak model] _ in
            guard let self, let model else { return }
            let next = Snapshot(health: model.health, pendingReviews: model.pendingReviewCount)
            if next != self.snapshot { self.snapshot = next }
        }
    }
}

struct EndpointIcon: View {
    @StateObject private var state: MenuIconState
    @Environment(\.colorScheme) private var colorScheme
    init(model: EndpointModel) { _state = StateObject(wrappedValue: MenuIconState(model: model)) }
    var body: some View {
        let snapshot = state.snapshot, count = snapshot.pendingReviews
        Image(nsImage: BoxCopMenuIcon.image(health: snapshot.health, pendingReviews: count, dark: colorScheme == .dark))
            .accessibilityLabel("BoxCop — " + snapshot.health.summary + (count > 0 ? " · " + ActionableAlert.countSummary(count) : ""))
    }
}

/// Status and the one action that matters now. Navigation, coverage limits and
/// diagnostics live in the window.
private struct EndpointMenu: View {
    @ObservedObject var model: EndpointModel
    @ObservedObject var updater: AppUpdater
    var body: some View {
        let health = model.health
        let alerts = model.actionableAlerts
        let activityCount = alerts.filter { $0.category != .software && $0.category != .approval }.reduce(0) { $0 + $1.itemIDs.count }
        let softwareCount = alerts.first { $0.category == .software }?.itemIDs.count ?? 0
        let approvalCount = alerts.first { $0.category == .approval }?.itemIDs.count ?? 0
        Text(health.summary)
        ForEach(MenuAction.available(for: health, setupPending: model.setupPending), id: \.self) { action in
            Button(action.rawValue) { perform(action) }
                .disabled((action == .resume || action == .restart) && !model.canStart)
        }
        // Persistent entry points even when Focus suppresses notification banners.
        if approvalCount > 0 {
            Button("Approve agent actions (\(approvalCount))") { model.showWindow(page: .approvals) }
        }
        if activityCount > 0 {
            Button("Review activity (\(activityCount))") {
                model.showWindow(page: .activity)
            }
        }
        if softwareCount > 0 {
            Button("Review software (\(softwareCount))") { model.showSoftwareReview() }
        }
        Divider()
        Button("Open BoxCop") { model.showWindow() }
        Button("Settings…") { model.showWindow(page: .settings) }.keyboardShortcut(",")
        if updater.enabled {
            Button(updater.availableVersion.map { "Update to \($0)…" } ?? "Check for Updates…") { updater.checkForUpdates() }
                .disabled(!updater.canCheckForUpdates && updater.availableVersion == nil)
            Toggle("Automatically Check for Updates", isOn: $updater.automaticallyChecksForUpdates)
        }
        Divider()
        Button("Quit BoxCop") { NSApp.terminate(nil) }.keyboardShortcut("q")
    }
    private func perform(_ action: MenuAction) {
        switch action {
        case .finishSetup: model.onboardingPresented = true; model.showWindow()
        case .retryPasteProtection:
            model.retry()
            // Re-arming is synchronous; if it still fails, show the reason instead of a silent no-op.
            if !model.guardActive { model.showWindow(page: .protection) }
        case .restart: model.retry()
        case .pause: model.pause()
        case .resume: model.start()
        }
    }
}
#endif
