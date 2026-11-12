#if os(macOS)
import AppKit
import Combine
import Sparkle

/// One updater per GUI session. Command-line helpers and development builds never
/// start update checks. Sparkle's normal termination path stops the engine via
/// AppDelegate.applicationShouldTerminate before replacing the app.
@MainActor final class AppUpdater: NSObject, ObservableObject, SPUStandardUserDriverDelegate {
    @Published private(set) var canCheckForUpdates = false
    @Published private(set) var availableVersion: String?
    @Published var automaticallyChecksForUpdates = false {
        didSet {
            guard controller?.updater.automaticallyChecksForUpdates != automaticallyChecksForUpdates else { return }
            controller?.updater.automaticallyChecksForUpdates = automaticallyChecksForUpdates
        }
    }
    private var controller: SPUStandardUpdaterController?
    private var observations = Set<AnyCancellable>()
    var enabled: Bool { controller != nil }

    /// Exercise Sparkle's real configuration and helper validation in the packaged
    /// app. The CLI exits before the next run-loop cycle, so no update check,
    /// permission prompt, or install is scheduled by this smoke check.
    /// False when there is no feed: nothing is started and no Sparkle object is created.
    @discardableResult static func validateStartup() throws -> Bool {
        guard feedConfigured else { return false }
        let controller = SPUStandardUpdaterController(startingUpdater: false, updaterDelegate: nil, userDriverDelegate: nil)
        try controller.updater.start()
        return true
    }

    /// Sparkle refuses to start without a feed URL, so a build with none simply has no updater.
    static var feedConfigured: Bool {
        guard let feed = Bundle.main.object(forInfoDictionaryKey: "SUFeedURL") as? String,
              let url = URL(string: feed), url.scheme == "https", url.host?.isEmpty == false else { return false }
        return true
    }

    func start() {
        #if arch(arm64)
        guard controller == nil, Self.feedConfigured,
              Bundle.main.object(forInfoDictionaryKey: "BoxCopReleaseProfile") as? String == "distribution",
              !CommandLine.arguments.contains(where: { $0.hasPrefix("--") }) else { return }
        let controller = SPUStandardUpdaterController(startingUpdater: false, updaterDelegate: nil, userDriverDelegate: self)
        self.controller = controller
        controller.updater.publisher(for: \.canCheckForUpdates)
            .receive(on: RunLoop.main).sink { [weak self] in self?.canCheckForUpdates = $0 }.store(in: &observations)
        controller.updater.publisher(for: \.automaticallyChecksForUpdates)
            .receive(on: RunLoop.main).sink { [weak self] in self?.automaticallyChecksForUpdates = $0 }.store(in: &observations)
        controller.startUpdater()
        // Sparkle otherwise waits until its persisted last-check date is due,
        // even after a relaunch. Keep subsequent checks on Sparkle's scheduler.
        if controller.updater.automaticallyChecksForUpdates {
            controller.updater.checkForUpdatesInBackground()
        }
        #endif
    }

    func checkForUpdates() { controller?.checkForUpdates(nil) }
    var supportsGentleScheduledUpdateReminders: Bool { true }
    func standardUserDriverShouldHandleShowingScheduledUpdate(_ update: SUAppcastItem, andInImmediateFocus immediateFocus: Bool) -> Bool {
        // BoxCop is a menu bar app: a menu label alone is too easy to miss.
        // Let Sparkle present its update window for every discovered update.
        true
    }
    func standardUserDriverWillHandleShowingUpdate(_ handleShowingUpdate: Bool, forUpdate update: SUAppcastItem, state: SPUUserUpdateState) {
        availableVersion = update.displayVersionString
    }
    func standardUserDriverWillFinishUpdateSession() { availableVersion = nil }
}
#endif
