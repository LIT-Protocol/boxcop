#if os(macOS)
import AppKit
import Combine
import Sparkle

/// One updater per GUI session. Command-line helpers and development builds never
/// start update checks. Sparkle's normal termination path drains the sidecar via
/// EndpointDelegate.applicationShouldTerminate before replacing the app.
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
    static func validateStartup() throws {
        let controller = SPUStandardUpdaterController(startingUpdater: false, updaterDelegate: nil, userDriverDelegate: nil)
        try controller.updater.start()
    }

    func start() {
        #if arch(arm64)
        guard controller == nil,
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
