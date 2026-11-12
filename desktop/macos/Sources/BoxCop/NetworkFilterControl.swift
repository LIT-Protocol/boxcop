#if os(macOS)
import AppKit
import NetworkExtension
import SystemExtensions
import BoxCopCore

/// Activation is a system extension inside the main app, not a second UI app.
final class NetworkFilterControl: NSObject, OSSystemExtensionRequestDelegate {
    private static var retained: NetworkFilterControl?
    static let identifier = "local.sentinel.endpoint.network-filter"
    /// Only the distribution build embeds the extension, and only an embedded extension can be activated.
    static var bundled: Bool {
        ReleaseProfile.resolve(bundleProfile: Bundle.main.object(forInfoDictionaryKey: "BoxCopReleaseProfile") as? String, arguments: []).usesNetworkProtection &&
            FileManager.default.fileExists(atPath: Bundle.main.bundleURL.appendingPathComponent("Contents/Library/SystemExtensions/\(identifier).systemextension").path)
    }
    static func run(enable: Bool) {
        let controller = NetworkFilterControl(); retained = controller
        _ = NSApplication.shared
        if enable {
            let request = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: identifier, queue: .main)
            request.delegate = controller; OSSystemExtensionManager.shared.submitRequest(request)
        } else { controller.configure(false) }
        RunLoop.main.run()
    }
    private func configure(_ enabled: Bool) {
        let manager = NEFilterManager.shared()
        manager.loadFromPreferences { error in
            if let error { self.finish(error); return }
            if enabled {
                let config = NEFilterProviderConfiguration()
                config.filterSockets = true; config.filterPackets = false
                config.filterDataProviderBundleIdentifier = Self.identifier
                manager.providerConfiguration = config
                manager.localizedDescription = "BoxCop outbound control"
            }
            manager.isEnabled = enabled
            manager.saveToPreferences { error in self.finish(error) }
        }
    }
    private func finish(_ error: Error?) {
        if let error {
            let ns = error as NSError
            print("Network filter unavailable: \(ns.domain) code \(ns.code)"); exit(1)
        }
        print("Network filter configuration saved; live flow tests are required to verify enforcement."); exit(0)
    }
    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        print("macOS requires approval for BoxCop's network extension.")
        NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.preference.security?General")!)
    }
    func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties, withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction { .replace }
    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        guard result == .completed else { print("Network extension activation requires restart."); exit(2) }
        configure(true)
    }
    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) { finish(error) }
}
#endif
