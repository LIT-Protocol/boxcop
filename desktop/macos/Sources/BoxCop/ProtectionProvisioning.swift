#if os(macOS)
import AppKit
import BoxCopCore
import SystemExtensions
import NetworkExtension

/// Where a network setup request stands with macOS.
enum NetworkSetupPhase: Equatable { case idle, extensionApproval, filterApproval, declined, failed(String) }

/// macOS owns installation/approval. No sudo scripts or SIP changes on customer Macs.
@MainActor final class ProtectionProvisioning: NSObject, OSSystemExtensionRequestDelegate {
    private var continuation: CheckedContinuation<Bool, Never>?
    /// Why macOS refused for a reason other than the person's answer. Asking again won't change it.
    private var activationFailure: String?
    var update: (String) -> Void = { _ in }
    var phaseChanged: (NetworkSetupPhase) -> Void = { _ in }
    var available: Bool { NetworkFilterControl.bundled }
    var setupIssue: String? {
        if Bundle.main.bundleURL.deletingLastPathComponent().path != "/Applications" {
            return "Move BoxCop to Applications, then open it there to set up outbound control."
        }
        if !available { return "This build does not include the network extension." }
        return nil
    }
    func activate(_ identifier: String) async -> Bool {
        if let setupIssue { update(setupIssue); return false }
        guard continuation == nil else { return false }
        return await withCheckedContinuation { continuation in
            self.continuation = continuation
            let request = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: identifier, queue: .main)
            request.delegate = self
            OSSystemExtensionManager.shared.submitRequest(request)
        }
    }
    func enableNetworkFilter() async -> Bool {
        phaseChanged(.idle)
        activationFailure = nil
        guard await activate(NetworkFilterControl.identifier) else { phaseChanged(activationFailure.map { .failed($0) } ?? .declined); return false }
        // macOS starts the observer only after enabling its configuration.
        phaseChanged(.filterApproval)
        let manager = NEFilterManager.shared()
        do {
            try await manager.loadFromPreferences()
            if let current = manager.providerConfiguration?.filterDataProviderBundleIdentifier, current != NetworkFilterControl.identifier {
                let reason = "Another filter configuration is selected; BoxCop did not replace it."
                update(reason); phaseChanged(.failed(reason)); return false
            }
            let configuration = NEFilterProviderConfiguration()
            configuration.filterSockets = true; configuration.filterPackets = false
            configuration.filterDataProviderBundleIdentifier = NetworkFilterControl.identifier
            manager.providerConfiguration = configuration
            manager.localizedDescription = "BoxCop outbound control"
            manager.isEnabled = true
            try await manager.saveToPreferences()
            update("Outbound control is on for all apps.")
            phaseChanged(.idle)
            return true
        } catch {
            update("Filter setup failed. Review macOS Network Extensions approval and retry."); phaseChanged(.declined); return false
        }
    }
    func removeExtensions() async {
        // A filter must be disabled before its decision service is removed.
        let manager = NEFilterManager.shared()
        do {
            try await manager.loadFromPreferences()
            if manager.providerConfiguration?.filterDataProviderBundleIdentifier == NetworkFilterControl.identifier {
                manager.isEnabled = false
                try await manager.saveToPreferences()
            }
        } catch { update("Could not disable the filter; services were not removed. Disable BoxCop in System Settings first."); return }
        for identifier in [NetworkFilterControl.identifier] {
            guard continuation == nil else { return }
            let success = await withCheckedContinuation { continuation in
                self.continuation = continuation
                let request = OSSystemExtensionRequest.deactivationRequest(forExtensionWithIdentifier: identifier, queue: .main)
                request.delegate = self; OSSystemExtensionManager.shared.submitRequest(request)
            }
            if !success { return }
        }
        update("Network extension removed. Connection history and blocking preferences were retained.")
    }
    nonisolated func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        Task { @MainActor in
        if #available(macOS 15, *) {
            update("Approve BoxCop in System Settings → General → Login Items & Extensions → Network Extensions.")
        } else {
            update("Approve BoxCop in System Settings → Privacy & Security, then return here.")
        }
        phaseChanged(.extensionApproval)
        openApprovalSettings()
        }
    }
    func openApprovalSettings() {
        let pane: String
        if #available(macOS 15, *) { pane = "com.apple.LoginItems-Settings.extension" } else { pane = "com.apple.preference.security?General" }
        if let url = URL(string: "x-apple.systempreferences:" + pane) { NSWorkspace.shared.open(url) }
    }
    nonisolated func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties, withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction { .replace }
    nonisolated func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        Task { @MainActor in
        if result != .completed { activationFailure = "macOS requires a restart to finish this change." }
        update(activationFailure ?? "")
        finish(result == .completed)
        }
    }
    nonisolated func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        Task { @MainActor in
        let error = error as NSError
        if error.domain == OSSystemExtensionErrorDomain && error.code == OSSystemExtensionError.Code.validationFailed.rawValue {
            let reason = "macOS rejected the network extension’s bundle. Install an updated BoxCop build; changing permissions will not fix this validation error. (Code 9)"
            activationFailure = reason
            update(reason)
        } else {
            update("System extension request failed (\(error.domain), \(error.code)). Check macOS approval and retry.")
        }
        finish(false)
        }
    }
    private func finish(_ success: Bool) {
        let pending = continuation; continuation = nil; pending?.resume(returning: success)
    }
}
/// Read-only status requests never activate an extension or prompt for approval.
@MainActor final class NetworkExtensionInspection: NSObject, OSSystemExtensionRequestDelegate {
    enum State { case checking, missing, awaitingApproval, installed, upgradeRequired, unavailable }
    private var continuation: CheckedContinuation<State, Never>?
    private var currentRequest: OSSystemExtensionRequest?
    func inspect() async -> State {
        guard continuation == nil else { return .checking }
        return await withCheckedContinuation { continuation in
            self.continuation = continuation
            let request = OSSystemExtensionRequest.propertiesRequest(forExtensionWithIdentifier: NetworkFilterControl.identifier, queue: .main)
            currentRequest = request
            request.delegate = self
            OSSystemExtensionManager.shared.submitRequest(request)
        }
    }
    private func finish(_ state: State) {
        let pending = continuation; continuation = nil; currentRequest = nil; pending?.resume(returning: state)
    }
    nonisolated func request(_ request: OSSystemExtensionRequest, foundProperties properties: [OSSystemExtensionProperties]) {
        let version = Bundle(url: Bundle.main.bundleURL.appendingPathComponent("Contents/Library/SystemExtensions/" + NetworkFilterControl.identifier + ".systemextension"))?.object(forInfoDictionaryKey: "CFBundleVersion") as? String
        let installed = properties.contains { $0.isEnabled && !$0.isUninstalling && $0.bundleVersion == version }
        let old = properties.contains { $0.isEnabled && !$0.isUninstalling }
        let awaiting = properties.contains { $0.isAwaitingUserApproval }
        Task { @MainActor in finish(installed ? .installed : old ? .upgradeRequired : awaiting ? .awaitingApproval : .missing) }
    }
    nonisolated func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        Task { @MainActor in finish(.unavailable) }
    }
    nonisolated func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        Task { @MainActor in finish(.unavailable) }
    }
    nonisolated func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        Task { @MainActor in finish(.awaitingApproval) }
    }
    nonisolated func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties, withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction { .cancel }
}
#endif
