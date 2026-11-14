#if os(macOS)
import AppKit
import BoxCopCore
import NetworkExtension
import UniformTypeIdentifiers

/// Layer 3 state and actions: the system extension, the content filter, threat blocking and history.
@MainActor final class NetworkConnectionsModel: ObservableObject {
    @Published private(set) var credentialProtectionWanted = UserDefaults.standard.bool(forKey: "boxcop.credentials.wanted")
    @Published var credentials: CredentialProtectionStatus?
    @Published var snapshot: NetworkActivitySnapshot?
    @Published var result = ""
    @Published var busy = false
    @Published var provisioningStatus = ""
    @Published var extensionState: NetworkExtensionInspection.State = .checking
    @Published var filterEnabled = false
    @Published var setupPhase = NetworkSetupPhase.idle
    /// The extension is installed, the filter is on and the extension answers.
    var setupReady: Bool { snapshot?.mode == "observe_all" && (filterEnabled || !provisioning.available) }
    private let inspection = NetworkExtensionInspection()
    private var refreshing = false
    let provisioning = ProtectionProvisioning()
    init() {
        provisioning.update = { [weak self] in self?.provisioningStatus = $0 }
        provisioning.phaseChanged = { [weak self] in self?.setupPhase = $0 }
    }
    /// Replace only an already-enabled older extension after an app upgrade.
    /// First installation and a disabled filter still need an explicit choice.
    func upgradeInstalledExtension() async {
        guard provisioning.available, !busy else { return }
        busy = true
        defer { busy = false }
        if await inspection.inspect() == .upgradeRequired {
            _ = await provisioning.activate(NetworkFilterControl.identifier)
        }
        await refresh()
    }
    /// Installs the extension if needed, then enables the filter. macOS asks for each approval.
    func enable() {
        guard !busy else { return }; busy = true
        Task {
            _ = await provisioning.enableNetworkFilter()
            await refresh()
            busy = false
        }
    }
    func setCredentialProtection(_ enabled: Bool) {
        guard !busy else { return }; busy = true
        Task {
            defer { busy = false }
            if enabled && credentials == nil {
                guard await provisioning.enableNetworkFilter() else { await refresh(); return }
            }
            result = await NetworkServiceClient.send(enabled ? "credential-protection-on" : "credential-protection-off") ?? "The extension did not answer. Finish system protection setup and retry."
            await refresh()
        }
    }
    func allowCredentialRead(_ id: UUID) {
        guard !busy else { return }; busy = true
        Task {
            result = await NetworkServiceClient.send("credential-allow " + id.uuidString) ?? "The extension did not answer."
            await refresh(); busy = false
        }
    }
    func openFullDiskAccess() {
        NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles")!)
    }
    func setThreatBlocking(_ enabled: Bool) {
        guard !busy else { return }; busy = true
        Task {
            if await NetworkServiceClient.send(enabled ? "network-threat-blocking-on" : "network-threat-blocking-off") == nil {
                result = "The network extension did not answer. Try again."
            } else { result = "" }
            await refresh(); busy = false
        }
    }
    func removeProtection() async -> Bool {
        guard !busy else { return false }; busy = true
        defer { busy = false }
        let removed = await provisioning.removeExtensions()
        await refresh()
        if removed {
            credentialProtectionWanted = false
            UserDefaults.standard.set(false, forKey: "boxcop.credentials.wanted")
        }
        return removed
    }
    func refresh() async {
        guard !refreshing else { return }; refreshing = true
        defer { refreshing = false }
        if provisioning.available { extensionState = await inspection.inspect() }
        let credentialReply = await NetworkServiceClient.send("credential-protection-status")
        credentials = credentialReply?.data(using: .utf8).flatMap { try? JSONDecoder().decode(CredentialProtectionStatus.self, from: $0) }
        if let credentials {
            credentialProtectionWanted = credentials.enabled
            UserDefaults.standard.set(credentials.enabled, forKey: "boxcop.credentials.wanted")
        }
        let reply = await NetworkServiceClient.send("network-activity")
        snapshot = reply?.data(using: .utf8).flatMap { try? JSONDecoder().decode(NetworkActivitySnapshot.self, from: $0) }
        guard provisioning.available else { return }
        let manager = NEFilterManager.shared()
        do {
            try await manager.loadFromPreferences()
            filterEnabled = manager.providerConfiguration?.filterDataProviderBundleIdentifier == NetworkFilterControl.identifier && manager.isEnabled
        } catch { filterEnabled = false }
    }
    func exportHistory() {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.json]; panel.nameFieldStringValue = "BoxCop-network-history.json"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        busy = true
        Task {
            defer { busy = false }
            guard let data = await NetworkServiceClient.send("network-activity-export")?.data(using: .utf8),
                  (try? JSONDecoder().decode([NetworkActivityEvent].self, from: data)) != nil else {
                result = "Could not export the connection history. Check that outbound control is on."; return
            }
            do { try data.write(to: url, options: .atomic); result = "Exported the retained connection history." }
            catch { result = "Could not write the export file." }
        }
    }
    func disable() {
        guard !busy else { return }; busy = true
        Task {
            defer { busy = false }
            let manager = NEFilterManager.shared()
            do {
                try await manager.loadFromPreferences()
                guard manager.providerConfiguration?.filterDataProviderBundleIdentifier == NetworkFilterControl.identifier else { return }
                manager.isEnabled = false; try await manager.saveToPreferences()
                provisioningStatus = ""; result = ""
            } catch { result = "Could not turn off outbound control. Turn off BoxCop under Network, Filters in System Settings." }
            await refresh()
        }
    }
}
#endif
