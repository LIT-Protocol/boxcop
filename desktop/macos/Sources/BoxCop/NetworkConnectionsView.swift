#if os(macOS)
import SwiftUI
import BoxCopCore
import NetworkExtension
import UniformTypeIdentifiers

@MainActor final class NetworkConnectionsModel: ObservableObject {
    @Published var snapshot: NetworkActivitySnapshot?
    @Published var status = "Checking network activity…"
    @Published var serviceStatus = ""
    @Published var filterStatus = "Checking macOS network extension…"
    @Published var result = ""
    @Published var busy = false
    @Published var provisioningStatus = ""
    @Published var extensionState: NetworkExtensionInspection.State = .checking
    @Published var filterEnabled = false
    @Published private(set) var setupPhase = NetworkSetupPhase.idle
    var setupReady: Bool { extensionState == .installed && filterEnabled && snapshot?.mode == "observe_all" }
    /// macOS has approved it, even if the extension has not reported in yet.
    var approved: Bool { extensionState == .installed && filterEnabled }
    private let inspection = NetworkExtensionInspection()
    private var refreshing = false
    let provisioning = ProtectionProvisioning()
    init() {
        provisioning.update = { [weak self] in self?.provisioningStatus = $0 }
        provisioning.phaseChanged = { [weak self] in self?.setupPhase = $0 }
    }
    /// Replace only an already-enabled older extension after an app upgrade.
    /// First installation and disabled protection still require explicit setup.
    func upgradeInstalledExtension() async {
        guard provisioning.available, !busy else { return }
        busy = true
        defer { busy = false }
        if await inspection.inspect() == .upgradeRequired {
            _ = await provisioning.activate(NetworkFilterControl.identifier)
        }
        await refresh()
    }
    func installService() {
        guard !busy else { return }; busy = true
        Task { _ = await provisioning.activate(NetworkFilterControl.identifier); await refresh(); busy = false }
    }
    func enableFilter() {
        guard !busy else { return }; busy = true
        Task {
            let enabled = await provisioning.enableNetworkFilter()
            await refresh()
            // Recorded once macOS accepts it, so a declined request is never a lost approval.
            if enabled { UserDefaults.standard.set(true, forKey: "boxcop.setup.network") }
            busy = false
        }
    }
    func setThreatBlocking(_ enabled: Bool) {
        guard !busy else { return }; busy = true
        Task {
            result = await EndpointSecurityControl.send(enabled ? "network-threat-blocking-on" : "network-threat-blocking-off")
            await refresh(); busy = false
        }
    }
    func removeProtection() {
        guard !busy else { return }; busy = true
        clearSetupChoice()
        Task { await provisioning.removeExtensions(); await refresh(); busy = false }
    }
    func refresh() async {
        guard !refreshing else { return }; refreshing = true
        defer { refreshing = false }
        if provisioning.available { extensionState = await inspection.inspect() }
        let reply = await EndpointSecurityControl.send("network-activity")
        snapshot = reply.data(using: .utf8).flatMap { try? JSONDecoder().decode(NetworkActivitySnapshot.self, from: $0) }
        let manager = NEFilterManager.shared()
        do {
            try await manager.loadFromPreferences()
            filterEnabled = manager.providerConfiguration?.filterDataProviderBundleIdentifier == NetworkFilterControl.identifier && manager.isEnabled
            filterStatus = filterEnabled ? "Network extension enabled in macOS." : "Network extension is off."
        } catch { filterEnabled = false; filterStatus = "Cannot read network extension settings." }
        serviceStatus = filterEnabled && snapshot == nil
            ? "BoxCop cannot read the network extension’s live status. Click Stop network protection, then Enable network protection and Refresh. This briefly pauses network protection. If status remains unavailable, restart your Mac."
            : ""
        let protection = snapshot?.threatProtection
        status = filterEnabled && snapshot == nil ? "Network status unavailable" : !setupReady ? "Network protection is not active" :
            protection?.enabled == true && protection?.error == nil ? "All apps · listed threat domains blocked" : "Observing all apps · threat blocking off"
    }
    /// Cleared before the change takes effect, so a status check during it can't read a lost approval.
    private func clearSetupChoice() { UserDefaults.standard.set(false, forKey: "boxcop.setup.network") }
    func exportHistory() {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.json]; panel.nameFieldStringValue = "BoxCop-network-activity.json"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        busy = true
        Task {
            defer { busy = false }
            let reply = await EndpointSecurityControl.send("network-activity-export")
            guard let data = reply.data(using: .utf8), (try? JSONDecoder().decode([NetworkActivityEvent].self, from: data)) != nil else {
                result = "Could not export retained history. Recheck the network extension."; return
            }
            do { try data.write(to: url, options: .atomic); result = "Exported retained connection history." }
            catch { result = "Could not write the export file." }
        }
    }
    func disableFilter() {
        guard !busy else { return }; busy = true
        Task {
            defer { busy = false }
            let manager = NEFilterManager.shared()
            do {
                try await manager.loadFromPreferences()
                guard manager.providerConfiguration?.filterDataProviderBundleIdentifier == NetworkFilterControl.identifier else { return }
                clearSetupChoice()
                manager.isEnabled = false; try await manager.saveToPreferences()
                provisioningStatus = ""; result = "Network logging and threat blocking stopped."
            } catch { result = "Could not stop network protection. Disable BoxCop in macOS Network filter settings." }
            await refresh()
        }
    }
}

@MainActor struct NetworkConnectionsView: View {
    @StateObject private var model: NetworkConnectionsModel
    private let polling: Bool
    private let openSetup: (() -> Void)?
    init(model: NetworkConnectionsModel? = nil, polling: Bool = true, openSetup: (() -> Void)? = nil) {
        _model = StateObject(wrappedValue: model ?? NetworkConnectionsModel()); self.polling = polling; self.openSetup = openSetup
    }
    @State private var search = ""
    @State private var showRecent = false
    @State private var isExpanded = false
    @State private var selected: NetworkActivityEvent?
    private var events: [NetworkActivityEvent] {
        (model.snapshot?.events ?? []).filter { event in
            search.isEmpty || [event.process.executable, event.responsibleApp.executable, event.hostname, event.remoteAddress, event.remotePort].compactMap { $0 }.joined(separator: " ").localizedCaseInsensitiveContains(search)
        }
    }
    var body: some View {
        GroupBox {
            DisclosureGroup(isExpanded: $isExpanded) {
                VStack(alignment: .leading, spacing: 12) {
                    Text(model.status).fontWeight(.medium)
                    Text("Outgoing connection attempts and retained summaries from this Mac.")
                    HStack {
                        Button("Refresh") { Task { await model.refresh() } }.disabled(model.busy)
                        Button("Export history…") { model.exportHistory() }.disabled(model.busy || model.snapshot == nil)
                        if let openSetup { Button("Manage network protection", action: openSetup) }
                    }
                    if model.snapshot == nil {
                        Text("Network history is unavailable. Review network protection in Connections to check setup and service status.").foregroundStyle(.secondary)
                    }
                    if let report = model.snapshot {
                        if report.dropped > 0 || report.writeFailures > 0 {
                            Text("Some activity is missing: \(report.dropped) dropped records · \(report.writeFailures) save failures this session.").foregroundStyle(.orange)
                        }
                        NetworkSummaryView(summary: report.summary, error: report.summaryError)
                        Toggle("Show recent activity", isOn: $showRecent)
                        if showRecent {
                            TextField("Search recent processes, domains or addresses", text: $search)
                            Text("Latest 100 retained attempts. Export includes all retained raw history.").foregroundStyle(.secondary)
                            if events.isEmpty { Text(search.isEmpty ? "No connections recorded yet. Open an app or visit a website." : "No matching recent connections.") }
                            ForEach(events.prefix(30)) { event in
                                Button { selected = event } label: {
                                    VStack(alignment: .leading, spacing: 3) {
                                        Text("\(event.process.name ?? event.responsibleApp.name ?? "Unknown process") → \(event.hostname ?? event.remoteAddress ?? "Unknown destination")")
                                        Text("\(event.timestamp.formatted(date: .omitted, time: .standard)) · \(event.transport.uppercased()) · port \(event.remotePort ?? "unknown") · \(event.threat == nil ? "allowed" : "BLOCKED")").foregroundStyle(event.threat == nil ? Color.secondary : Color.red)
                                    }.frame(maxWidth: .infinity, alignment: .leading)
                                }.buttonStyle(.plain).padding(.vertical, 4)
                            }
                            if events.count > 30 { Text("Showing 30 matches. Narrow the search or export history.").foregroundStyle(.secondary) }
                        }
                    }
                    NetworkRecordingDisclosure()
                    if !model.result.isEmpty { Text(model.result).textSelection(.enabled) }
                }.font(.caption).frame(maxWidth: .infinity, alignment: .leading)
            } label: {
                Label("Network activity", systemImage: "network").font(.headline)
            }
        }
        .task {
            guard polling else { return }
            while !Task.isCancelled {
                await model.refresh()
                do { try await Task.sleep(nanoseconds: 5_000_000_000) } catch { return }
            }
        }
        .sheet(item: $selected) { event in
            VStack(alignment: .leading, spacing: 14) {
                Text("Connection details").font(.title2)
                Text("\(event.threat == nil ? "Observed and allowed" : "Blocked: listed threat domain") · \(event.timestamp.formatted())")
                ScrollView {
                    VStack(alignment: .leading, spacing: 8) {
                        if let threat = event.threat {
                            Text("Blocked hostname: \(threat.hostname)").foregroundStyle(.red)
                            Text("Reason: \(threat.reason)")
                            Text("Source: \(threat.source) · revision: \(threat.revision)")
                        }
                        Text("Process: \(event.process.executable ?? "Unavailable")")
                        Text("PID: \(event.process.pid.map(String.init) ?? "unknown") · UID: \(event.process.uid.map(String.init) ?? "unknown")")
                        Text("Responsible app: \(event.responsibleApp.executable ?? "Unavailable")")
                        Text("Destination: \(event.remoteAddress ?? "unavailable"):\(event.remotePort ?? "unknown") · \(event.transport)")
                        Text("Hostname: \(event.hostname ?? "Not supplied by macOS") · source: \(event.hostnameSource)")
                        Text("URL: \(event.url ?? "Not supplied by macOS")")
                        Text("Signing: \(event.process.signingStatus) · team: \(event.process.teamIdentifier ?? "unavailable")")
                        Text("Certificate subjects: \(event.process.signingAuthorities?.joined(separator: " → ") ?? "Unavailable")")
                        Text("Identifier: \(event.process.signingIdentifier ?? "unavailable") · code hash: \(event.process.codeHash ?? "unavailable")")
                        Text("Arguments: \(event.process.arguments?.joined(separator: " ") ?? "Unavailable")")
                        Text("Ancestors (snapshot): \(event.process.ancestors?.map { "\($0.pid): \($0.executable ?? "unknown")" }.joined(separator: " → ") ?? "Unavailable")")
                        Text("Metadata: \(event.process.metadataStatus)").foregroundStyle(.secondary)
                    }.frame(maxWidth: .infinity, alignment: .leading).textSelection(.enabled)
                }
                Button("Done") { selected = nil }.keyboardShortcut(.cancelAction)
            }.padding(24).frame(width: 650, height: 480)
        }
    }
}

/// Installation and protection policy stay separate from connection history.
@MainActor struct NetworkProtectionSetupView: View {
    @ObservedObject var model: NetworkConnectionsModel
    var polling = true
    var openActivity: (() -> Void)?
    @State private var removalConfirmation = false

    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 12) {
                Label("Network protection", systemImage: "network").font(.headline)
                Text(model.status).fontWeight(.medium)
                Text("See outgoing connections from all apps, including newly installed tools. Block domains listed for threats such as malware and phishing. Unlisted destinations remain allowed; unfamiliar names alone are not blocked.")
                if let issue = model.provisioning.setupIssue { Text(issue).foregroundStyle(.secondary) }
                if model.provisioning.setupIssue == nil {
                    HStack {
                        Button(model.extensionState == .installed ? "1. Extension installed" : model.extensionState == .upgradeRequired ? "1. Update network extension" : "1. Install network extension") { model.installService() }.disabled(model.extensionState == .installed)
                        Button(model.filterEnabled ? "2. Network protection enabled" : "2. Enable network protection") { model.enableFilter() }.disabled(model.extensionState != .installed || model.filterEnabled)
                    }.disabled(model.busy)
                }
                Text(model.filterStatus)
                if !model.serviceStatus.isEmpty { Text(model.serviceStatus).foregroundStyle(.orange) }
                if !model.provisioningStatus.isEmpty { Text(model.provisioningStatus) }
                HStack {
                    Button("Refresh") { Task { await model.refresh() } }.disabled(model.busy)
                    Button("Stop network protection") { model.disableFilter() }.disabled(model.busy || !model.filterEnabled)
                    Button("Remove extension…", role: .destructive) { removalConfirmation = true }.disabled(model.busy)
                }
                if let report = model.snapshot {
                    if let protection = report.threatProtection {
                        Toggle("Block listed threat domains", isOn: Binding(get: { protection.enabled }, set: model.setThreatBlocking))
                            .disabled(model.busy || !model.setupReady)
                        Text("\(protection.domainCount) exact hostnames · list dated \(String(protection.publishedAt.prefix(10))). Updates ship with app releases.").foregroundStyle(.secondary)
                        if let date = ISO8601DateFormatter().date(from: protection.publishedAt), Date().timeIntervalSince(date) > 7 * 86_400 {
                            Text("Threat list is over a week old. Update BoxCop for newer coverage.").foregroundStyle(.orange)
                        }
                        if let error = protection.error { Text(error).foregroundStyle(.orange) }
                    }
                }
                NetworkRecordingDisclosure()
                DisclosureGroup("Threat blocking coverage and source") {
                    Text("Exact hostname matches use the bundled HaGeZi Threat Intelligence Feeds Mini snapshot. This list includes malware, phishing and other threats; it can contain errors. Hostnames must be supplied by macOS. IP-only connections, unlisted subdomains, proxies/VPN tunnels and existing connections may bypass domain matching. Encrypted payloads are not inspected. Allowed does not mean safe. Turn off threat blocking to investigate a false positive while keeping the connection log.")
                    Link("Threat list source, license and corrections", destination: URL(string: "https://github.com/hagezi/dns-blocklists")!)
                }
                if let openActivity { Button("View network activity", action: openActivity) }
                if !model.result.isEmpty { Text(model.result).textSelection(.enabled) }
            }.font(.caption).frame(maxWidth: .infinity, alignment: .leading)
        }
        .task {
            guard polling else { return }
            while !Task.isCancelled {
                await model.refresh()
                do { try await Task.sleep(nanoseconds: 5_000_000_000) } catch { return }
            }
        }
        .confirmationDialog("Remove BoxCop’s network extension? Logging and threat blocking stop; retained history stays on this Mac.", isPresented: $removalConfirmation, titleVisibility: .visible) {
            Button("Remove extension", role: .destructive) { model.removeProtection() }
        }
    }
}

private struct NetworkRecordingDisclosure: View {
    var body: some View {
        DisclosureGroup("What is recorded") {
            Text("Local connection metadata: process paths, IDs, signing information, arguments and ancestry when available; destination address, port, protocol, and hostname/URL supplied by macOS. Arguments and URLs may contain sensitive information. No payloads are inspected. History stays on this Mac in an administrator-owned log, capped at 8 MiB; older entries rotate out. Separate daily app and destination summaries retain the last seven calendar days, with bounded storage. Summaries are saved every five seconds; a sudden restart may lose the latest counters. Export creates a file you control. A connection event is an attempted flow, not proof that data was transferred. Domains are unavailable for some flows. Existing connections, remote agents and traffic macOS does not deliver to the extension are outside this log.")
        }
    }
}

#endif
