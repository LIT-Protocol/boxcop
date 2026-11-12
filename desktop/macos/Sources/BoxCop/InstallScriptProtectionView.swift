#if os(macOS)
import SwiftUI
import BoxCopCore

/// Controls and evidence for contained package install scripts. Rows state what was
/// refused; they do not claim an attack was stopped.
struct InstallScriptProtectionView: View {
    @ObservedObject var model: EndpointModel
    @State private var busy = false
    @State private var failed = false

    private var status: ScriptProtectionStatus? { model.scriptProtectionStatus }

    var body: some View {
        GroupBox("Install script protection · npm") {
            VStack(alignment: .leading, spacing: 10) {
                Text(!model.running ? "Start BoxCop protection to manage install scripts" :
                    (failed ? "Install script protection status unavailable" : status?.summary ?? "Checking install script protection…")).fontWeight(.medium)
                Text("Scripts that packages run while they install can only connect to approved destinations. This covers anything those scripts start, including background processes.").font(.caption)
                if let status, status.routed, !status.active {
                    Text("Routing is enabled but BoxCop’s proxy is not running, so install scripts currently have no network access at all.")
                        .font(.caption).foregroundStyle(.orange)
                }
                HStack {
                    Button(status?.active == true ? "Protection enabled" : "Enable install script protection") { perform(.enable) }
                        .disabled(!model.running || busy || status?.active == true)
                    Button("Disable") { perform(.disable) }.disabled(!model.running || busy || status?.routed != true)
                }
                if let blocked = status?.blocked, !blocked.isEmpty {
                    Divider()
                    Text("Blocked connections").font(.caption).fontWeight(.medium)
                    ForEach(blocked) { item in
                        VStack(alignment: .leading, spacing: 4) {
                            Text(item.message).font(.caption).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                            Text([item.project.map { "Project: " + $0 }, item.count > 1 ? "\(item.count) attempts" : nil, "Last: " + item.time]
                                .compactMap { $0 }.joined(separator: " · ")).font(.caption2).foregroundStyle(.secondary).textSelection(.enabled)
                            if let package = item.package {
                                Button("Allow \(item.host) for \(package)") { perform(.allow, package: package, host: item.host) }
                                    .controlSize(.small).disabled(busy)
                            }
                        }
                    }
                }
                if let exceptions = status?.exceptions, !exceptions.isEmpty {
                    Divider()
                    Text("Approved destinations").font(.caption).fontWeight(.medium)
                    ForEach(exceptions, id: \.self) { rule in
                        HStack {
                            Text(rule.package + " → " + rule.host).font(.caption).textSelection(.enabled)
                            Spacer()
                            Button("Remove") { perform(.revoke, package: rule.package, host: rule.host) }.controlSize(.small).disabled(busy)
                        }
                    }
                }
                Text("Blocks outgoing connections only. Install scripts can still read files, and an approved destination can still be misused. Code a package leaves behind runs unrestricted later. Scripts that connect without using the proxy settings are blocked without being listed here.")
                    .font(.caption).foregroundStyle(.secondary)
                Text("Covers npm. A project’s own npm settings can override it, and installs inside an agent’s own sandbox rely on that sandbox instead. Your project’s own scripts are not restricted.")
                    .font(.caption).foregroundStyle(.secondary)
            }.frame(maxWidth: .infinity, alignment: .leading).padding(8)
        }
    }

    private func perform(_ action: ScriptProtectionAction, package: String = "", host: String = "") {
        guard !busy else { return }
        busy = true
        Task { @MainActor in
            defer { busy = false }
            do { try await model.scriptProtection(action, package: package, host: host); failed = false } catch { failed = true }
        }
    }
}
#endif
