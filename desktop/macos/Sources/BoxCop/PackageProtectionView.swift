#if os(macOS)
import SwiftUI
import BoxCopCore

struct PackageProtectionView: View {
    @ObservedObject var model: EndpointModel
    @State private var status: PackageProtectionStatus?
    @State private var requesting = false
    @State private var pendingAction: PackageProtectionAction?
    @State private var error: String?

    private var active: Bool { model.running && error == nil && status?.active == true }

    var body: some View {
        GroupBox("Package protection · npm and pnpm") {
            VStack(alignment: .leading, spacing: 10) {
                Text(!model.running ? "Start BoxCop protection to manage package installs" :
                    (error == nil ? status?.summary ?? "Checking package protection…" : "Package protection status unavailable")).fontWeight(.medium)
                // Status polling is read-only; show setup progress only while
                // the engine is actually changing package protection.
                if model.running && status?.busy == true {
                    HStack { ProgressView().controlSize(.small); Text("BoxCop is setting up package protection…") }
                }
                if let error { Text(error).foregroundStyle(.orange).textSelection(.enabled) }
                Text("Block listed malicious package downloads without delaying newly published releases.").font(.caption)
                if let status {
                    if status.routed && !status.active && !status.busy {
                        Text("Package routing is enabled, but protection is not ready. Retry or disable routing to restore installs.")
                            .font(.caption).foregroundStyle(.orange)
                    }
                    if status.active && status.stale {
                        Text("The malware list is over 24 hours old. Existing matches still block; recent threats may be missing.")
                            .font(.caption).foregroundStyle(.orange)
                    }
                    if let date = status.generatedAt { Text("List updated: \(date)").font(.caption).textSelection(.enabled) }
                    if let updateError = status.updateError { Text(updateError).font(.caption).foregroundStyle(.orange) }
                }
                HStack {
                    Button(active ? "Protection enabled" : "Enable npm and pnpm protection") { perform(.enable) }
                        .disabled(!model.running || pendingAction != nil || status?.busy == true || status?.configured == false || active)
                    Button("Disable package routing") { perform(.disable) }
                        .disabled(!model.running || pendingAction != nil || status?.busy == true || status?.routed != true)
                    Button("Recheck") { perform(.status) }.disabled(!model.running || pendingAction != nil)
                }
                Text("Package protection runs inside BoxCop. Quitting or pausing BoxCop stops it; package installs routed through BoxCop will fail until protection resumes or you disable routing. Scoped private registries are preserved.")
                    .font(.caption).foregroundStyle(.secondary)
                Text("Cached packages, project settings, direct URLs and other package managers may bypass these checks. An allowed package has no matching block; it is not certified safe.")
                    .font(.caption).foregroundStyle(.secondary)
            }.frame(maxWidth: .infinity, alignment: .leading).padding(8)
        }.task(id: model.running) {
            status = nil
            guard model.running else { return }
            while !Task.isCancelled {
                if !requesting && pendingAction == nil { await request(.status) }
                do { try await Task.sleep(nanoseconds: 1_000_000_000) } catch { return }
            }
        }
    }

    private func perform(_ action: PackageProtectionAction) {
        guard pendingAction == nil else { return }
        pendingAction = action
        Task { @MainActor in
            defer { pendingAction = nil }
            // A click during a background poll must be honored, not dropped.
            // Reserve the next request while the current poll completes.
            while requesting {
                do { try await Task.sleep(nanoseconds: 20_000_000) } catch { return }
            }
            guard model.running, !Task.isCancelled else { return }
            await request(action)
        }
    }

    @MainActor private func request(_ action: PackageProtectionAction) async {
        guard !requesting else { return }
        requesting = true
        defer { requesting = false }
        do {
            status = try await model.packageProtection(action)
            error = nil
        } catch {
            // Preserve the last known routing state so a failed status request
            // does not remove the recovery controls or report protection active.
            self.error = "Could not reach BoxCop’s package protection. Recheck or restart BoxCop protection."
        }
    }
}
#endif
