#if os(macOS)
import Foundation
import SwiftUI
import BoxCopCore

struct SoftwareFixItem: Decodable, Identifiable {
    let id: String
    let name: String
    let versions: String
    let location: String
    let adapter: String
    let detail: String
    let observationIds: [String]
    var state: String? = nil
    var automatic: Bool { adapter != "review" }
}
struct SoftwareFixPlan: Decodable, Identifiable {
    let id: String
    let name: String
    let versions: String
    let location: String
    let ready: Bool
    let target: String
    let impact: String
    let fingerprint: String
    var diagnostics: String? = nil
}
struct SoftwareFixResult: Decodable, Identifiable {
    let id: String
    let status: String
    let detail: String
    var diagnostics: String? = nil
    var name: String? = nil
    var versions: String? = nil
    var attemptedAt: String? = nil
    var title: String {
        switch status {
        case "restart_needed": return "Restart needed"
        case "failed": return "Update failed"
        case "cleanup_needed": return "Old-version cleanup needed"
        case "migration_needed": return "Migration or manual review needed"
        case "in_progress": return "Completion not recorded"
        case "unverified": return "Couldn’t verify"
        default: return "Needs your decision"
        }
    }
}
struct SoftwareFixResponse: Decodable {
    let schema: String
    let plans: [SoftwareFixPlan]
    let results: [SoftwareFixResult]
    let error: String?
}

enum SoftwareRemediation {
    static func request(_ operation: String, payload: [String: Any]) async -> SoftwareFixResponse? {
        guard let input = try? JSONSerialization.data(withJSONObject: payload) else { return nil }
        return await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .utility).async {
                let process = Process(), output = Pipe(), stdin = Pipe()
                process.executableURL = Bundle.main.bundleURL.appendingPathComponent("Contents/Resources/engine/boxcop-engine")
                process.arguments = ["--software-remediation", operation]
                process.environment = EngineConfiguration.cleanEnvironment(ProcessInfo.processInfo.environment)
                process.standardInput = stdin
                process.standardOutput = output
                process.standardError = FileHandle.nullDevice
                do { try process.run() } catch { continuation.resume(returning: nil); return }
                // Preparation is bounded; installation has no time cap. Do not
                // terminate the supervisor while a package manager is working.
                try? stdin.fileHandleForWriting.write(contentsOf: input)
                try? stdin.fileHandleForWriting.close()
                var bytes = Data()
                var oversized = false
                while let chunk = try? output.fileHandleForReading.read(upToCount: 65536), !chunk.isEmpty {
                    if bytes.count + chunk.count <= 2 * 1024 * 1024 { bytes.append(chunk) }
                    else { oversized = true }
                }
                process.waitUntilExit()
                try? output.fileHandleForReading.close()
                let decoder = JSONDecoder(); decoder.keyDecodingStrategy = .convertFromSnakeCase
                let response = oversized ? nil : try? decoder.decode(SoftwareFixResponse.self, from: bytes)
                continuation.resume(returning: response?.schema == "boxcop.software-remediation.v1" ? response : nil)
            }
        }
    }
}

struct SoftwareFixChecklist: View {
    @ObservedObject var model: EndpointModel
    @State private var consoleSelection: SoftwareConsoleSelection?
    @State private var copyStatus: [String: String] = [:]
    private var items: [SoftwareFixItem] { model.activeSoftwareFixItems }
    private var automatic: [SoftwareFixItem] { items.filter(\.automatic) }
    private struct FixGroup: Identifiable {
        let id: String
        let title: String
        let action: String
        let explanation: String
        let items: [SoftwareFixItem]
        var automatic: Bool { items.allSatisfy(\.automatic) }
    }
    private var groups: [FixGroup] {
        let grouped = Dictionary(grouping: items) { item in
            if item.automatic { return item.adapter }
            if item.state == "migration_needed" { return "migration-" + item.name }
            if item.name == "node" && item.location.contains("/.nvm/") { return "node-migration" }
            if item.name.hasSuffix("-browser") { return "browser-review" }
            return "review-" + item.name
        }
        return grouped.map { key, values in
            let rows = values.sorted { ($0.name, $0.location) < ($1.name, $1.location) }
            switch key {
            case "homebrew":
                return FixGroup(id: key, title: "Homebrew packages", action: "Update with Homebrew",
                    explanation: "Update selected packages, verify the replacement, then remove affected old versions automatically.", items: rows)
            case "homebrew_cleanup":
                return FixGroup(id: key, title: "Old Homebrew versions", action: "Remove old versions",
                    explanation: "A fixed version is installed. Preview cleanup of affected copies left behind.", items: rows)
            case "pillow":
                return FixGroup(id: key, title: "Pillow environments", action: "Update Pillow",
                    explanation: "Find a compatible fixed release for each selected Python environment.", items: rows)
            case "node-migration":
                return FixGroup(id: key, title: "Node runtimes", action: "Migrate older Node versions",
                    explanation: "Review project pins and global packages before replacing or removing old installations.", items: rows)
            case "browser-review":
                return FixGroup(id: key, title: "Embedded browsers", action: "Verify the vendor fix",
                    explanation: "BoxCop can’t confirm whether these apps include the browser security fix. Check the vendor’s guidance or ask your coding agent to investigate.", items: rows)
            case "migration-pillow":
                return FixGroup(id: key, title: "Python environments", action: "Migrate Python environment",
                    explanation: rows[0].detail, items: rows)
            case "migration-ruby":
                return FixGroup(id: key, title: "Ruby installation", action: "Review runtime installation",
                    explanation: rows[0].detail, items: rows)
            default:
                return FixGroup(id: key, title: rows[0].name, action: rows[0].name == "lm-studio" ? "Update and inspect plugins" : "Review vendor guidance",
                    explanation: rows[0].detail, items: rows)
            }
        }.sorted {
            let order = ["homebrew": 0, "homebrew_cleanup": 1, "pillow": 2, "node-migration": 3, "browser-review": 4]
            return (order[$0.id] ?? 4, $0.id) < (order[$1.id] ?? 4, $1.id)
        }
    }
    private var busy: Bool { model.softwareFixBusy || model.inventoryBusy }
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            if !automatic.isEmpty {
                HStack {
                    Text("Available updates").font(.headline)
                    Spacer()
                    Button("Select all") { model.selectedSoftwareFixes = Set(automatic.map(\.id)) }
                    Button("Select none") { model.selectedSoftwareFixes.removeAll() }
                }.disabled(busy)
            }
            if !groups.isEmpty {
                VStack(spacing: 0) {
                    HStack {
                        Text("AFFECTED SOFTWARE").frame(maxWidth: .infinity, alignment: .leading)
                        Text("FIX / NEXT STEP").frame(width: 230, alignment: .leading)
                    }
                    .font(.system(size: 10, weight: .semibold)).foregroundStyle(.secondary)
                    .padding(.horizontal, 12).padding(.vertical, 10)
                    .background(Color.primary.opacity(0.035))
                    ForEach(groups) { group in
                        Divider()
                        fixRow(group)
                    }
                }
                .background(Color(nsColor: .controlBackgroundColor).opacity(0.35))
                .clipShape(RoundedRectangle(cornerRadius: 8))
                .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(Color.primary.opacity(0.1)))
            }
            if !automatic.isEmpty {
                HStack {
                    Text("\(model.selectedSoftwareFixes.count) of \(automatic.count) automatic actions selected")
                        .font(.caption).foregroundStyle(.secondary)
                    Spacer()
                    Button("Fix checked items (\(model.selectedSoftwareFixes.count))…") {
                        Task { await model.prepareSoftwareFixes() }
                    }.buttonStyle(.bordered)
                        .disabled(model.selectedSoftwareFixes.isEmpty || busy)
                }
                Text("Review versions and dependency changes before anything is installed.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            if !model.softwareFixStatus.isEmpty { Text(model.softwareFixStatus).font(.callout) }
            if let active = model.activeSoftwareFix {
                Button("View live console…") { consoleSelection = active }
            }
            if !model.softwareFixPlans.isEmpty && !model.softwareFixBusy {
                GroupBox("Review update plan") {
                    VStack(alignment: .leading, spacing: 10) {
                        ForEach(model.softwareFixPlans) { plan in
                            Text("\(plan.name): \(plan.versions) → \(plan.ready ? plan.target : "Needs review")").fontWeight(.medium)
                            Text(plan.impact).font(.caption).textSelection(.enabled)
                            if let diagnostics = plan.diagnostics, !diagnostics.isEmpty {
                                DisclosureGroup("Command details") { Text(diagnostics).font(.caption.monospaced()).textSelection(.enabled) }
                            }
                        }
                        Text("Updates may change dependencies. BoxCop will not quit apps, restart services, delete old runtimes outside an approved cleanup or change project pins. Keep BoxCop open until updates finish.").font(.caption)
                        HStack {
                            Button("Apply \(model.softwareFixPlans.filter(\.ready).count) actions") { Task { await model.applySoftwareFixes() } }
                                .disabled(!model.softwareFixPlans.contains(where: \.ready))
                            Button("Cancel") { model.cancelSoftwareFixPlan() }
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading)
                }
            }
        }.frame(maxWidth: .infinity, alignment: .leading)
        .sheet(item: $consoleSelection) { SoftwareConsoleView(selection: $0, isActive: model.activeSoftwareFix?.id == $0.id) }
    }

    private func copyInstructions(for group: FixGroup) {
        guard let report = model.softwareInventory else { return }
        let installations = group.items.map { item in
            let advisories = report.records.filter { item.observationIds.contains($0.id) }
                .flatMap(\.advisories).filter(\.needsReview)
            var seen = Set<String>()
            return SoftwareAgentInstructions.Installation(name: item.name, versions: item.versions, path: item.location,
                advisories: advisories.filter { seen.insert($0.id + "|" + $0.state).inserted }.map {
                    SoftwareAgentInstructions.Advisory(id: $0.id, state: $0.state, affectedRange: $0.affectedRange,
                        fixedVersions: $0.fixedVersions, source: $0.source, prerequisites: $0.prerequisites, remediation: $0.remediation)
                })
        }
        guard let text = SoftwareAgentInstructions.make(installations: installations, scannedAt: report.generatedAt,
                                                       incomplete: report.incomplete, coverage: report.coverage) else {
            copyStatus[group.id] = "Couldn’t prepare instructions. Recheck software and retry."; return
        }
        NSPasteboard.general.clearContents()
        copyStatus[group.id] = NSPasteboard.general.setString(text, forType: .string)
            ? "Copied · paste into your agent" : "Couldn’t copy. Try again."
    }

    private func fixRow(_ group: FixGroup) -> some View {
        let selected = group.items.filter { model.selectedSoftwareFixes.contains($0.id) }.count
        return HStack(alignment: .top, spacing: 20) {
            VStack(alignment: .leading, spacing: 7) {
                HStack(spacing: 8) {
                    if group.automatic {
                        Toggle(isOn: Binding(get: { selected == group.items.count }, set: { checked in
                            let ids = Set(group.items.map(\.id))
                            if checked { model.selectedSoftwareFixes.formUnion(ids) }
                            else { model.selectedSoftwareFixes.subtract(ids) }
                        })) { Text(group.title).fontWeight(.semibold) }
                        .toggleStyle(.checkbox).disabled(busy)
                    } else {
                        Image(systemName: "person.crop.circle.badge.questionmark").foregroundStyle(.secondary)
                        Text(group.title).fontWeight(.semibold)
                    }
                    if group.automatic && selected > 0 && selected < group.items.count {
                        Text("\(selected)/\(group.items.count) selected").font(.caption).foregroundStyle(.secondary)
                    }
                }
                if group.items.contains(where: { $0.state == "failed" }) {
                    Label("Previous update failed · retry available", systemImage: "exclamationmark.circle").font(.caption).foregroundStyle(.orange)
                }
                if group.items.contains(where: { $0.state == "in_progress" }) {
                    Text("The update’s completion couldn’t be confirmed. Check again before retrying.").font(.caption).foregroundStyle(.orange)
                }
                Text(group.items.map { "\($0.name) \($0.versions)" }.joined(separator: " · "))
                    .font(.caption).foregroundStyle(.secondary).lineLimit(2)
                DisclosureGroup("\(group.items.count) installation\(group.items.count == 1 ? "" : "s")") {
                    VStack(alignment: .leading, spacing: 10) {
                        ForEach(group.items) { item in
                            VStack(alignment: .leading, spacing: 3) {
                                if item.automatic {
                                    Toggle(isOn: Binding(get: { model.selectedSoftwareFixes.contains(item.id) }, set: { checked in
                                        if checked { model.selectedSoftwareFixes.insert(item.id) }
                                        else { model.selectedSoftwareFixes.remove(item.id) }
                                    })) { Text("\(item.name) \(item.versions)") }
                                    .toggleStyle(.checkbox).disabled(busy)
                                } else { Text("\(item.name) \(item.versions)") }
                                Text(item.location).font(.caption.monospaced()).foregroundStyle(.secondary)
                                    .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                                ForEach(model.activeSoftwareFindings.filter { item.observationIds.contains($0.id) }) { observation in
                                    SoftwareAdvisoryDetails(item: observation)
                                    Button("Ignore this finding") { model.ignoreSoftwareFinding(observation) }
                                        .disabled(busy)
                                }
                                if let result = model.softwareFixResults.first(where: { $0.id == item.id }) {
                                    DisclosureGroup("Update details") {
                                        Text(result.title).fontWeight(.medium)
                                        Text(result.detail).font(.caption)
                                        if let diagnostics = result.diagnostics, !diagnostics.isEmpty {
                                            Text(diagnostics).font(.caption.monospaced()).textSelection(.enabled)
                                        }
                                        Button("View update log…") {
                                            consoleSelection = SoftwareConsoleSelection(id: result.id, name: item.name)
                                        }
                                    }
                                }
                            }
                        }
                    }.padding(.vertical, 6)
                }.font(.caption)
            }.frame(maxWidth: .infinity, alignment: .leading)
            VStack(alignment: .leading, spacing: 6) {
                Text(group.action).fontWeight(.medium)
                Text(group.explanation).font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if group.automatic {
                    Label(group.id == "homebrew_cleanup" ? "Cleanup · preview required" : "Automatic update", systemImage: group.id == "homebrew_cleanup" ? "trash" : "arrow.down.circle")
                        .font(.caption).foregroundStyle(AppPalette.accent)
                } else {
                    Text("Needs your review").font(.caption).foregroundStyle(.orange)
                    Button("Copy agent instructions") { copyInstructions(for: group) }
                        .font(.caption)
                        .help("Copies this group’s installed versions, local paths, advisories and repair options. Nothing is sent automatically.")
                    if let status = copyStatus[group.id] {
                        Text(status).font(.caption).foregroundStyle(.secondary)
                    }
                }
            }.frame(width: 230, alignment: .leading)
        }.padding(12)
    }
}

struct SoftwareAdvisoryDetails: View {
    let item: SoftwareObservation
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            ForEach(item.advisories.filter(\.needsReview)) { advisory in
                Text(advisory.id).fontWeight(.medium)
                Text(advisory.prerequisites)
                Text(advisory.remediation)
                AlertFeedbackButton(category: .software)
                Text("Affected: \(advisory.affectedRange) · Fixed in: \(advisory.fixedVersions)")
                if let url = URL(string: advisory.source), url.scheme == "https" {
                    Link("Read security guidance", destination: url)
                }
            }
        }.font(.caption).padding(.vertical, 6)
    }
}
#endif
