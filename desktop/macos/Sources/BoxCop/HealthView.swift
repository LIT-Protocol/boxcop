#if os(macOS)
import SwiftUI
import BoxCopCore

extension ExposureAdvisory {
    /// How pressing a finding is, from what the check could establish.
    var severity: (label: String, color: Color) {
        switch state {
        case "affected_version": return ("Vulnerable", Palette.red)
        case "update_available": return ("Update available", Palette.amber)
        default: return ("Needs a check", Palette.accent)
        }
    }
}

/// Software findings, what to do about each, and a guided fix for the ones BoxCop can update.
struct HealthView: View {
    @ObservedObject var model: AppModel
    @State private var console: SoftwareConsoleSelection?
    @State private var copied: String?
    @State private var expanded = Set<String>()
    @State private var showIgnored = false

    private struct FixGroup: Identifiable {
        let id: String
        let title: String
        let action: String
        let explanation: String
        let items: [SoftwareFixItem]
        var automatic: Bool { items.allSatisfy(\.automatic) }
    }
    private var groups: [FixGroup] {
        let grouped = Dictionary(grouping: model.activeFixItems) { item -> String in
            if item.automatic { return item.adapter }
            if item.state == "migration_needed" { return "migration-" + item.name }
            if item.name == "node" && item.location.contains("/.nvm/") { return "node-migration" }
            if item.name.hasSuffix("-browser") { return "browser-review" }
            return "review-" + item.name
        }
        let order = ["homebrew": 0, "homebrew_cleanup": 1, "pillow": 2, "node-migration": 3, "browser-review": 4]
        return grouped.map { key, values -> FixGroup in
            let rows = values.sorted { ($0.name, $0.location) < ($1.name, $1.location) }
            switch key {
            case "homebrew": return FixGroup(id: key, title: "Homebrew packages", action: "Update with Homebrew",
                                             explanation: "Updates the selected packages, checks the new version, then removes the affected old copies.", items: rows)
            case "homebrew_cleanup": return FixGroup(id: key, title: "Old Homebrew versions", action: "Remove old versions",
                                                     explanation: "A fixed version is installed. This removes the affected copies left behind.", items: rows)
            case "pillow": return FixGroup(id: key, title: "Pillow in Python environments", action: "Update Pillow",
                                           explanation: "Finds a compatible fixed release for each selected environment.", items: rows)
            case "node-migration": return FixGroup(id: key, title: "Old Node versions", action: "Move projects to a supported Node",
                                                   explanation: "Check which projects still use these versions before replacing or removing them.", items: rows)
            case "browser-review": return FixGroup(id: key, title: "Apps with a built-in browser", action: "Check the vendor's fix",
                                                   explanation: "BoxCop cannot tell whether these apps include the browser security fix. Check the vendor's guidance or ask your agent to look.", items: rows)
            default: return FixGroup(id: key, title: rows[0].name, action: rows[0].name == "lm-studio" ? "Update and check plugins" : "Read the vendor's guidance",
                                     explanation: rows[0].detail, items: rows)
            }
        }.sorted { (order[$0.id] ?? 5, $0.id) < (order[$1.id] ?? 5, $1.id) }
    }
    private var busy: Bool { model.fixBusy || model.inventoryBusy }
    private var automatic: [SoftwareFixItem] { model.activeFixItems.filter(\.automatic) }

    var body: some View {
        let groups = self.groups
        let count = model.activeFindings.count
        PageScaffold(title: "Health", subtitle: subtitle(count)) {
            HStack(spacing: 10) {
                Button(copied == "all" ? "Copied" : "Copy all steps for my agent") {
                    copyInstructions(model.activeFixItems, copyID: "all")
                }
                .buttonStyle(.quiet).disabled(busy || model.activeFixItems.isEmpty)
                .help("Copies active findings and repair guidance, including local paths. Review before sharing with an agent.")
                if model.inventoryBusy { ProgressView().controlSize(.small) }
                Button(model.inventoryBusy ? "Checking" : "Check now") { Task { await model.refreshInventory() } }
                    .buttonStyle(.quiet).disabled(busy || !model.capabilities.engine)
            }
        } content: {
            if let error = model.inventoryError { Text(error).font(.system(size: 12.5)).foregroundStyle(Palette.amber) }
            if !model.wants(.machineHealth) {
                notice("Machine health is off.", "Turn it on to check installed software for known security issues every five minutes.", "Turn on") { model.setLayer(.machineHealth, on: true) }
            } else if model.inventory == nil {
                Text(model.capabilities.engine ? "The first check has not finished yet." : LayerRules.engineMissing).font(.system(size: 12.5)).foregroundStyle(Palette.quiet)
            } else if groups.isEmpty {
                HStack(spacing: 10) {
                    Image(systemName: "checkmark.circle.fill").font(.system(size: 18)).foregroundStyle(Palette.green)
                    Text(model.ignoredFindings.isEmpty ? "No known issues in the software BoxCop checked." : "Nothing needs your attention. Ignored findings are listed below.")
                        .font(.system(size: 13))
                }
            } else {
                RowGroup {
                    ForEach(Array(groups.enumerated()), id: \.element.id) { index, group in
                        if index > 0 { RowDivider() }
                        row(group)
                    }
                }
                if !automatic.isEmpty { fixBar }
            }
            if !model.fixStatus.isEmpty { Text(model.fixStatus).font(.system(size: 12.5)) }
            if let active = model.activeFix { Button("Show live console") { console = active }.buttonStyle(.quiet) }
            if !model.fixPlans.isEmpty && !model.fixBusy { plan }
            if !model.ignoredFindings.isEmpty { ignored }
            if let report = model.inventory, report.incomplete {
                Text("This check was incomplete: \(report.coverage)").font(.system(size: 11.5)).foregroundStyle(Palette.quiet).fixedSize(horizontal: false, vertical: true)
            }
            Text("A finding means an installed version has a known security issue. It does not mean an attack was detected.")
                .font(.system(size: 11.5)).foregroundStyle(Palette.quiet)
        }
        .sheet(item: $console) { SoftwareConsoleView(selection: $0, isActive: model.activeFix?.id == $0.id) }
    }

    private func subtitle(_ count: Int) -> String {
        var checked = "Not checked yet."
        if let date = model.inventoryCheckedAt { checked = "Last checked " + date.formatted(date: .omitted, time: .shortened) + "." }
        else if let report = model.inventory { checked = "Last checked " + Format.stamp(report.generatedAt) + "." }
        let findings: String = count == 0 ? "No findings to review." : "\(count) finding\(count == 1 ? "" : "s") to review."
        return findings + " " + checked
    }

    private func notice(_ title: String, _ text: String, _ button: String, action: @escaping () -> Void) -> some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.system(size: 13, weight: .semibold))
                Text(text).font(.system(size: 12.5)).foregroundStyle(Palette.quiet)
            }
            Spacer()
            Button(button, action: action).buttonStyle(.primary).disabled(!model.capabilities.engine)
        }
        .padding(14)
        .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(Palette.border))
    }

    private func advisories(_ group: FixGroup) -> [ExposureAdvisory] {
        let ids = Set(group.items.flatMap(\.observationIds))
        return model.activeFindings.filter { ids.contains($0.id) }.flatMap(\.advisories)
    }

    private func row(_ group: FixGroup) -> some View {
        let selected = group.items.filter { model.selectedFixes.contains($0.id) }.count
        let worst = advisories(group).map(\.severity).min { rank($0.label) < rank($1.label) }
        let open = expanded.contains(group.id)
        return VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .top, spacing: 10) {
                if group.automatic {
                    Toggle("", isOn: Binding(get: { selected == group.items.count }, set: { checked in
                        let ids = Set(group.items.map(\.id))
                        if checked { model.selectedFixes.formUnion(ids) } else { model.selectedFixes.subtract(ids) }
                    })).toggleStyle(CheckStyle()).labelsHidden().disabled(busy).accessibilityLabel("Fix \(group.title)")
                } else {
                    Image(systemName: "person.crop.circle.badge.questionmark").font(.system(size: 13)).foregroundStyle(Palette.quiet).frame(width: 16)
                }
                VStack(alignment: .leading, spacing: 3) {
                    HStack(spacing: 8) {
                        Text(group.title).font(.system(size: 13, weight: .semibold))
                        if let worst { Pill(text: worst.label, color: worst.color) }
                        if group.items.contains(where: { $0.state == "failed" }) { Pill(text: "Last update failed", color: Palette.amber) }
                    }
                    Text(group.items.map { "\($0.name) \($0.versions)" }.joined(separator: " · ")).font(.system(size: 12, design: .monospaced)).foregroundStyle(Palette.quiet).lineLimit(1)
                    Text(group.action + ". " + group.explanation).font(.system(size: 12)).fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 8)
                VStack(alignment: .trailing, spacing: 6) {
                    if group.automatic { Pill(text: "BoxCop can fix", color: Palette.green) }
                    else { Button(copied == group.id ? "Copied" : "Copy steps for my agent") { copyInstructions(group) }.buttonStyle(.quiet)
                        .help("Copies the installed versions, paths, advisories and repair options. Nothing is sent anywhere.") }
                    Button(open ? "Hide details" : "Details") { if open { expanded.remove(group.id) } else { expanded.insert(group.id) } }
                        .buttonStyle(.plain).font(.system(size: 11.5, weight: .medium)).foregroundStyle(Palette.accent)
                }
            }
            if open { details(group) }
        }
        .padding(12)
    }

    private func rank(_ label: String) -> Int { ["Vulnerable": 0, "Update available": 1][label] ?? 2 }

    private func details(_ group: FixGroup) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            ForEach(group.items) { item in
                VStack(alignment: .leading, spacing: 4) {
                    HStack(spacing: 8) {
                        if item.automatic {
                            Toggle("", isOn: Binding(get: { model.selectedFixes.contains(item.id) }, set: { checked in
                                if checked { model.selectedFixes.insert(item.id) } else { model.selectedFixes.remove(item.id) }
                            })).toggleStyle(CheckStyle()).labelsHidden().disabled(busy).accessibilityLabel("Fix \(item.name)")
                        }
                        Text("\(item.name) \(item.versions)").font(.system(size: 12.5, weight: .medium))
                    }
                    Text(item.location).font(.system(size: 11.5, design: .monospaced)).foregroundStyle(Palette.quiet).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                    ForEach(model.activeFindings.filter { item.observationIds.contains($0.id) }) { observation in
                        ForEach(observation.advisories) { advisory in
                            VStack(alignment: .leading, spacing: 2) {
                                HStack(spacing: 8) {
                                    Text(advisory.id).font(.system(size: 12, weight: .medium))
                                    Pill(text: advisory.severity.label, color: advisory.severity.color)
                                }
                                Text(advisory.prerequisites).font(.system(size: 12))
                                Text(advisory.remediation).font(.system(size: 12))
                                Text("Affected: \(advisory.affectedRange). Fixed in: \(advisory.fixedVersions).").font(.system(size: 11.5)).foregroundStyle(Palette.quiet)
                                if let url = URL(string: advisory.source), url.scheme == "https" { Link("Read the security advisory", destination: url).font(.system(size: 11.5)) }
                            }
                        }
                        Button("Ignore this finding") { model.ignoreFinding(observation) }.buttonStyle(.quiet).disabled(busy)
                    }
                    if let result = model.fixResults.first(where: { $0.id == item.id }) {
                        Text("\(result.title). \(result.detail)").font(.system(size: 12)).foregroundStyle(Palette.quiet).fixedSize(horizontal: false, vertical: true)
                        Button("Show update log") { console = SoftwareConsoleSelection(id: result.id, name: item.name) }.buttonStyle(.quiet)
                    }
                }
            }
        }
        .padding(.leading, 26)
    }

    private var fixBar: some View {
        HStack(spacing: 10) {
            Text("\(model.selectedFixes.count) of \(automatic.count) automatic fixes selected").font(.system(size: 12)).foregroundStyle(Palette.quiet)
            Spacer()
            Button("Select all") { model.selectedFixes = Set(automatic.map(\.id)) }.buttonStyle(.quiet).disabled(busy)
            Button("Fix selected") { Task { await model.prepareFixes() } }.buttonStyle(.primary).disabled(model.selectedFixes.isEmpty || busy)
                .help("Shows the exact versions and changes first. Nothing is installed until you apply the plan.")
        }
    }

    private var plan: some View {
        VStack(alignment: .leading, spacing: 9) {
            SectionTitle("Review the plan")
            ForEach(model.fixPlans) { plan in
                VStack(alignment: .leading, spacing: 2) {
                    Text("\(plan.name): \(plan.versions) → \(plan.ready ? plan.target : "needs a manual check")").font(.system(size: 12.5, weight: .medium))
                    Text(plan.impact).font(.system(size: 12)).foregroundStyle(Palette.quiet).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                    if let diagnostics = plan.diagnostics, !diagnostics.isEmpty {
                        Text(diagnostics).font(.system(size: 11, design: .monospaced)).foregroundStyle(Palette.quiet).textSelection(.enabled)
                    }
                }
            }
            Text("Updates can change dependencies. BoxCop does not quit apps, restart services or change project version pins. Keep BoxCop open until the updates finish.")
                .font(.system(size: 11.5)).foregroundStyle(Palette.quiet).fixedSize(horizontal: false, vertical: true)
            HStack {
                Button("Apply \(model.fixPlans.filter(\.ready).count) update\(model.fixPlans.filter(\.ready).count == 1 ? "" : "s")") { Task { await model.applyFixes() } }
                    .buttonStyle(.primary).disabled(!model.fixPlans.contains(where: \.ready))
                Button("Cancel") { model.cancelFixPlan() }.buttonStyle(.quiet)
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Palette.sidebar.opacity(0.6), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(Palette.border))
    }

    private var ignored: some View {
        let rows = model.ignoredFindings.sorted { ($0.name, $0.version, $0.advisoryID) < ($1.name, $1.version, $1.advisoryID) }
        return VStack(alignment: .leading, spacing: 7) {
            Button { showIgnored.toggle() } label: {
                HStack(spacing: 5) {
                    Image(systemName: showIgnored ? "chevron.down" : "chevron.right").font(.system(size: 9, weight: .semibold))
                    SectionTitle("Ignored findings (\(rows.count))")
                }.foregroundStyle(Palette.quiet).contentShape(Rectangle())
            }.buttonStyle(.plain)
            if showIgnored {
                RowGroup {
                    ForEach(Array(rows.enumerated()), id: \.element) { index, finding in
                        if index > 0 { RowDivider() }
                        HStack(spacing: 8) {
                            Text("\(finding.name) \(finding.version)").font(.system(size: 12, weight: .medium))
                            Text(finding.advisoryID).font(.system(size: 11.5, design: .monospaced)).foregroundStyle(Palette.quiet).lineLimit(1)
                            Spacer()
                            Button("Restore") { model.restoreFinding(finding) }.buttonStyle(.quiet).disabled(busy)
                        }
                        .padding(.horizontal, 10).frame(height: 32)
                    }
                }
            }
        }
    }

    private func copyInstructions(_ group: FixGroup) {
        copyInstructions(group.items, copyID: group.id)
    }

    private func copyInstructions(_ items: [SoftwareFixItem], copyID: String) {
        guard let report = model.inventory else { return }
        let installations = items.map { item -> SoftwareAgentInstructions.Installation in
            let advisories = model.activeFindings.filter { item.observationIds.contains($0.id) }.flatMap(\.advisories).filter(\.needsReview)
            var seen = Set<String>()
            return SoftwareAgentInstructions.Installation(name: item.name, versions: item.versions, path: item.location,
                advisories: advisories.filter { seen.insert($0.id + "|" + $0.state).inserted }.map {
                    SoftwareAgentInstructions.Advisory(id: $0.id, state: $0.state, affectedRange: $0.affectedRange,
                        fixedVersions: $0.fixedVersions, source: $0.source, prerequisites: $0.prerequisites, remediation: $0.remediation)
                })
        }
        guard let text = SoftwareAgentInstructions.make(installations: installations, scannedAt: report.generatedAt,
                                                       incomplete: report.incomplete, coverage: report.coverage) else { return }
        Format.copy(text); copied = copyID
    }
}
#endif
