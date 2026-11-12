#if os(macOS)
import SwiftUI
import BoxCopCore

/// Home summarizes evidence; configuration lives in Connections and Settings.
struct ProtectionDashboard: View {
    @ObservedObject var model: EndpointModel
    @ObservedObject var network: NetworkConnectionsModel
    private var pasteActive: Bool { model.running && model.guardActive }
    private var findings: [SoftwareObservation] { model.activeSoftwareFindings }
    @State private var approvals: ReviewPolicies?
    @State private var approvalsManaged = false
    @State private var packages: PackageProtectionStatus?
    private var human: Bool { model.showsHumanChecks }
    /// Agents are found but BoxCop is not checking them yet.
    private var agentsAvailable: [String]? {
        if case let .available(tools)? = model.agentSetupStatus { return tools }
        return nil
    }
    private var networkActive: Bool {
        network.setupReady && network.snapshot?.threatProtection?.enabled == true && network.snapshot?.threatProtection?.error == nil
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 24) {
            HStack(alignment: .top, spacing: 14) {
                Image(systemName: "shield.lefthalf.filled").font(.system(size: 32)).foregroundStyle(AppPalette.accent)
                VStack(alignment: .leading, spacing: 6) {
                    Text(model.running ? "Your protection at a glance." : "Know where you stand.").font(.system(size: 25, weight: .semibold))
                    Text("Your protection, what needs attention, and the decisions BoxCop has made.")
                        .foregroundStyle(.secondary)
                }
            }
            nextSteps
            coverage
            SecurityActivityFeed(records: model.records, events: model.workflow.events, limit: 5) {
                model.selectedPage = .activity
            }
        }
        .task {
            if let input = try? JSONSerialization.data(withJSONObject: ["op": "status"]),
               let snapshot = await ReviewService.request(input), snapshot.ok {
                approvals = snapshot.policies; approvalsManaged = snapshot.managed_by != nil
            }
        }
        .task(id: model.running) {
            packages = model.running ? try? await model.packageProtection(.status) : nil
        }
    }

    private var nextSteps: some View {
        GroupBox("Needs attention") {
            VStack(alignment: .leading, spacing: 14) {
                if let tools = agentsAvailable {
                    action("Connect your AI agents", detail: "BoxCop found " + AgentSetupCopy.join(tools) + " but isn’t checking their actions yet.",
                           button: "Review setup", symbol: "terminal") { model.selectedPage = .connections }
                }
                if human && !pasteActive {
                    action(model.starting ? "Protection is starting" : "Turn on paste protection",
                           detail: model.menuStatus + ". Turn on paste protection to check supported keyboard shortcuts.",
                           button: "Review setup", symbol: "doc.on.clipboard") { model.selectedPage = .connections }
                }
                if !findings.isEmpty || model.softwareFixBusy {
                    softwareSummary
                }
                if model.softwareInventory == nil {
                    action("Check installed software", detail: model.inventoryStatus,
                           button: "Review software", symbol: "app.badge") { model.softwareReviewPresented = true }
                }
                if model.releaseProfile.usesNetworkProtection && !networkActive {
                    action("Review outgoing protection", detail: network.status,
                           button: "Review connections", symbol: "network") { model.selectedPage = .connections }
                }
                if (pasteActive || !human) && agentsAvailable == nil && findings.isEmpty && !model.softwareFixBusy && model.softwareInventory != nil && (!model.releaseProfile.usesNetworkProtection || networkActive) {
                    Label("No immediate actions from the current checks.", systemImage: "checkmark.circle")
                    Text("Review coverage below for limits and unverified connections.").font(.caption).foregroundStyle(.secondary)
                }
                HStack {
                    if let checked = model.inventoryCheckedAt {
                        Text("Software checked \(checked.formatted(date: .abbreviated, time: .shortened))").font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button(model.inventoryBusy ? "Checking…" : "Recheck software") { Task { await model.refreshSoftwareInventory() } }
                        .disabled(model.inventoryBusy || model.softwareFixBusy)
                }
                TimelineView(.periodic(from: .now, by: 30)) { context in
                    if let checked = model.inventoryCheckedAt, context.date.timeIntervalSince(checked) > 600 {
                        Text("Software results are out of date. Recheck for current findings.").font(.caption).foregroundStyle(.orange)
                    }
                }
            }
        }
    }

    private var softwareSummary: some View {
        let items = model.activeSoftwareFixItems
        let automatic = items.filter(\.automatic).count
        let review = items.count - automatic
        let names = Array(Set(items.map(\.name))).sorted()
        return VStack(alignment: .leading, spacing: 8) {
            action(model.softwareFixBusy ? "Software fixes in progress" : "Software needs attention",
                   detail: items.isEmpty ? "Review the latest software findings and next steps." : "\(items.count) installation\(items.count == 1 ? "" : "s") · \(automatic) automatic fixes · \(review) need review",
                   button: model.softwareFixBusy ? "View progress" : "Review and fix", symbol: "app.badge") {
                model.softwareReviewPresented = true
            }
            if !names.isEmpty {
                Text(names.prefix(5).joined(separator: ", ") + (names.count > 5 ? " and \(names.count - 5) more" : ""))
                    .font(.caption).foregroundStyle(.secondary)
            }
            if model.softwareFixBusy {
                Text(model.softwareFixStatus).font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    private var coverage: some View {
        GroupBox {
            VStack(spacing: 12) {
                coverageRow("Agent actions", status: agentStatus.text, symbol: "terminal", active: agentStatus.active,
                            detail: "Checks commands and file actions in connected Claude Code, Codex and Cursor sessions.")
                Divider()
                coverageRow("Agent approvals", status: approvalsStatus.text, symbol: "hand.raised", active: approvalsStatus.active,
                            detail: "Holds recognized agent commands that send messages or spend money until you approve them.")
                Divider()
                coverageRow("Outgoing connections", status: model.releaseProfile.usesNetworkProtection ? (networkActive ? "Threat blocking active" : "Not confirmed active") : "Not included in this build", symbol: "network", active: networkActive && model.releaseProfile.usesNetworkProtection,
                            detail: "Blocks listed threat domains in every app, including downloads and requests made by agents. Other destinations and existing connections may remain allowed.")
                Divider()
                coverageRow("Packages", status: packages?.active == true ? "Blocking known malicious packages" : "Not active", symbol: "shippingbox", active: packages?.active == true,
                            detail: "Routes npm and pnpm installs, including ones agents run, through BoxCop’s malicious package list.")
                Divider()
                coverageRow("Software checks", status: model.softwareInventory == nil ? "Not checked" : (model.softwareInventory?.incomplete == true ? "Some software could not be checked" : "Check complete"),
                            symbol: "app.badge", active: model.softwareInventory != nil && model.softwareInventory?.incomplete == false,
                            detail: "Checks installed software for known vulnerabilities. Review software coverage to see what was checked or skipped.")
                Button("Review software coverage") { model.softwareReviewPresented = true }.font(.caption)
                if human {
                    Divider()
                    coverageRow("Sensitive data", status: pasteActive ? "Limited protection active" : "Not active", symbol: "doc.on.clipboard", active: pasteActive,
                                detail: "Checks supported Command-V pastes. Menu Paste, uploads and direct clipboard reads can bypass checks.")
                    Divider()
                    coverageRow("Email review (Gmail)", status: model.reviewCoverage.status, symbol: "envelope.badge",
                                active: model.reviewCoverage.active, detail: model.reviewCoverage.detail)
                    Divider()
                    coverageRow("Screen sharing", status: model.presentationRunning ? "Selected presentation active" : "Direct sharing is not protected", symbol: "rectangle.on.rectangle", active: model.presentationRunning,
                                detail: model.presentationRunning ? "Only BoxCop’s presentation window is checked before display. Direct sharing bypasses it." : model.backgroundScreenStatus + " Warnings cannot prevent exposure.")
                }
            }
        } label: {
            HStack {
                Text("Your coverage")
                Spacer()
                Button("Manage connections") { model.selectedPage = .connections }.font(.caption)
            }
        }
    }

    private var agentStatus: (text: String, active: Bool) {
        switch model.agentSetupStatus {
        case nil: return ("No supported agents found", false)
        case .available?, .failed?: return ("Not connected", false)
        case .added?: return ("Connected · waiting for first check", false)
        case let .on(tools)?: return ("Checking " + AgentSetupCopy.join(tools), true)
        }
    }
    private var approvalsStatus: (text: String, active: Bool) {
        guard let approvals else { return ("Status unavailable", false) }
        let on = [approvals.external, approvals.spending].filter { $0 }.count
        let text = on == 2 ? "On" : on == 0 ? "Off" : "\(on) of 2 rules on"
        return (approvalsManaged ? text + " · set by your team" : text, on > 0)
    }

    private func action(_ title: String, detail: String, button: String, symbol: String, perform: @escaping () -> Void) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: symbol).foregroundStyle(.orange).frame(width: 22).padding(.top, 2)
            VStack(alignment: .leading, spacing: 5) {
                Text(title).fontWeight(.semibold)
                Text(detail).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 8)
            Button(button, action: perform)
        }
    }

    private func coverageRow(_ title: String, status: String, symbol: String, active: Bool, detail: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: symbol).foregroundStyle(AppPalette.quiet).frame(width: 22)
            VStack(alignment: .leading, spacing: 5) {
                HStack {
                    Text(title).fontWeight(.medium)
                    Spacer()
                    Text(status).font(.caption).foregroundStyle(active ? Color.green : AppPalette.quiet)
                }
                Text(detail).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

struct SecurityActivityFeed: View {
    let records: [SafeRecord]
    let events: [WorkflowEvent]
    var limit = 30
    var showAll: (() -> Void)?
    private var items: [SecurityActivityItem] { SecurityActivityItem.make(records: records, events: events) }

    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 14) {
                if items.isEmpty {
                    Label("No recent security decisions", systemImage: "clock")
                    Text("Blocks, warnings and actions you allow will appear here. See Connections for what BoxCop checks.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                ForEach(Array(items.prefix(limit))) { item in
                    DisclosureGroup {
                        VStack(alignment: .leading, spacing: 6) {
                            Text(item.detail)
                            Text(item.date.formatted(date: .abbreviated, time: .standard)).foregroundStyle(.secondary)
                            if let category = item.feedbackCategory { AlertFeedbackButton(category: category) }
                        }.font(.caption).textSelection(.enabled).padding(.vertical, 6)
                    } label: {
                        HStack(alignment: .top, spacing: 10) {
                            Image(systemName: "shield.lefthalf.filled").foregroundStyle(AppPalette.accent)
                            VStack(alignment: .leading, spacing: 4) {
                                Text(item.title).fontWeight(.medium)
                                Text(item.summary).font(.caption).foregroundStyle(.secondary).lineLimit(2)
                            }
                            Spacer()
                            Text(item.date, style: .time).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
            }
        } label: {
            HStack {
                Text("Recent security activity")
                Spacer()
                if let showAll { Button("View activity", action: showAll).font(.caption) }
            }
        }
    }
}
#endif
