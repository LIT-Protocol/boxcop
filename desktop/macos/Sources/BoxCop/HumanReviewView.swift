#if os(macOS)
import SwiftUI
import AppKit
import LocalAuthentication
import CryptoKit
import UserNotifications
import BoxCopCore

struct ReviewPolicies: Codable, Equatable {
    var external = false
    var destructive = false
    var spending = false
    var threshold_cents = 2500
    var currency = "usd"
}
struct ReviewRequest: Codable, Identifiable {
    let id: String
    let status: String
    let application: String
    let source: String
    let command: String
    let input: String
    let reasons: [String]
    let expires: Double
    var created: Double?
    var reviewed_at: Double?
    var consumed_at: Double?
}
/// Advisory, local-model text. Never part of what is approved.
struct ReviewSummary: Decodable {
    let summary: String?
    let concerns: [String]?
    let failed: Bool?
}
struct ReviewSnapshot: Decodable {
    let ok: Bool
    let policies: ReviewPolicies?
    let requests: [ReviewRequest]?
    let error: String?
    let managed_by: String?
    var summaries: [String: ReviewSummary]?
    var summary_model: Bool?
}

struct HumanReviewView: View {
    @ObservedObject var model: EndpointModel
    @ObservedObject var approvals: AgentApprovalWatcher
    @State private var policies = ReviewPolicies()
    @State private var savedPolicies = ReviewPolicies()
    @State private var requests: [ReviewRequest] = []
    @State private var summaries: [String: ReviewSummary] = [:]
    @State private var summaryModel = false
    @State private var error: String?
    @State private var managedBy: String?
    @State private var busy = false
    @State private var queued = false
    @State private var loaded = false
    @State private var notificationsDelivered = true

    private var anyRuleOn: Bool { savedPolicies.external || savedPolicies.spending }
    private var now: Double { Date().timeIntervalSince1970 }
    private var waiting: [ReviewRequest] { requests.reversed().filter { $0.status == "pending" && $0.expires > now } }
    private var history: [ReviewRequest] { requests.reversed().filter { !($0.status == "pending" && $0.expires > now) } }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("Choose which agent actions need your approval.").font(.headline)
            Text("These rules cover recognized commands in connected Claude Code, Codex and Cursor hooks on this Mac. Other tools, hidden script effects, browser actions and cloud agents are not covered. Existing security blocks cannot be overridden here.")
                .foregroundStyle(.secondary)
            if loaded && anyRuleOn && !notificationsDelivered {
                HStack(alignment: .top, spacing: 10) {
                    Image(systemName: "bell.slash").foregroundStyle(.orange)
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Notifications are off, so held actions can wait here unseen.").font(.callout.weight(.medium))
                        Text("Agents stop until you answer. The menu bar and this page still show the count.").font(.caption).foregroundStyle(.secondary)
                        HStack {
                            Button("Turn on notifications") { model.setNotifications(true); Task { try? await Task.sleep(nanoseconds: 1_500_000_000); await checkNotifications() } }
                            Link("Notification Settings", destination: URL(string: "x-apple.systempreferences:com.apple.Notifications-Settings.extension")!)
                        }.font(.caption)
                    }
                }
                .padding(12).frame(maxWidth: .infinity, alignment: .leading)
                .background(Color.orange.opacity(0.08), in: RoundedRectangle(cornerRadius: 10))
            }
            HStack {
                Text(waiting.isEmpty ? "Approval inbox" : "Waiting for you (\(waiting.count))").font(.headline)
                Spacer()
                Button("Refresh") { refresh() }
            }
            if let error { Text(error).foregroundStyle(.red) }
            if loaded && waiting.isEmpty {
                Text(anyRuleOn ? "Nothing is waiting. When an enabled rule matches, the agent pauses and the action appears here."
                               : "No rules are on. Turn on a rule below to hold matching agent actions for your approval.")
                    .foregroundStyle(.secondary)
            }
            ForEach(waiting) { request in
                ApprovalRequestCard(request: request, summary: summaries[request.id], summaryModel: summaryModel,
                                    reject: { resolve(request, approve: false) }, approve: { resolve(request, approve: true) })
            }
            GroupBox("Review policies") {
                VStack(alignment: .leading, spacing: 12) {
                    Toggle("Review external communications", isOn: $policies.external)
                    Text("Recognized mail, sendmail, SMTP and gog/gws send commands. All recipients require review.").font(.caption).foregroundStyle(.secondary)
                    Toggle("Review spending above a threshold", isOn: $policies.spending)
                    Stepper("Threshold: \(Double(policies.threshold_cents) / 100, format: .currency(code: "USD"))", value: $policies.threshold_cents, in: 0...100000000, step: 500)
                        .disabled(!policies.spending)
                    Text("Stripe charge/payment-intent commands only. Unknown amounts and other currencies require review. This does not cover purchases in other apps.").font(.caption).foregroundStyle(.secondary)
                    Button("Save policies") {
                        if policies.external || policies.spending { model.requestApprovalNotificationsIfUndecided() }
                        perform(["op": "configure", "policies": policyObject])
                    }
                        .disabled(!loaded || policies == savedPolicies)
                    Text("Changing policies expires outstanding approvals. Requests retain command content locally; keep sensitive values out of command arguments.").font(.caption).foregroundStyle(.secondary)
                }.padding(8)
            }
            .disabled(managedBy != nil)
            if let managedBy {
                Text("Review rules are managed by \(managedBy). Cached rules stay active offline. Individual actions still need your approval on this Mac.").font(.callout)
            }
            if !history.isEmpty {
                Text("Recent").font(.headline)
                VStack(spacing: 0) {
                    ForEach(Array(history.prefix(25).enumerated()), id: \.element.id) { index, request in
                        if index > 0 { Divider() }
                        ApprovalHistoryRow(request: request, summary: summaries[request.id])
                    }
                }
                .padding(.horizontal, 12)
                .overlay(RoundedRectangle(cornerRadius: 10).stroke(AppPalette.border))
            }
        }.disabled(busy)
            .task { refresh(); await checkNotifications() }
            .onChange(of: approvals.revision) { refresh() }
            .onChange(of: approvals.pending.map(\.id)) { refresh() }
    }
    private var policyObject: [String: Any] {
        ["external": policies.external, "destructive": false, "spending": policies.spending,
         "threshold_cents": policies.threshold_cents, "currency": policies.currency]
    }
    private func checkNotifications() async {
        let settings = await UNUserNotificationCenter.current().notificationSettings()
        notificationsDelivered = model.choices.notifications && (settings.authorizationStatus == .authorized || settings.authorizationStatus == .provisional) && settings.alertSetting == .enabled
    }
    private func refresh() {
        if busy { queued = true } else { perform(["op": "status"]) }
    }
    private func resolve(_ request: ReviewRequest, approve: Bool) {
        perform(["op": "resolve", "id": request.id, "approve": approve])
    }
    private func perform(_ request: [String: Any]) {
        guard !busy, let input = try? JSONSerialization.data(withJSONObject: request) else { return }
        busy = true
        Task {
            let result = await ReviewService.request(input)
            busy = false
            defer {
                approvals.touch()
                if queued { queued = false; perform(["op": "status"]) }
            }
            guard let result, result.ok, let config = result.policies, let rows = result.requests else {
                error = result?.error ?? "Approval service unavailable. Use the installed BoxCop app and refresh."
                return
            }
            error = nil; loaded = true
            policies = config; savedPolicies = config; requests = rows; managedBy = result.managed_by
            summaries = result.summaries ?? [:]; summaryModel = result.summary_model ?? false
        }
    }
}

/// One held action, readable first and exact underneath.
struct ApprovalRequestCard: View {
    let request: ReviewRequest
    let summary: ReviewSummary?
    let summaryModel: Bool
    let reject: () -> Void
    let approve: () -> Void
    @State private var showRaw = false
    private var details: AgentActionDetails { AgentActionDetails(application: request.application, command: request.command, input: request.input) }

    var body: some View {
        let details = details
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .firstTextBaseline) {
                Image(systemName: "hand.raised.fill").foregroundStyle(.orange)
                Text(details.agent).font(.headline)
                if let tool = details.tool { Text(tool).font(.subheadline).foregroundStyle(.secondary) }
                Spacer()
                Text("Expires \(Date(timeIntervalSince1970: request.expires), style: .relative)").font(.caption).foregroundStyle(.secondary).monospacedDigit()
            }
            HStack(spacing: 6) {
                ForEach(request.reasons, id: \.self) { ApprovalChip(text: AgentActionDetails.reasonLabel($0), color: .orange) }
                if details.sandboxDisabled { ApprovalChip(text: "Sandbox disabled", color: .red, symbol: "exclamationmark.triangle.fill") }
            }
            ApprovalSummaryView(summary: summary, summaryModel: summaryModel, pending: true)
            if let description = details.agentDescription {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Agent says").font(.caption).foregroundStyle(.secondary)
                    Text(description).textSelection(.enabled)
                }
            }
            if let command = details.command {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Command").font(.caption).foregroundStyle(.secondary)
                    ScrollView {
                        Text(command).font(.system(.callout, design: .monospaced)).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading).padding(10)
                    }
                    .frame(maxHeight: 220).fixedSize(horizontal: false, vertical: true)
                    .background(AppPalette.sidebar, in: RoundedRectangle(cornerRadius: 8))
                    .overlay(RoundedRectangle(cornerRadius: 8).stroke(AppPalette.border))
                }
            }
            Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 4) {
                if let path = details.displayPath() { detailRow("Folder", path) }
                if let session = details.shortSessionID { detailRow("Session", session) }
                if let timeout = details.timeoutSeconds { detailRow("Timeout", "\(timeout) s") }
                ForEach(details.otherArguments, id: \.name) { detailRow($0.name, $0.value) }
            }
            DisclosureGroup("Exact request", isExpanded: $showRaw) {
                Text(details.rawJSON).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading).padding(.top, 4)
            }.font(.caption)
            HStack {
                Button("Reject", role: .destructive, action: reject)
                Button("Review and approve once…", action: approve).buttonStyle(.borderedProminent)
                Spacer()
                AlertFeedbackButton(category: .agent)
            }
            Text("Approval requires Mac authentication and allows one exact retry. BoxCop never runs the action itself; the agent must retry it.")
                .font(.caption).foregroundStyle(.secondary)
        }
        .padding(16).frame(maxWidth: .infinity, alignment: .leading)
        .background(AppPalette.canvas, in: RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.orange.opacity(0.5)))
    }
    private func detailRow(_ name: String, _ value: String) -> some View {
        GridRow {
            Text(name).font(.caption).foregroundStyle(.secondary)
            Text(value).font(.system(.caption, design: .monospaced)).textSelection(.enabled).lineLimit(3)
        }
    }
}

private struct ApprovalSummaryView: View {
    let summary: ReviewSummary?
    let summaryModel: Bool
    let pending: Bool
    var body: some View {
        if let text = summary?.summary {
            VStack(alignment: .leading, spacing: 4) {
                Label("Summary from the on-device model. It can be wrong; check the command.", systemImage: "sparkles")
                    .font(.caption).foregroundStyle(.secondary)
                Text(text).fixedSize(horizontal: false, vertical: true).textSelection(.enabled)
                ForEach(summary?.concerns ?? [], id: \.self) { concern in
                    Label(concern, systemImage: "exclamationmark.circle").font(.callout).foregroundStyle(.orange)
                }
            }
            .padding(10).frame(maxWidth: .infinity, alignment: .leading)
            .background(AppPalette.accent.opacity(0.06), in: RoundedRectangle(cornerRadius: 8))
        } else if pending && summary == nil && summaryModel {
            HStack(spacing: 6) {
                ProgressView().controlSize(.small)
                Text("Summarizing on this Mac…").font(.caption).foregroundStyle(.secondary)
            }
        } else if pending && !summaryModel {
            Text("Plain-English summaries use the on-device model. Turn on Local AI workflow review in Settings to download it.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }
}

private struct ApprovalChip: View {
    let text: String
    let color: Color
    var symbol: String? = nil
    var body: some View {
        HStack(spacing: 4) {
            if let symbol { Image(systemName: symbol) }
            Text(text)
        }
        .font(.caption.weight(.medium)).foregroundStyle(color)
        .padding(.horizontal, 8).padding(.vertical, 3)
        .background(color.opacity(0.12), in: Capsule())
    }
}

/// Finished, expired or rejected requests: one line each, details on demand.
struct ApprovalHistoryRow: View {
    let request: ReviewRequest
    let summary: ReviewSummary?
    @State private var expanded = false
    private var status: (String, Color) {
        switch request.status {
        case "pending": return ("Expired", .secondary)
        case "approved": return ("Approved · awaiting retry", .green)
        case "consumed": return ("Approved · used", .green)
        case "rejected": return ("Rejected", .red)
        default: return (request.status.capitalized, .secondary)
        }
    }
    var body: some View {
        let details = AgentActionDetails(application: request.application, command: request.command, input: request.input)
        DisclosureGroup(isExpanded: $expanded) {
            VStack(alignment: .leading, spacing: 8) {
                if let text = summary?.summary { Text(text).font(.callout) }
                if let description = details.agentDescription { Text("Agent says: " + description).font(.callout).foregroundStyle(.secondary) }
                if let path = details.displayPath() { Text(path).font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary) }
                Text(details.command ?? request.command).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading).padding(8)
                    .background(AppPalette.sidebar, in: RoundedRectangle(cornerRadius: 6))
                if request.status == "approved" {
                    Text("Ready for one exact retry before expiry. Approval does not execute the action.").font(.caption).foregroundStyle(.secondary)
                } else if request.status == "consumed" {
                    Text("Permission used once. Completion is not verified by the hook.").font(.caption).foregroundStyle(.secondary)
                }
            }.padding(.vertical, 6)
        } label: {
            HStack(spacing: 8) {
                Text(details.agent).font(.callout.weight(.medium))
                Text(request.reasons.map(AgentActionDetails.reasonLabel).joined(separator: ", ")).font(.callout).foregroundStyle(.secondary)
                Text(details.agentDescription ?? firstLine(details.command ?? request.command))
                    .font(.callout).foregroundStyle(.secondary).lineLimit(1).truncationMode(.tail)
                Spacer(minLength: 8)
                Text(status.0).font(.caption).foregroundStyle(status.1)
                if let created = request.created {
                    Text(Date(timeIntervalSince1970: created), style: .time).font(.caption).foregroundStyle(.secondary)
                }
            }
        }
        .padding(.vertical, 8)
    }
    private func firstLine(_ text: String) -> String { String(text.split(separator: "\n", maxSplits: 1).first ?? "") }
}

enum ReviewService {
    static func request(_ input: Data) async -> ReviewSnapshot? {
        await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                let process = Process(), output = Pipe(), stdin = Pipe()
                let bundle = Bundle.main.bundleURL
                process.executableURL = bundle.appendingPathComponent("Contents/Resources/engine/boxcop-engine")
                process.arguments = ["--human-review", "--data-dir", FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/BoxCop").path,
                                     "--executable", bundle.appendingPathComponent("Contents/MacOS/BoxCop").path]
                process.standardInput = stdin; process.standardOutput = output; process.standardError = FileHandle.nullDevice
                do {
                    try process.run()
                    DispatchQueue.global().asyncAfter(deadline: .now() + 125) { if process.isRunning { process.terminate() } }
                    try stdin.fileHandleForWriting.write(contentsOf: input)
                    try stdin.fileHandleForWriting.close()
                    let data = output.fileHandleForReading.readDataToEndOfFile()
                    process.waitUntilExit()
                    continuation.resume(returning: try? JSONDecoder().decode(ReviewSnapshot.self, from: data))
                } catch { continuation.resume(returning: nil) }
            }
        }
    }
}

/// The CLI cannot supply an approval flag: this entry point always asks the Mac owner.
@MainActor enum AgentActionReview {
    static func run() -> Never {
        let bytes = FileHandle.standardInput.readData(ofLength: 100001)
        guard bytes.count <= 100000,
              let request = try? JSONDecoder().decode(ReviewRequest.self, from: bytes),
              request.status == "pending", request.expires > Date().timeIntervalSince1970 else { exit(1) }
        _ = NSApplication.shared
        NSApp.setActivationPolicy(.accessory)
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = "Approve this \(AgentActionDetails.agentName(request.application)) action once?"
        alert.informativeText = "\(request.reasons.joined(separator: "; "))\n\nAllows one exact retry in the reported session before expiry. This does not execute the action or verify completion."
        alert.addButton(withTitle: "Cancel")
        alert.addButton(withTitle: "Authenticate and approve")
        alert.buttons[0].keyEquivalent = "\r"
        alert.buttons[1].keyEquivalent = ""
        let scroll = NSScrollView(frame: NSRect(x: 0, y: 0, width: 650, height: 350))
        scroll.hasVerticalScroller = true
        let text = NSTextView(frame: scroll.bounds)
        text.isEditable = false; text.isSelectable = true
        text.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
        let details = AgentActionDetails(application: request.application, command: request.command, input: request.input)
        var lines = ["Agent: \(details.agent)" + (details.tool.map { " · \($0)" } ?? "")]
        if let path = details.workingDirectory { lines.append("Folder: \(path)") }
        if details.sandboxDisabled { lines.append("Sandbox: DISABLED for this command") }
        if let description = details.agentDescription { lines.append("Agent says: \(description)") }
        lines.append("\nCommand:\n\(details.command ?? request.command)")
        lines.append("\n— Exact request (this is what is approved) —\n\(details.rawJSON)")
        text.string = lines.joined(separator: "\n")
        text.isVerticallyResizable = true
        text.textContainer?.widthTracksTextView = true
        text.autoresizingMask = [.width]
        scroll.documentView = text
        alert.accessoryView = scroll
        guard alert.runModal() == .alertSecondButtonReturn else { exit(1) }
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else { exit(1) }
        var finished = false, approved = false
        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "approve the exact agent action you reviewed.") { success, _ in
            DispatchQueue.main.async { approved = success; finished = true }
        }
        let deadline = Date().addingTimeInterval(90)
        while !finished && Date() < deadline { RunLoop.current.run(until: Date().addingTimeInterval(0.05)) }
        context.invalidate()
        guard finished && approved && request.expires > Date().timeIntervalSince1970 else { exit(1) }
        let digest = SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
        print("{\"approved\":true,\"review_sha256\":\"\(digest)\"}")
        exit(0)
    }
}
#endif
