#if os(macOS)
import SwiftUI
import BoxCopCore

/// Live controls and evidence behind the personal-app layout from the BoxCop study.
struct EndpointDetails: View {
    @ObservedObject var model: EndpointModel
    let section: Section
    enum Section { case liveStatus, software, paste, workflow, consent, guardSettings, diagnostics, limits, integration, decisions }
    var body: some View {
        Group {
            switch section {
            case .liveStatus: liveStatus
            case .software: software
            case .paste: paste
            case .workflow: workflow
            case .consent: consent
            case .guardSettings: guardSettings
            case .diagnostics: diagnostics
            case .limits: limits
            case .integration: integration
            case .decisions: decisions
            }
        }
    }
    private var liveStatus: some View {
        GroupBox("Live status") {
            VStack(alignment: .leading, spacing: 8) {
                Text(model.menuStatus).font(.headline)
                Text(model.engineStatus)
                Text(model.collectionStatus)
                Text(model.journalStatus)
                Text(model.endpointSecurityStatus)
                Text(model.hostAgentStatus).font(.caption).textSelection(.enabled)
                Text(model.guardStatus)
                if let error = model.errorMessage { Text(error).foregroundStyle(.red) }
                Text("\(model.workflow.events.count) workflow events · \(model.workflow.dropped) evicted")
                Text(model.activityCollection ? "Activity collection runs automatically while monitoring. Browser collection requires the extension; macOS permissions control access to window context and screen capture." : "Activity collection is off. Turn it on under Monitoring permissions.")
                    .font(.caption).foregroundStyle(.secondary)
            }.frame(maxWidth: .infinity, alignment: .leading).padding(8)
        }
    }
    private var software: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 6) {
                    Text(model.inventoryStatus).font(.headline)
                    if let checked = model.inventoryCheckedAt {
                        Text("Last checked \(checked.formatted(date: .abbreviated, time: .shortened))")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                Spacer()
                Button(model.inventoryBusy ? "Checking…" : "Check again") {
                    Task { await model.refreshSoftwareInventory() }
                }.disabled(model.inventoryBusy || model.softwareFixBusy)
            }
            if let report = model.softwareInventory {
                TimelineView(.periodic(from: .now, by: 30)) { context in
                    if let checked = model.inventoryCheckedAt, context.date.timeIntervalSince(checked) > 600 {
                        Label("Results may be out of date. Check again for the latest findings.", systemImage: "clock")
                            .font(.callout).foregroundStyle(.orange)
                    }
                }
                if report.incomplete {
                    Label("Some software couldn’t be checked. See check details below.", systemImage: "exclamationmark.triangle")
                        .font(.callout).foregroundStyle(.orange)
                }
                SoftwareFixChecklist(model: model)
                Text("Ignore a finding in its installation details to hide it from Home. Your choice is saved on this Mac; new advisories or changed versions will appear again.")
                    .font(.caption).foregroundStyle(.secondary)
                if !model.ignoredSoftwareFindings.isEmpty {
                    DisclosureGroup("Ignored findings (\(model.ignoredSoftwareFindings.count))") {
                        VStack(alignment: .leading, spacing: 12) {
                            Text("Ignored findings are not fixed. Undo restores them to attention if they are still detected.")
                                .font(.caption).foregroundStyle(.secondary)
                            ForEach(model.ignoredSoftwareFindings.sorted {
                                [$0.name, $0.path, $0.version, $0.advisoryID, $0.state, $0.fixedVersions, $0.kind].lexicographicallyPrecedes(
                                    [$1.name, $1.path, $1.version, $1.advisoryID, $1.state, $1.fixedVersions, $1.kind])
                            }, id: \.self) { finding in
                                HStack(alignment: .top) {
                                    VStack(alignment: .leading, spacing: 3) {
                                        Text("\(finding.name) \(finding.version) · \(finding.advisoryID)")
                                        Text(finding.path).font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                                    }
                                    Spacer()
                                    Button("Undo") { model.restoreSoftwareFinding(finding) }
                                        .disabled(model.inventoryBusy || model.softwareFixBusy)
                                }
                            }
                        }.padding(.vertical, 8)
                    }
                }
                // Keep guidance available even if an observation has no repair action.
                let ungrouped = model.activeSoftwareFindings.filter { finding in
                    !(report.remediationItems ?? []).contains { $0.observationIds.contains(finding.id) }
                }
                ForEach(ungrouped) { item in
                    DisclosureGroup("\(item.name) \(item.version) — review guidance") {
                        SoftwareAdvisoryDetails(item: item)
                        Button("Ignore this finding") { model.ignoreSoftwareFinding(item) }
                            .disabled(model.inventoryBusy || model.softwareFixBusy)
                    }
                }
                Text("Checks selected software for known security issues. Running apps and embedded components may still need verification.")
                    .font(.caption).foregroundStyle(.secondary)
                DisclosureGroup("Check details") {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Security advisories reviewed \(report.reviewedAt). Checks refresh every five minutes while BoxCop is open.")
                        Text(report.coverage)
                        ForEach(report.limitations ?? [], id: \.self) { Text($0) }
                        if report.cacheStatus != "saved" { Text("Latest report could not be saved locally.") }
                        ForEach(Array((report.issueDetails ?? []).enumerated()), id: \.offset) { _, issue in
                            Text(issue.path).font(.caption.monospaced()).textSelection(.enabled)
                            Text(issue.explanation)
                        }
                        ForEach(report.issues, id: \.self) { Text($0.replacingOccurrences(of: "_", with: " ")) }
                        ForEach(Array((report.roots ?? []).enumerated()), id: \.offset) { _, root in
                            Text("\(root.path) · \(root.state.replacingOccurrences(of: "_", with: " "))")
                                .textSelection(.enabled)
                        }
                    }.font(.caption).foregroundStyle(.secondary).padding(.top, 8)
                }
            }
        }.frame(maxWidth: .infinity, alignment: .leading)
    }
    private var paste: some View {
        GroupBox("Latest paste check") {
            VStack(alignment: .leading, spacing: 8) {
                Text(model.clipboardStatus)
                if let record = model.records.first(where: { $0.kind != .clipboardCopy }) {
                    Text("Most recent paste evaluation · \(record.action.rawValue.uppercased()) · \(record.createdAt.formatted(date: .omitted, time: .standard))").font(.headline)
                    ForEach(Array(record.reasons.enumerated()), id: \.offset) { _, reason in Text(reason) }
                    Text(PolicyReason.recovery(record.action)).font(.callout)
                    Text("Historical decision; check Home for current protection coverage. Reference: \(record.id.uuidString)").font(.caption).textSelection(.enabled)
                }
                Button("Manage paste protection") { model.selectedPage = .connections }
            }.frame(maxWidth: .infinity, alignment: .leading).padding(8)
        }
    }
    private var workflow: some View {
        GroupBox("Recent activity") {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Button("Export activity…") { model.exportWorkflow() }.disabled(model.workflow.events.isEmpty)
                    Spacer()
                    Text("Live view · last 2,000 events").foregroundStyle(.secondary)
                }
                if model.workflow.events.isEmpty { Text("No activity yet.").foregroundStyle(.secondary) }
                ForEach(model.workflow.events.suffix(16).reversed()) { event in
                    Text("\(event.observedAt.formatted(date: .omitted, time: .standard)) · \(event.kind) · \(event.availability)")
                        .font(.caption.monospaced())
                }
            }.frame(maxWidth: .infinity, alignment: .leading).padding(8)
        }
    }
    private var consent: some View {
        GroupBox(model.requiresMonitoringConsent ? "Monitoring consent" : "Session overrides") {
            VStack(alignment: .leading, spacing: 10) {
                Text(model.requiresMonitoringConsent ? "Enable monitoring, then choose Start monitoring. Decisions are saved on this Mac." : "Development mode starts all implemented collectors automatically. Monitoring can be paused for this session. Monitor app focus, launches/exits, bundle identity/PID and new clipboard plain text. The frontmost app when observed is not proof of who copied it.")
                Toggle("Allow local monitoring", isOn: Binding(get: { model.choices.monitoring }, set: model.setMonitoringConsent))
                if model.requiresMonitoringConsent {
                    Toggle("Collect app activity", isOn: Binding(get: { model.activityCollection }, set: model.setActivityCollection))
                }
                Text("Clipboard text is checked locally and is not saved. Activity collection includes window context, selected text, pointer activity, home-folder changes, connected browser and agent events, and window captures. Exports may contain private activity details. Allow clipboard access when macOS asks so BoxCop can check pastes.").font(.caption).foregroundStyle(.secondary)
                Picker("Role for protection rules", selection: Binding(get: { model.choices.role }, set: model.setRole)) {
                    ForEach(Role.allCases, id: \.self) { Text($0.rawValue.capitalized).tag($0) }
                }.pickerStyle(.segmented)
                HStack {
                    Button("Start monitoring") { model.start() }.disabled(!model.canStart)
                    Button("Pause monitoring") { model.pause() }.disabled(!model.running && !model.starting)
                    Button("Retry") { model.retry() }.disabled(model.starting || model.stopping || !model.choices.monitoring)
                }
                Text(model.engineStatus).font(.callout)
                if let error = model.errorMessage { Label(error, systemImage: "exclamationmark.triangle").foregroundStyle(.red) }
                Text(model.clipboardStatus).font(.callout)
            }.frame(maxWidth: .infinity, alignment: .leading).padding(8)
        }
    }
    private var guardSettings: some View {
        GroupBox("Paste protection") {
            VStack(alignment: .leading, spacing: 10) {
                Toggle("Check standard Command-V pastes", isOn: Binding(get: { model.choices.guardShortcut }, set: model.setGuardConsent))
                    .disabled(model.teamConnection.state.settings["guard_shortcut"] != nil)
                HStack {
                    Button("Request Accessibility…") { model.requestAccessibility() }
                    Button("Retry paste protection") { model.retry() }.disabled(!model.running || !model.choices.guardShortcut)
                }
                Text(model.guardStatus).font(.callout)
                Text("Pastes are allowed by default, including large text and unavailable or pending checks. Only a completed block decision for the same clipboard and destination holds Command-V. A paste may pass before a background check detects a secret. The clipboard is never changed.").font(.caption)
            }.frame(maxWidth: .infinity, alignment: .leading).padding(8)
        }
    }
    private var diagnostics: some View {
        GroupBox("Development diagnostics") {
            VStack(alignment: .leading, spacing: 8) {
                Toggle("Write local development log", isOn: Binding(get: { model.developmentLogging }, set: model.setDevelopmentLogging))
                Text(model.developmentStatus).font(.caption).textSelection(.enabled)
                if model.developmentLogging {
                    Button("Run in-app paste test (overwrites clipboard)") { model.runPasteSelfTest() }
                    Text(model.pasteTestStatus).font(.caption).textSelection(.enabled)
                }
            }.frame(maxWidth: .infinity, alignment: .leading).padding(8)
        }
    }
    private var limits: some View {
        GroupBox("Protection limits") {
            VStack(alignment: .leading, spacing: 8) {
                Text("Edit → Paste, remapped/nonstandard shortcuts, drag/drop, direct clipboard reads, browser/network APIs, uploads, Secure Input, lost event taps and an exited app can bypass interception. Monitoring alone blocks nothing.")
                Text("Pastes have no size limit. New plain text up to 4096 Unicode scalars is checked; larger pastes are allowed without a content check. Files, multiple items, password-manager observations and concealed/transient/auto-generated clipboard representations are skipped. Unavailable or incomplete checks do not block pasting. Only a completed block decision stops a paste. Copy new text after Start/Resume or after resolving an unsupported state.")
                Text("An allowed paste is not a guarantee that the content is safe. Activity history shows checks, not whether content was pasted or sent.")
            }.font(.caption).frame(maxWidth: .infinity, alignment: .leading).padding(8)
        }
    }
    private var integration: some View {
        GroupBox("Startup & notifications") {
            VStack(alignment: .leading, spacing: 8) {
                Toggle("Security notifications", isOn: Binding(get: { model.choices.notifications }, set: model.setNotifications))
                Text("Alerts for blocked pastes and software that needs review. Clipboard content is never included.").font(.caption).foregroundStyle(.secondary)
                Text(model.notificationsStatus).font(.caption)
                NotificationVisibilityView()
                Button("Send test notification") { model.sendTestNotification() }
                if let status = model.testNotificationStatus { Text(status).font(.caption).foregroundStyle(.secondary) }
                Toggle("Show brief review heads-ups", isOn: Binding(get: { model.onScreenAlertsEnabled }, set: model.setOnScreenAlertsEnabled))
                Toggle("Keep heads-ups on screen until I dismiss them", isOn: Binding(get: { model.keepReviewAlertsVisible }, set: model.setKeepReviewAlertsVisible))
                    .disabled(!model.onScreenAlertsEnabled)
                Text("For enabled draft, email, code and PDF review alerts, BoxCop shows a small heads-up instead of requesting a macOS notification. Requires BoxCop banners to be allowed in Notification Settings. BoxCop does not detect Focus; this setting applies all the time.")
                    .font(.caption).foregroundStyle(.secondary)
                Text("Heads-ups show no email or file details and do not take keyboard focus. They hide after 8 seconds, pause while hovered, and combine bursts. Closing one does not mark anything reviewed. Pending reviews remain in BoxCop; orange in the menu bar means protection needs attention.")
                    .font(.caption).foregroundStyle(.secondary)
                Text("VoiceOver uses macOS notifications and the menu review count to preserve your reading position. Heads-ups are hidden when screen sharing or main-display mirroring is detected. Sharing detection may be unavailable without Accessibility permission. Existing security intervention panels keep their own behavior.")
                    .font(.caption).foregroundStyle(.secondary)
                Toggle("Launch BoxCop at login", isOn: Binding(get: { model.loginEnabled }, set: model.setLoginEnabled)).disabled(model.loginBusy)
                Text(model.loginStatus).font(.caption)
                Toggle("Start monitoring when BoxCop opens", isOn: Binding(get: { model.choices.autoStart }, set: model.setAutoStart)).disabled(!model.choices.monitoring)
                Text(model.choices.autoStart ? "Monitoring starts at launch. To stay paused after reopening BoxCop, turn this off." : "Monitoring stays paused until you start it.").font(.caption)
                Text("Monitoring pauses during sleep. If you paused it yourself, it stays paused after waking.").font(.caption).foregroundStyle(.secondary)
            }.frame(maxWidth: .infinity, alignment: .leading).padding(8)
        }
    }
    private var decisions: some View {
        GroupBox("Recent decisions") {
            VStack(alignment: .leading, spacing: 12) {
                if model.records.isEmpty { Text("No decisions yet. Start monitoring to save local decision history.").foregroundStyle(.secondary) }
                ForEach(model.records) { record in
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Text(record.action.rawValue.uppercased()).bold().foregroundStyle(record.action == .block ? Color.red : record.action == .warn ? Color.orange : Color.primary)
                            Text(record.kind == .clipboardCopy ? "Clipboard observation" : (record.kind == .pastePreparation ? "Prepared paste policy" : "Paste attempt"))
                            Spacer()
                            Text(record.createdAt, style: .time).font(.caption)
                        }
                        Text(record.bundleID ?? "App identity not retained").font(.caption.monospaced())
                        ForEach(Array(record.reasons.enumerated()), id: \.offset) { _, reason in Text(reason).font(.caption) }
                        if !record.policyIDs.isEmpty { Text(record.policyIDs.joined(separator: ", ")).font(.caption.monospaced()).foregroundStyle(.secondary) }
                    }
                    Divider()
                }
            }.frame(maxWidth: .infinity, alignment: .leading).padding(8)
        }
    }
}
#endif
