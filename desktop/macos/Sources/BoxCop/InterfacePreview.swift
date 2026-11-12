#if os(macOS)
import AppKit
import SwiftUI
import PDFKit
import BoxCopCore

/// Render the real interface without activating collectors, hooks or the engine.
/// Usage: BoxCop --dev-interface-preview /absolute/output/directory
@MainActor enum InterfacePreview {
    /// A held Claude Code action as it appears in the inbox, with and without a local summary.
    private static func renderApprovals(destination: URL) throws {
        let input = #"{"cwd": "/Users/me/.t3/worktrees/BoxCop/t3-280416ab", "hook_event_name": "PreToolUse", "session_id": "337f02ec-dda2-48bb-9a7a-8b47e1b2fb8d", "tool_input": {"command": "ssh -F ~/.sentinel-lab/ssh_config -oHostName=192.168.64.4 boxcop-lab 'mkdir -p ~/pr135 && cat > ~/pr135/probe.command <<\"EOF\"\n#!/bin/zsh\nexport PATH=\"$HOME/SentinelLab/p01-vendor-clis/bin:$PATH\"\ncd /tmp && claude -p \"Reply with just the word pong\" > ~/pr135/probe.log 2>&1\necho \"exit=$?\" >> ~/pr135/probe.log\nEOF\nchmod +x ~/pr135/probe.command; rm -f ~/pr135/probe.log; open -a Terminal ~/pr135/probe.command'", "dangerouslyDisableSandbox": true, "description": "Run Claude in guest GUI session via open", "timeout": 120000}, "tool_name": "Bash"}"#
        let request = ReviewRequest(id: "preview", status: "pending", application: "claude", source: "reported-shell-hook:/Users/me",
                                    command: "", input: input, reasons: ["Review destructive actions"], expires: Date().timeIntervalSince1970 + 167,
                                    created: Date().timeIntervalSince1970 - 733)
        let summary = ReviewSummary(summary: "Connects over SSH to the lab VM at 192.168.64.4, writes a small script there that asks Claude to reply \"pong\", deletes the previous probe log and opens the script in Terminal on that machine.",
                                    concerns: ["Runs commands on a remote machine", "Deletes ~/pr135/probe.log on the remote host", "The agent asked to run this outside its sandbox"], failed: nil)
        for dark in [false, true] {
            try render(VStack(alignment: .leading, spacing: 16) {
                ApprovalRequestCard(request: request, summary: summary, summaryModel: true, reject: {}, approve: {})
                ApprovalRequestCard(request: request, summary: nil, summaryModel: false, reject: {}, approve: {})
                ApprovalHistoryRow(request: ReviewRequest(id: "old", status: "rejected", application: "claude", source: "", command: "rm -rf build",
                    input: #"{"cwd": "/tmp", "tool_input": {"command": "rm -rf build", "description": "Clean build output"}, "tool_name": "Bash"}"#,
                    reasons: ["Review destructive actions"], expires: 0, created: Date().timeIntervalSince1970 - 4000), summary: nil)
                    .padding(.horizontal, 12).overlay(RoundedRectangle(cornerRadius: 10).stroke(AppPalette.border))
            }.padding(24).frame(width: 760).background(AppPalette.canvas).environment(\.colorScheme, dark ? .dark : .light),
            name: "approval-request" + (dark ? "-dark" : ""), destination: destination)
        }
    }
    static func run(directory: String) throws {
        let destination = URL(fileURLWithPath: directory, isDirectory: true)
        try FileManager.default.createDirectory(at: destination, withIntermediateDirectories: true)
        let suite = "BoxCop.InterfacePreview.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        let model = EndpointModel(defaults: defaults)
        _ = NSApplication.shared
        NSApp.setActivationPolicy(.prohibited)
        for dark in [false, true] {
            try render(InterventionNoticeView(title: "Paste blocked", actionTitle: "Allow once",
                message: "BoxCop’s protection rules blocked this paste. Allow once if you trust this destination.",
                allow: {}, feedback: {}, dismiss: {}).environment(\.colorScheme, dark ? .dark : .light),
                name: "paste-alert" + (dark ? "-dark" : ""), destination: destination)
            try render(InterventionNoticeView(title: "Connection blocked", actionTitle: "Open BoxCop",
                message: InterventionKind.network.message, allow: {}, feedback: {}, dismiss: {})
                .environment(\.colorScheme, dark ? .dark : .light),
                name: "network-alert" + (dark ? "-dark" : ""), destination: destination)
        }
        try render(AlertFeedbackForm(category: .paste).environmentObject(model.productSupport),
                   name: "alert-feedback", destination: destination)
        try render(ProductSupportSettings(support: model.productSupport).environmentObject(model.productSupport)
            .padding(20).frame(width: 760).background(AppPalette.canvas), name: "crash-report-settings", destination: destination)
        try renderSetup(destination: destination)
        // Home and Connections follow the agent/human choice: agent protection only, then after opting in.
        model.setHumanChecksShown(false)
        for (name, shown) in [("individual", false), ("human-checks", true)] {
            model.setHumanChecksShown(shown)
            try render(ProtectionDashboard(model: model, network: model.networkConnections).padding(20).frame(width: 760).background(AppPalette.canvas),
                       name: "home-" + name, destination: destination)
            try render(ProtectionSetupView(model: model).padding(20).frame(width: 760).background(AppPalette.canvas),
                       name: "connections-" + name, destination: destination)
        }
        model.setHumanChecksShown(false)
        for page in EndpointPage.allCases {
            model.selectedPage = page
            try render(EndpointView(model: model), name: page.rawValue.lowercased(), size: NSSize(width: 900, height: page == .protection ? 1000 : 680), destination: destination)
        }
        try renderApprovals(destination: destination)
        if let replay = ProcessInfo.processInfo.environment["BOXCOP_CODE_REPLAY"] {
            try model.configureCodeVerificationInterfacePreview(replayPath: replay)
            try render(CodeVerificationActivity(model: model).padding(20).frame(width: 900).background(AppPalette.canvas),
                       name: "code-verification", destination: destination)
            model.verifyCodeVerificationPreviewCleanup()
        }
        if let replay = ProcessInfo.processInfo.environment["BOXCOP_NODE_REPLAY"] {
            try model.configureCodeVerificationInterfacePreview(replayPath: replay)
            try render(CodeVerificationActivity(model: model).padding(20).frame(width: 900).background(AppPalette.canvas),
                       name: "code-verification-node", destination: destination)
            model.verifyCodeVerificationPreviewCleanup()
        }
        if let replay = ProcessInfo.processInfo.environment["BOXCOP_CI_REPLAY"] {
            try model.configureCodeVerificationInterfacePreview(replayPath: replay, expectedOutcomes: ["failed_ci_check", "passing_ci_observed", "unknown", "unknown"])
            try render(CodeVerificationActivity(model: model).padding(20).frame(width: 900).background(AppPalette.canvas),
                       name: "code-verification-ci", destination: destination)
            model.verifyCodeVerificationPreviewCleanup()
        }
        if let replay = ProcessInfo.processInfo.environment["BOXCOP_REVIEW_REPLAY"] {
            try model.configureCodeVerificationInterfacePreview(replayPath: replay, expectedOutcomes: ["diff_version_changed", "diff_version_observed", "unknown"])
            try render(CodeVerificationActivity(model: model).padding(20).frame(width: 900).background(AppPalette.canvas),
                       name: "code-review-version", destination: destination)
            model.verifyCodeVerificationPreviewCleanup()
            for clearLiveView in [false, true] {
                try model.configureCodeVerificationInterfacePreview(replayPath: replay, expectedOutcomes: ["diff_version_changed", "diff_version_observed", "unknown"])
                model.verifyCodeReviewInvalidationPreview(clearLiveView: clearLiveView)
            }
        }
        model.selectedPage = .protection
        model.configureActiveInterfacePreview(withFinding: true)
        try render(EndpointView(model: model), name: "home-active", size: NSSize(width: 1000, height: 1100), destination: destination)
        try render(ScrollView { EndpointDetails(model: model, section: .software).padding(20) }.background(Color(nsColor: .windowBackgroundColor)), name: "software-review", size: NSSize(width: 1000, height: 1100), destination: destination)
        model.configureActiveInterfacePreview(withFinding: false)
        try render(EndpointView(model: model), name: "home-active-clear", size: NSSize(width: 1000, height: 1100), destination: destination)
        let consoleData = try JSONSerialization.data(withJSONObject: [
            "text": "$ /opt/homebrew/bin/brew upgrade --formula ruby\n\n==> Upgrading ruby\n==> ./configure --prefix=/opt/homebrew/Cellar/ruby/4.0.9\nchecking for clang... clang\nchecking for OpenSSL... yes\n==> make\ncompiling array.c\ncompiling string.c\ncompiling vm.c\nlinking ruby\n\nIllustrative console preview; no updater was executed.",
            "status": "running", "updated_at": "Just now · illustrative preview", "truncated": false
        ])
        let consoleDecoder = JSONDecoder(); consoleDecoder.keyDecodingStrategy = .convertFromSnakeCase
        let consoleSnapshot = try consoleDecoder.decode(SoftwareConsoleSnapshot.self, from: consoleData)
        try render(SoftwareConsoleView(selection: .init(id: String(repeating: "0", count: 24), name: "ruby"), isActive: true, initialSnapshot: consoleSnapshot),
                   name: "software-console", size: NSSize(width: 850, height: 600), destination: destination)
        let network = NetworkConnectionsModel()
        network.snapshot = NetworkActivitySnapshot(events: [], observed: 0, dropped: 0, writeFailures: 0, lastFlow: nil, startedAt: Date(), retentionBytes: 8 * 1024 * 1024)
        var summary = NetworkActivitySummary()
        for (process, app, host, count) in [
            ("/Applications/Browser.app/Contents/MacOS/Browser Helper", "/Applications/Browser.app/Contents/MacOS/Browser", "example.org", 48),
            ("/Applications/Browser.app/Contents/MacOS/Browser", "/Applications/Browser.app/Contents/MacOS/Browser", "cdn.example.org", 12),
            ("/usr/bin/curl", "/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal", "api.example.org", 6)
        ] {
            var event = NetworkActivityEvent(remoteAddress: "192.0.2.1", remotePort: "443", localAddress: nil,
                localPort: nil, hostname: host, hostnameSource: "flow_url", url: nil, transport: "tcp",
                socketFamily: 2, socketType: 1, socketProtocol: 6, flowType: "socket")
            event.process.executable = process; event.responsibleApp.executable = app
            for _ in 0..<count { summary.record(event) }
        }
        network.snapshot?.summary = summary
        network.status = "Preview fixture · observing all apps"
        network.filterStatus = "Illustrative data only; no filter was activated."
        try render(NetworkConnectionsView(model: network, polling: false).padding(20).frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading).background(Color(nsColor: .windowBackgroundColor)), name: "outgoing-connections", size: NSSize(width: 900, height: 850), destination: destination)
        // Review before sending: production cards with synthetic evidence; nothing is requested from macOS.
        for allowed in [true, false] {
            model.configureReviewReminderPreview(notificationsAllowed: allowed)
            let suffix = allowed ? "" : "-notifications-off"
            precondition(model.pendingActivityReviewCount > 0, "Pending reviews must remain visible without notification permission")
            try render(HStack(spacing: 12) {
                EndpointIcon(model: model)
                Text(model.menuStatus)
            }.padding(16).background(AppPalette.canvas), name: "review-menu-bar" + suffix, destination: destination)
            try render(ReviewRemindersCard(model: model, expandDetails: true).padding(20).frame(width: 760, alignment: .topLeading)
                .background(AppPalette.canvas), name: "review-reminders" + suffix, destination: destination)
            try render(ReviewPolicyCard(model: model).padding(20).frame(width: 760, alignment: .topLeading)
                .background(AppPalette.canvas), name: "review-policy-enabled" + suffix, destination: destination)
            model.selectedPage = .activity
            try render(EndpointView(model: model), name: "activity-review" + suffix, size: NSSize(width: 1000, height: 1500), destination: destination)
        }
        model.selectedPage = .settings
        try render(EndpointView(model: model), name: "settings-review", size: NSSize(width: 1000, height: 1600), destination: destination)
        let review = ActionReviewContent(
            title: "Your screen may contain private information",
            explanation: "Sensitive content is visible. Close or hide it before sharing.",
            action: "Start screen sharing in Zoom", application: "Zoom",
            details: "BoxCop checks visible displays before supported share actions. Ongoing shares are not guarded.")
        try render(ActionReviewCard(content: review), name: "share-review", destination: destination)
        var restricted = review
        restricted.allowsProceed = false
        try render(ActionReviewCard(content: restricted), name: "share-review-no-override", destination: destination)
        try render(ActionReviewCard(content: review).environment(\.colorScheme, .dark), name: "share-review-dark", destination: destination)
        // Owned synthetic PDF: exercise the production snapshot loader and renderer, never a user's files.
        let pdf = PDFDocument()
        for index in 0..<3 {
            let size = NSSize(width: 612, height: 792)
            let image = NSImage(size: size, flipped: false) { rect in
                NSColor.white.setFill(); rect.fill()
                if index == 1 { return true } // Intentional blank page exercises the advisory.
                ("PDF attachment review" as NSString).draw(at: NSPoint(x: 48, y: 680),
                    withAttributes: [.font: NSFont.systemFont(ofSize: 28, weight: .semibold), .foregroundColor: NSColor.black])
                ("Page \(index + 1) of 3 · owned test fixture" as NSString).draw(at: NSPoint(x: 48, y: 630),
                    withAttributes: [.font: NSFont.systemFont(ofSize: 18), .foregroundColor: NSColor.darkGray])
                ("A local preview must match the exact selected file.\nDisplaying one page does not credit the other pages.\nNo email is sent by this fixture." as NSString).draw(in: NSRect(x: 48, y: 420, width: 510, height: 150),
                    withAttributes: [.font: NSFont.systemFont(ofSize: 16), .foregroundColor: NSColor.black])
                return true
            }
            guard let page = PDFPage(image: image) else { throw PDFPreviewError.unsupported }
            pdf.insert(page, at: index)
        }
        guard let data = pdf.dataRepresentation() else { throw PDFPreviewError.unsupported }
        let pdfURL = destination.appendingPathComponent("owned-pdf-review-fixture.pdf")
        try data.write(to: pdfURL)
        let snapshot = try LocalPDFSnapshot.read(pdfURL)
        guard let decoded = PDFDocument(data: snapshot.data), decoded.pageCount == 3 else { throw PDFPreviewError.unsupported }
        model.configurePDFReviewInterfacePreview(snapshot: snapshot, document: decoded)
        try render(PDFReviewActivity(model: model).groupBoxStyle(AppCardStyle()).padding(20)
            .frame(width: 900, height: 350, alignment: .topLeading).background(AppPalette.canvas),
            name: "pdf-review-no-preview", size: NSSize(width: 900, height: 350), destination: destination)
        if let preview = model.pdfPreview {
            precondition(preview.renderCheck?.potentiallyBlankPages == [1])
            try render(PDFPreviewSheet(model: model, preview: preview).frame(width: 850, height: 900).background(AppPalette.canvas),
                name: "pdf-review-preview", size: NSSize(width: 850, height: 900), destination: destination)
            // Offscreen rendering must not create user exposure evidence.
            precondition(model.pdfReviewBook.previews.isEmpty)
            // Seed illustrative partial state only for layout QA; this is not live viewing acceptance.
            model.recordPDFPage(previewID: preview.id, page: 0)
            try render(PDFReviewActivity(model: model).groupBoxStyle(AppCardStyle()).padding(20)
                .frame(width: 900, height: 350, alignment: .topLeading).background(AppPalette.canvas),
                name: "pdf-review-partial", size: NSSize(width: 900, height: 350), destination: destination)
        }
        let alertFixtures = [ReviewHeadsUpItem(category: .draft, itemID: "owned-fixture")]
        for dark in [false, true] {
            try render(ActionableAlertCard(items: alertFixtures, open: {}, dismiss: {})
                .environment(\.colorScheme, dark ? .dark : .light),
                name: "actionable-alert-panel" + (dark ? "-dark" : ""), destination: destination)
        }
        try render(ActionableAlertCard(items: alertFixtures + [ReviewHeadsUpItem(category: .pdf, itemID: "owned-pdf")], open: {}, dismiss: {}),
                   name: "review-heads-up-grouped", destination: destination)
        try model.configureEmailAlertInterfacePreview()
        try render(EmailReviewAlertsCard(model: model).padding(20).frame(width: 760).background(AppPalette.canvas),
                   name: "email-alerts", destination: destination)
        model.verifyEmailAlertPreviewLifecycle()
    }
    /// The real setup pages with fixture rows. Live permission and engine state are not exercised.
    private static func renderSetup(destination: URL) throws {
        func row(_ id: String, _ title: String, _ line: String, _ action: String? = nil, primary: Bool = false, lamp: SetupLamp = .off, highlighted: Bool = false, status: String? = nil) -> SetupRowModel {
            SetupRowModel(id: id, title: title, line: line, lamp: lamp, highlighted: highlighted, status: status,
                          actions: action.map { [SetupAction(title: $0, primary: primary, perform: {})] } ?? [])
        }
        let tools = ["Claude Code", "Codex", "Cursor"]
        let agents = row("agents", SetupCopy.agentsTitle, AgentSetupCopy.availableLine(tools: tools), SetupCopy.turnOn, primary: true)
        let agentsAdded = row("agents", SetupCopy.agentsTitle, AgentSetupCopy.addedLine(tools: tools), lamp: .added, status: SetupCopy.added)
        let pasteLead = row("paste", SetupCopy.pasteTitle, SetupCopy.pasteLine, SetupCopy.allowAccessibility, primary: true)
        let network = row("network", SetupCopy.networkTitle, SetupCopy.networkLine, SetupCopy.allowNetworkFilter)
        let networkOn = row("network", SetupCopy.networkTitle, SetupCopy.networkLine, lamp: .on, status: SetupCopy.on)
        let networkWait = row("network", SetupCopy.networkTitle, SetupCopy.approveInSettings, SetupCopy.openSettings, lamp: .waiting, highlighted: true)
        let networkDeclined = row("network", SetupCopy.networkTitle, SetupCopy.notGranted, SetupCopy.tryAgain, highlighted: true)
        let packages = row("packages", SetupCopy.packagesTitle, SetupCopy.packagesLine, SetupCopy.turnOn)
        let packagesOn = row("packages", SetupCopy.packagesTitle, SetupCopy.packagesOnLine, lamp: .on, status: SetupCopy.on)
        let screen = row("screen", SetupCopy.screenTitle, SetupCopy.screenLine, SetupCopy.allowScreenRecording)
        let approvalsLine = SetupCopy.approvalsLine
        let approvals = row("approvals", SetupCopy.approvalsTitle, approvalsLine, SetupCopy.turnOn)
        let approvalsLead = row("approvals", SetupCopy.approvalsTitle, approvalsLine, SetupCopy.turnOn, primary: true)
        let approvalsOn = row("approvals", SetupCopy.approvalsTitle, approvalsLine, lamp: .on, status: SetupCopy.on)
        func page(_ view: some View, _ name: String) throws {
            for mode in ["-dark", "-light"] {
                try render(view.foregroundStyle(AppPalette.ink).background(AppPalette.canvas).environment(\.colorScheme, mode == "-dark" ? .dark : .light),
                           name: "setup-" + name + mode, size: NSSize(width: 720, height: 580), destination: destination)
            }
        }
        try page(SetupWelcomePage(start: {}, later: {}), "1-welcome")
        /// Individuals see agent protection only; a team adds checks on the person's own actions.
        func list(_ agentRows: [SetupRowModel], human: [SetupRowModel]? = nil, primary: Bool = false) -> some View {
            var sections = [SetupSection(id: "agents", title: SetupCopy.agentSectionTitle, line: SetupCopy.agentSectionLine, rows: agentRows)]
            if let human { sections.append(SetupSection(id: "human", title: SetupCopy.humanSectionTitle, line: SetupCopy.humanSectionTeamLine, rows: human)) }
            return SetupProtectionsPage(sections: sections, showMore: human == nil ? {} : nil, privacyLine: human == nil ? SetupCopy.privacyLine : SetupCopy.teamPrivacyLine,
                                        continuePrimary: primary, learnMore: {}, proceed: {}).padding(.top, 16)
        }
        try page(list([agents, approvals, network, packages]), "2-list")
        try page(list([agentsAdded, approvalsLead, network, packages]), "3-agents-added")
        try page(list([agentsAdded, approvalsOn, networkWait, packages]), "4-network-waiting")
        try page(list([agentsAdded, approvalsOn, networkDeclined, packages]), "5-network-declined")
        try page(list([agentsAdded, approvalsOn, networkOn, packagesOn], primary: true), "6-nearly-done")
        try page(list([agentsAdded, approvalsOn, networkOn, packagesOn], human: [pasteLead, screen]), "6b-team")
        try page(SetupFinishPage(lit: true, done: {}), "7-running")
        try page(SetupFinishPage(lit: false, done: {}), "8-none-on")
        try render(SetupDataSheet(rows: SetupCopy.dataRows, done: {}).environment(\.colorScheme, .dark), name: "setup-9-your-data-dark", destination: destination)
        try render(SystemSettingsHelperView(text: SetupCopy.helperList).padding(20).environment(\.colorScheme, .dark), name: "setup-10-helper-dark", destination: destination)
    }
    private static func render<Content: View>(_ content: Content, name: String, size: NSSize? = nil, destination: URL) throws {
        let view = NSHostingView(rootView: content)
        view.appearance = NSAppearance(named: name.hasSuffix("-dark") ? .darkAqua : .aqua)
        let bounds = NSRect(origin: .zero, size: size ?? view.fittingSize)
        let window = NSWindow(contentRect: bounds, styleMask: [.borderless], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        window.contentView = view
        view.frame = bounds
        view.layoutSubtreeIfNeeded()
        guard let bitmap = view.bitmapImageRepForCachingDisplay(in: view.bounds) else { throw CocoaError(.fileWriteUnknown) }
        view.cacheDisplay(in: view.bounds, to: bitmap)
        guard let png = bitmap.representation(using: .png, properties: [:]) else { throw CocoaError(.fileWriteUnknown) }
        try png.write(to: destination.appendingPathComponent(name + ".png"))
        window.close()
    }
}
#endif
