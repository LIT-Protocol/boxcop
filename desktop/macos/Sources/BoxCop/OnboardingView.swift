#if os(macOS)
import SwiftUI
import AppKit
import BoxCopCore

struct LocalPrivacyCard: View {
    var isTeam = false
    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 8) {
                Label("Processed on your Mac", systemImage: "lock.shield")
                    .font(.headline)
                Text(isTeam
                     ? "BoxCop processes monitored content locally. Your team sees decisions and security activity, never your content."
                     : "BoxCop processes monitored content locally. Optional crash reports and feedback you choose to send go to BoxCop; no usage analytics are collected. Network history stays on this Mac; it can include process arguments and URLs.")
            }.frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

enum SetupCopy {
    static let welcomeTitle = "Welcome to BoxCop"
    static let welcomeLine = "BoxCop protects you as AI works for you on this computer."
    static let protectionsTitle = "Choose what to turn on"
    static let privacyLine = "Your data is processed on this Mac and never sent to BoxCop."
    static let teamPrivacyLine = "Your team sees decisions and security activity, never your content."

    static let agentSectionTitle = "Protect your AI agents"
    static let agentSectionLine = "Checks what agents run, send and download on this Mac."
    static let humanSectionTitle = "Checks on your own actions"
    static let humanSectionTeamLine = "Your team uses these to catch mistakes before they leave your Mac."
    static let humanSectionLine = "Mostly useful for teams. They need extra macOS permissions and run continuously."
    static let showHumanChecks = "Show checks on your own actions"

    static let agentsTitle = "AI agent protection"
    static let approvalsTitle = "Agent approvals"
    static let approvalsLine = "Asks you before agents send messages or spend over a limit you set."
    static let approvalsFailed = "BoxCop couldn’t save approval rules."
    static let agentsFailed = "BoxCop couldn’t change these settings."
    static let pasteTitle = "Paste protection"
    static let pasteLine = "Blocks commands from fake “verify you’re human” pages."
    static let networkTitle = "Network protection"
    static let networkLine = "Blocks known phishing and malware sites in every app."
    static let networkUnavailable = "Network protection isn’t responding."
    static let packagesTitle = "Package protection"
    static let packagesLine = "Routes npm and pnpm through BoxCop to block known malicious packages."
    static let packagesOnLine = "npm and pnpm installs need BoxCop running."
    static let screenTitle = "Screen protection"
    static let screenLine = "Covers your screen if BoxCop detects a password or key while you share it."
    static let screenWarnLine = "Warns you if BoxCop detects a password or key while you share your screen."

    static let turnOn = "Turn On"
    static let allowAccessibility = "Allow Accessibility…"
    static let allowNetworkFilter = "Allow Network Filter…"
    static let allowScreenRecording = "Allow Screen Recording…"
    static let openSettings = "Open Settings"
    static let tryAgain = "Try Again"
    static let restart = "Restart BoxCop"
    static let on = "On"
    static let added = "Added"
    static let teamLocked = "Set by your team"

    static let approveInSettings = "Turn on BoxCop in System Settings."
    static let approveFilter = "Click Allow, even if macOS highlights Don’t Allow."
    static let notGranted = "Permission not granted."
    static let helperList = "Turn on BoxCop in this list"
    static var helperNetwork: String {
        if #available(macOS 15, *) { return "Open Network Extensions, then turn on BoxCop" }
        return "Click Allow for BoxCop"
    }

    static let dataTitle = "Your data"
    static let dataProcessed = "Processed"
    static let dataStored = "Stored on this Mac"
    static let dataRows: [SetupDataRow] = [
        .init(name: "AI agents", processed: "Commands and file actions", stored: "Decisions, tool names and file paths"),
        .init(name: "Approvals", processed: "Agent commands that match your rules", stored: "Held requests and their command details"),
        .init(name: "Paste", processed: "Copied text and the destination app", stored: "Decisions and app names"),
        .init(name: "Network", processed: "Where each app connects", stored: "Connection history, URLs and command details"),
        .init(name: "Packages", processed: "Names and versions", stored: "Nothing"),
        .init(name: "Screen", processed: "On-screen text during sharing or recording", stored: "Decisions only"),
        .init(name: "Software", processed: "Installed apps and packages", stored: "Names, versions and findings"),
    ]
    static let activityRow = SetupDataRow(name: "Activity", processed: "Window titles, selected text, clicks, files, browser and agent events", stored: "Activity history and window captures")
    static let adapterRow = SetupDataRow(name: "Activity", processed: "Browser and agent events", stored: "Activity history")

    static let running = "BoxCop is running"
    static let runningLine = "Find it in your menu bar."
    static let noneOn = "No protections are on"
    static let noneOnLine = "Find BoxCop in your menu bar."
}

struct SetupDataRow: Identifiable {
    let name: String
    let processed: String
    let stored: String
    var id: String { name }
}

enum SetupLamp { case off, added, on, waiting }

struct SetupAction: Identifiable {
    let title: String
    var primary = false
    let perform: () -> Void
    var id: String { title }
}

struct SetupRowModel: Identifiable {
    let id: String
    let title: String
    var line: String
    var lamp = SetupLamp.off
    var highlighted = false
    var status: String?
    var actions: [SetupAction] = []
}

private struct SetupButtonStyle: ButtonStyle {
    var primary = false
    var compact = false
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: compact ? 13 : 14, weight: primary ? .semibold : .medium))
            .foregroundStyle(primary ? AppPalette.canvas : AppPalette.ink)
            .padding(.horizontal, compact ? 13 : 18)
            .frame(height: compact ? 30 : 34)
            .background(primary ? AppPalette.ink : compact ? AppPalette.ink.opacity(0.1) : .clear,
                        in: RoundedRectangle(cornerRadius: compact ? 8 : 10, style: .continuous))
            // An outline keeps an available button from reading as disabled.
            .overlay { if !primary && !compact { RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(AppPalette.ink.opacity(0.35)) } }
            .opacity(configuration.isPressed ? 0.75 : 1)
            .fixedSize()
    }
}

private struct SetupFooter<Content: View>: View {
    @ViewBuilder let content: () -> Content
    var body: some View {
        VStack(spacing: 0) {
            Divider()
            HStack { content() }.padding(.horizontal, 22).padding(.vertical, 14)
        }
    }
}

struct SetupWelcomePage: View {
    let start: () -> Void
    let later: () -> Void
    var body: some View {
        VStack(spacing: 0) {
            Spacer(minLength: 0)
            BoxCopMark().fill(AppPalette.ink).frame(width: 76, height: 76).accessibilityHidden(true)
            Text(SetupCopy.welcomeTitle).font(.system(size: 32, weight: .semibold)).tracking(-0.5).padding(.top, 34)
            Text(SetupCopy.welcomeLine).font(.system(size: 16)).foregroundStyle(AppPalette.quiet).padding(.top, 10)
            Spacer(minLength: 0)
            SetupFooter {
                Button("Set Up Later", action: later).buttonStyle(.plain).foregroundStyle(AppPalette.quiet)
                Spacer()
                Button("Get Started", action: start).buttonStyle(SetupButtonStyle(primary: true)).keyboardShortcut(.defaultAction)
            }
        }
    }
}

struct SetupRowsView: View {
    let rows: [SetupRowModel]
    var body: some View {
        VStack(spacing: 0) {
            ForEach(rows) { row in
                content(row)
                if row.id != rows.last?.id { Rectangle().fill(AppPalette.border).frame(height: 1).padding(.leading, 40) }
            }
        }
        .frame(width: 648)
        .background(AppPalette.raised, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
        .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).strokeBorder(AppPalette.border))
    }
    @ViewBuilder private func lamp(_ state: SetupLamp) -> some View {
        switch state {
        case .on: Circle().fill(AppPalette.light).frame(width: 9, height: 9).shadow(color: AppPalette.light.opacity(0.9), radius: 6)
        case .added: Circle().strokeBorder(AppPalette.light, lineWidth: 1.5).frame(width: 9, height: 9)
        case .off: Circle().fill(AppPalette.quiet.opacity(0.45)).frame(width: 9, height: 9)
        case .waiting: ProgressView().controlSize(.small).scaleEffect(0.75)
        }
    }
    private func content(_ row: SetupRowModel) -> some View {
        HStack(alignment: .center, spacing: 12) {
            lamp(row.lamp).frame(width: 14, height: 18)
            VStack(alignment: .leading, spacing: 3) {
                Text(row.title).font(.system(size: 15, weight: .semibold))
                Text(row.line).font(.system(size: 13)).foregroundStyle(AppPalette.quiet)
                    .lineSpacing(1.5).fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 10)
            if let status = row.status {
                Text(status).font(.system(size: 13.5, weight: .medium)).foregroundStyle(row.lamp == .on ? AppPalette.ink : AppPalette.quiet).fixedSize()
            }
            ForEach(row.actions) { action in
                Button(action.title, action: action.perform).buttonStyle(SetupButtonStyle(primary: action.primary, compact: true))
            }
        }
        .padding(.horizontal, 14).padding(.vertical, 12)
        .background(row.highlighted ? AppPalette.ink.opacity(0.04) : .clear)
    }
}

/// Agent protection is for everyone. Checks on the person's own actions are mainly team policy,
/// so individuals see them only on request.
struct SetupSection: Identifiable {
    let id: String
    let title: String
    let line: String
    var rows: [SetupRowModel]
}

struct SetupProtectionsPage: View {
    let sections: [SetupSection]
    var showMore: (() -> Void)?
    let privacyLine: String
    let continuePrimary: Bool
    let learnMore: () -> Void
    let proceed: () -> Void
    var body: some View {
        VStack(spacing: 0) {
            Text(SetupCopy.protectionsTitle).font(.system(size: 30, weight: .semibold)).tracking(-0.45).padding(.top, 12).padding(.bottom, 16)
            ScrollView {
                VStack(spacing: 18) {
                    ForEach(sections.filter { !$0.rows.isEmpty }) { section in
                        VStack(alignment: .leading, spacing: 8) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(section.title).font(.system(size: 13.5, weight: .semibold))
                                Text(section.line).font(.system(size: 12.5)).foregroundStyle(AppPalette.quiet)
                            }.padding(.leading, 4)
                            SetupRowsView(rows: section.rows)
                        }
                    }
                    if let showMore {
                        Button(action: showMore) { Label(SetupCopy.showHumanChecks, systemImage: "plus") }
                            .buttonStyle(SetupButtonStyle(compact: true))
                    }
                }.frame(maxWidth: .infinity).padding(.bottom, 4)
            }.scrollBounceBehavior(.basedOnSize)
            HStack(spacing: 6) {
                Text(privacyLine).foregroundStyle(AppPalette.quiet)
                Button("Learn More…", action: learnMore).buttonStyle(.plain).fontWeight(.medium)
            }.font(.system(size: 12.5)).padding(.top, 12).padding(.bottom, 4)
            Spacer(minLength: 0)
            SetupFooter {
                Spacer()
                if continuePrimary {
                    Button("Continue", action: proceed).buttonStyle(SetupButtonStyle(primary: true)).keyboardShortcut(.defaultAction)
                } else {
                    Button("Continue", action: proceed).buttonStyle(SetupButtonStyle())
                }
            }
        }
    }
}

struct SetupDataSheet: View {
    let rows: [SetupDataRow]
    var teamLine: String?
    let done: () -> Void
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(SetupCopy.dataTitle).font(.system(size: 22, weight: .semibold)).tracking(-0.3).padding(.bottom, teamLine == nil ? 20 : 6)
            if let teamLine { Text(teamLine).foregroundStyle(AppPalette.quiet).padding(.bottom, 20) }
            HStack(spacing: 14) {
                Text("").frame(width: 84, alignment: .leading)
                Text(SetupCopy.dataProcessed).frame(width: 250, alignment: .leading)
                Text(SetupCopy.dataStored).frame(maxWidth: .infinity, alignment: .leading)
            }.font(.system(size: 12.5, weight: .medium)).foregroundStyle(AppPalette.quiet).padding(.bottom, 8)
            ForEach(rows) { row in
                Divider()
                HStack(alignment: .top, spacing: 14) {
                    Text(row.name).font(.system(size: 13.5, weight: .semibold)).frame(width: 84, alignment: .leading)
                    Text(row.processed).frame(width: 250, alignment: .leading).fixedSize(horizontal: false, vertical: true)
                    Text(row.stored).frame(maxWidth: .infinity, alignment: .leading).fixedSize(horizontal: false, vertical: true)
                }.font(.system(size: 13)).padding(.vertical, 10)
            }
            Divider()
            HStack {
                Spacer()
                Button("Done", action: done).buttonStyle(SetupButtonStyle(primary: true)).keyboardShortcut(.defaultAction)
            }.padding(.top, 16)
        }
        .padding(26).frame(width: 640)
        .foregroundStyle(AppPalette.ink)
        .background(AppPalette.canvas)
    }
}

struct SetupFinishPage: View {
    let lit: Bool
    let done: () -> Void
    var body: some View {
        VStack(spacing: 0) {
            Spacer(minLength: 0)
            ZStack {
                if lit { Circle().fill(AppPalette.light).frame(width: 120, height: 120).blur(radius: 42).opacity(0.75) }
                BoxCopMark().fill(lit ? AppPalette.ink : AppPalette.quiet).frame(width: 76, height: 76).accessibilityHidden(true)
            }
            Text(lit ? SetupCopy.running : SetupCopy.noneOn).font(.system(size: 32, weight: .semibold)).tracking(-0.5).padding(.top, 34)
            Text(lit ? SetupCopy.runningLine : SetupCopy.noneOnLine).font(.system(size: 15.5)).foregroundStyle(AppPalette.quiet).padding(.top, 10)
            Spacer(minLength: 0)
            SetupFooter {
                Spacer()
                Button("Done", action: done).buttonStyle(SetupButtonStyle(primary: true)).keyboardShortcut(.defaultAction)
            }
        }
    }
}

/// Connects the setup pages to live macOS and engine state. A row is on only when it is really running.
struct OnboardingView: View {
    @ObservedObject var model: EndpointModel
    @ObservedObject private var network: NetworkConnectionsModel
    init(model: EndpointModel) {
        self.model = model; self.network = model.networkConnections
        // Starting from the real answer keeps a later change meaningful.
        _accessibility = State(initialValue: ShortcutTap.accessibilityGranted)
        _screen = State(initialValue: CGPreflightScreenCaptureAccess())
    }
    @StateObject private var helper = SystemSettingsHelper()
    @AppStorage("boxcop.setup.step") private var savedStep = 0
    @AppStorage("boxcop.setup.screen") private var screenWanted = false
    @State private var accessibility: Bool
    @State private var screen: Bool
    @State private var showingData = false
    @State private var package: PackageProtectionStatus?
    @State private var packageAttempted = false
    @State private var networkStalledSeconds = 0
    @State private var packagesPresent = false
    @State private var agentsAttempted = false
    @State private var waitedSeconds = 0
    @State private var restartError: String?
    @State private var approvals: ReviewSnapshot?
    @State private var approvalsBusy = false
    @State private var approvalsFailed = false
    @State private var approvalsRequested = false
    private var page: SetupPage { SetupPage(storedStep: savedStep) }

    var body: some View {
        Group {
            switch page {
            case .welcome:
                SetupWelcomePage(start: { savedStep = SetupPage.protections.rawValue }, later: { model.onboardingPresented = false })
            case .protections:
                SetupProtectionsPage(sections: sections, showMore: humanSectionVisible ? nil : { model.setHumanChecksShown(true) }, privacyLine: model.teamConnection.isTeam ? SetupCopy.teamPrivacyLine : SetupCopy.privacyLine,
                                     continuePrimary: actionableCount <= 1, learnMore: { showingData = true },
                                     proceed: { savedStep = SetupPage.finish.rawValue })
            case .finish:
                SetupFinishPage(lit: anyTurnedOn, done: { model.finishSetup() })
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .sheet(isPresented: $showingData) {
            SetupDataSheet(rows: dataRows, teamLine: model.teamConnection.isTeam ? SetupCopy.teamPrivacyLine : nil, done: { showingData = false })
        }
        .onAppear {
            if page == .finish { savedStep = SetupPage.protections.rawValue }
            packagesPresent = PackageManagerDetection.isPresent(home: NSHomeDirectory()) { FileManager.default.fileExists(atPath: $0) }
            // Screen Recording can relaunch the app before setup asks for Accessibility.
            if page == .protections && !model.setupComplete && screenRequested && nextScreenPermission == .accessibility { model.requestNextScreenPermission() }
        }
        .task {
            while !Task.isCancelled {
                accessibility = ShortcutTap.accessibilityGranted
                screen = CGPreflightScreenCaptureAccess()
                waitedSeconds = helperText == nil ? 0 : waitedSeconds + 1
                networkStalledSeconds = network.filterEnabled && !network.busy && !networkOn ? networkStalledSeconds + 1 : 0
                do { try await Task.sleep(nanoseconds: 1_000_000_000) } catch { return }
            }
        }
        .task { await loadApprovals(nil) }
        .task(id: model.running) {
            package = nil
            guard model.running else { return }
            while !Task.isCancelled {
                package = try? await model.packageProtection(.status)
                do { try await Task.sleep(nanoseconds: 1_000_000_000) } catch { return }
            }
        }
        // Once nothing else is needed the permission check starts the engine, and it honors Pause.
        .onChange(of: screen) { _, granted in if granted && screenRequested && nextScreenPermission != nil { model.requestNextScreenPermission() } }
        .onChange(of: helperText, initial: true) { _, text in
            if let text, page == .protections { helper.show(text) } else { helper.stop() }
        }
        .onDisappear { helper.stop() }
    }

    private var sections: [SetupSection] {
        var sections = [SetupSection(id: "agents", title: SetupCopy.agentSectionTitle, line: SetupCopy.agentSectionLine,
                                     rows: [agentRow, approvalsRow, networkRow, packageRow].compactMap { $0 })]
        if humanSectionVisible {
            sections.append(SetupSection(id: "human", title: SetupCopy.humanSectionTitle,
                                         line: model.teamConnection.isTeam ? SetupCopy.humanSectionTeamLine : SetupCopy.humanSectionLine,
                                         rows: [pasteRow, screenRow]))
        }
        // One suggested action at a time. The last one left is optional, so Continue takes over.
        let all = sections.flatMap(\.rows)
        if actionableCount(in: all) > 1, !all.contains(where: { $0.lamp == .waiting }) {
            outer: for s in sections.indices {
                if let lead = sections[s].rows.firstIndex(where: { !$0.actions.isEmpty && !$0.highlighted }) {
                    sections[s].rows[lead].actions[0].primary = true
                    break outer
                }
            }
        }
        return sections
    }
    private var rows: [SetupRowModel] { sections.flatMap(\.rows) }
    /// Paste and screen checks guard against the person's own mistakes. Individuals rarely need
    /// them, so they stay out of the way unless a team uses them, they are already on, or asked for.
    private var humanSectionVisible: Bool {
        model.showsHumanChecks || screenRequested
    }
    private func actionableCount(in rows: [SetupRowModel]) -> Int { rows.filter { !$0.actions.isEmpty }.count }
    private var actionableCount: Int { actionableCount(in: rows) }
    private var anyTurnedOn: Bool { rows.contains { $0.lamp == .on || $0.lamp == .added } }
    private var dataRows: [SetupDataRow] {
        SetupCopy.dataRows.filter { humanSectionVisible || !["Paste", "Screen"].contains($0.name) } + (model.activityCollection ? [SetupCopy.activityRow] : model.collectAdapters ? [SetupCopy.adapterRow] : [])
    }
    private var awaitingNetworkApproval: Bool {
        network.extensionState == .awaitingApproval || (network.setupPhase == .extensionApproval && network.extensionState != .installed)
    }
    private var waitingOnAccessibility: Bool { model.choices.monitoring && model.choices.guardShortcut && !accessibility }
    private var screenRequested: Bool { model.choices.monitoring && screenWanted && model.backgroundScreenEnabled }
    private var networkOn: Bool {
        let threat = network.snapshot?.threatProtection
        return network.setupReady && threat?.enabled == true && threat?.error == nil
    }
    private var engineIdle: Bool { !model.running && !model.starting }
    private var restartEngine: SetupAction { SetupAction(title: model.errorMessage == nil ? SetupCopy.turnOn : SetupCopy.tryAgain) { model.retry() } }
    private var nextScreenPermission: SetupPermission? { SetupRequirements.nextForScreen(accessibility: accessibility, screenRecording: screen) }
    private var settings: [String: Bool] { model.teamConnection.state.settings }
    private var helperText: String? {
        if awaitingNetworkApproval { return SetupCopy.helperNetwork }
        if waitingOnAccessibility || (screenRequested && nextScreenPermission != nil) { return SetupCopy.helperList }
        return nil
    }

    private var agentRow: SetupRowModel? {
        guard let status = AgentSetupCopy.status(of: model.agentSetupTools, attempted: agentsAttempted) else { return nil }
        var row = SetupRowModel(id: "agents", title: SetupCopy.agentsTitle, line: "")
        switch status {
        case let .available(tools):
            row.line = AgentSetupCopy.availableLine(tools: tools)
            row.actions = [SetupAction(title: SetupCopy.turnOn) { agentsAttempted = true; model.repairAgentHooks() }]
        case .failed:
            row.line = SetupCopy.agentsFailed; row.highlighted = true
            row.actions = [SetupAction(title: SetupCopy.tryAgain) { model.repairAgentHooks() }]
        case let .added(tools, codexAsks):
            row.line = AgentSetupCopy.addedLine(tools: tools, codexAsks: codexAsks); row.lamp = .added; row.status = SetupCopy.added
        case let .on(tools):
            row.line = AgentSetupCopy.availableLine(tools: tools); row.lamp = .on; row.status = SetupCopy.on
        }
        if model.agentRepairBusy { row.lamp = .waiting; row.status = nil; row.actions = [] }
        return row
    }

    private var approvalsRow: SetupRowModel {
        let policies = approvals?.policies
        var row = SetupRowModel(id: "approvals", title: SetupCopy.approvalsTitle,
                                line: SetupCopy.approvalsLine)
        let allOn = policies.map { $0.external && $0.spending } ?? false
        if approvalsBusy || (approvals == nil && !approvalsFailed) {
            row.lamp = .waiting
        } else if approvalsFailed || policies == nil {
            row.line = SetupCopy.approvalsFailed; row.highlighted = true
            row.actions = [SetupAction(title: SetupCopy.tryAgain) { Task { await loadApprovals(approvalsRequested ? true : nil) } }]
        } else if approvals?.managed_by != nil {
            row.lamp = allOn ? .on : .off; row.status = SetupCopy.teamLocked
        } else if allOn {
            row.lamp = .on; row.status = SetupCopy.on
        } else {
            row.actions = [SetupAction(title: SetupCopy.turnOn) { approvalsRequested = true; Task { await loadApprovals(true) } }]
        }
        return row
    }
    /// Reads the approval rules, or turns on both rules when `enable` is true. The approval service
    /// is a short-lived engine process, so nothing keeps running for this row.
    private func loadApprovals(_ enable: Bool?) async {
        guard !approvalsBusy else { return }
        approvalsBusy = true
        defer { approvalsBusy = false }
        var snapshot = approvals
        if snapshot?.policies == nil, let input = try? JSONSerialization.data(withJSONObject: ["op": "status"]) {
            snapshot = await ReviewService.request(input)
        }
        if enable == true, let current = snapshot?.policies, snapshot?.ok == true, snapshot?.managed_by == nil,
           let input = try? JSONSerialization.data(withJSONObject: ["op": "configure", "policies": [
               "external": true, "destructive": false, "spending": true,
               "threshold_cents": current.threshold_cents, "currency": current.currency]]) {
            snapshot = await ReviewService.request(input)
        }
        approvalsFailed = snapshot?.ok != true || snapshot?.policies == nil
        if !approvalsFailed { approvals = snapshot }
    }

    private var pasteRow: SetupRowModel {
        var row = SetupRowModel(id: "paste", title: SetupCopy.pasteTitle, line: SetupCopy.pasteLine)
        if settings["guard_shortcut"] == false {
            row.status = SetupCopy.teamLocked
        } else if model.running && model.guardActive {
            row.lamp = .on; row.status = SetupCopy.on
        } else if waitingOnAccessibility {
            waitInSettings(&row) { model.requestAccessibility() }
        } else if model.choices.monitoring && model.choices.guardShortcut {
            if model.running {
                row.line = model.guardStatus; row.highlighted = true
                row.actions = [SetupAction(title: SetupCopy.tryAgain) { model.retry() }]
            } else if engineIdle { row.actions = [restartEngine] } else { row.lamp = .waiting }
        } else {
            row.actions = [SetupAction(title: accessibility ? SetupCopy.turnOn : SetupCopy.allowAccessibility) { model.turnOnPasteProtection() }]
        }
        return row
    }

    private var networkRow: SetupRowModel? {
        guard model.releaseProfile.usesStandaloneNetworkProtection else { return nil }
        var row = SetupRowModel(id: "network", title: SetupCopy.networkTitle, line: SetupCopy.networkLine)
        if let issue = network.provisioning.setupIssue { row.line = issue; return row }
        let threat = network.snapshot?.threatProtection
        if networkOn {
            row.lamp = .on; row.status = SetupCopy.on
        } else if network.setupReady && threat?.enabled == false && threat?.error == nil {
            row.actions = [SetupAction(title: SetupCopy.turnOn) { network.setThreatBlocking(true) }]
        } else if network.setupPhase == .filterApproval {
            row.line = SetupCopy.approveFilter; row.lamp = .waiting; row.highlighted = true
        } else if awaitingNetworkApproval {
            waitInSettings(&row) { network.provisioning.openApprovalSettings() }
        } else if case let .failed(reason) = network.setupPhase {
            row.line = reason; row.highlighted = true
            row.actions = [SetupAction(title: SetupCopy.tryAgain) { network.enableFilter() }]
        } else if network.setupPhase == .declined {
            row.line = SetupCopy.notGranted; row.highlighted = true
            row.actions = [SetupAction(title: SetupCopy.tryAgain) { network.enableFilter() }]
        } else if !network.busy, let error = threat?.error {
            row.line = error; row.highlighted = true
            row.actions = [SetupAction(title: SetupCopy.tryAgain) { network.setThreatBlocking(true) }]
        } else if !network.busy && networkStalledSeconds >= 15 {
            row.line = SetupCopy.networkUnavailable; row.highlighted = true
            row.actions = [SetupAction(title: SetupCopy.tryAgain) { network.enableFilter() }]
        } else if network.busy || network.filterEnabled {
            row.lamp = .waiting
        } else {
            row.actions = [SetupAction(title: SetupCopy.allowNetworkFilter) { network.enableFilter() }]
        }
        return row
    }

    private var packageRow: SetupRowModel? {
        guard packagesPresent, package?.configured != false else { return nil }
        var row = SetupRowModel(id: "packages", title: SetupCopy.packagesTitle, line: SetupCopy.packagesLine)
        if package?.active == true {
            row.line = SetupCopy.packagesOnLine; row.lamp = .on; row.status = SetupCopy.on
        } else if model.packageSetupPending || package?.busy == true {
            if engineIdle { row.actions = [restartEngine] } else { row.lamp = .waiting }
        } else if packageAttempted || package?.routed == true {
            row.highlighted = true
            row.actions = [SetupAction(title: SetupCopy.tryAgain) { model.turnOnPackageProtection() }]
        } else {
            row.actions = [SetupAction(title: SetupCopy.turnOn) { packageAttempted = true; model.turnOnPackageProtection() }]
        }
        return row
    }

    private var screenRow: SetupRowModel {
        var row = SetupRowModel(id: "screen", title: SetupCopy.screenTitle, line: model.backgroundScreenFullScreen ? SetupCopy.screenLine : SetupCopy.screenWarnLine)
        if settings["background_screen"] == false {
            row.status = SetupCopy.teamLocked
        } else if screenRequested {
            if nextScreenPermission != nil {
                waitInSettings(&row) { model.requestNextScreenPermission() }
            } else if model.running {
                row.lamp = .on; row.status = SetupCopy.on
            } else if engineIdle { row.actions = [restartEngine] } else { row.lamp = .waiting }
        } else {
            let title = nextScreenPermission == .screenRecording ? SetupCopy.allowScreenRecording : nextScreenPermission == .accessibility ? SetupCopy.allowAccessibility : SetupCopy.turnOn
            row.actions = [SetupAction(title: title) { model.turnOnScreenProtection() }]
        }
        return row
    }

    private func waitInSettings(_ row: inout SetupRowModel, open: @escaping () -> Void) {
        row.line = restartError ?? SetupCopy.approveInSettings
        row.lamp = .waiting
        row.highlighted = true
        row.actions = [SetupAction(title: SetupCopy.openSettings, perform: open)]
        // macOS can keep reporting a stale answer until the app relaunches. Setup resumes on this page.
        if waitedSeconds >= 20 { row.actions.append(SetupAction(title: SetupCopy.restart) { restartForPermissionCheck() }) }
    }
    private func restartForPermissionCheck() {
        // Pass paths as arguments, never shell source. Wait for this process to exit
        // so Launch Services cannot merely reactivate the old permission state.
        let helper = Process()
        helper.executableURL = URL(fileURLWithPath: "/bin/sh")
        helper.arguments = ["-c", "i=0; while /bin/kill -0 \"$1\" 2>/dev/null; do i=$((i+1)); [ \"$i\" -lt 100 ] || exit 1; /bin/sleep 0.2; done; /usr/bin/open \"$2\"", "boxcop-restart", String(ProcessInfo.processInfo.processIdentifier), Bundle.main.bundleURL.path]
        do {
            try helper.run()
            NSApplication.shared.terminate(nil)
        } catch {
            restartError = "Could not restart automatically. Quit BoxCop from its menu bar menu, then reopen it."
        }
    }
}
#endif
