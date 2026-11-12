#if os(macOS)
import AppKit
import SwiftUI
import Combine
import ServiceManagement
import UserNotifications
import BoxCopCore

/// What this build can do at all. A missing prerequisite shows a layer as Unavailable, not Off.
struct Capabilities {
    var engine: Bool
    var networkExtension: Bool
    var networkPlacementIssue: String?
    var triageRuntime: Bool
    var version: String

    @MainActor static var current: Capabilities {
        let bundled = NetworkFilterControl.bundled
        let inApplications = Bundle.main.bundleURL.deletingLastPathComponent().path == "/Applications"
        return Capabilities(engine: EngineTools.available, networkExtension: bundled,
                            networkPlacementIssue: bundled && !inApplications ? "Move BoxCop to Applications, then open it there to set up outbound control." : nil,
                            triageRuntime: EngineTools.inferenceAvailable,
                            version: Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "development")
    }
}

/// One thing on Overview that is waiting for the person.
struct NeedsYouItem: Identifiable {
    enum Action { case reviewApproval(String), openNetworkSettings, repairHooks, openHealth, restartEngine, fix(LayerID) }
    let id: String
    let icon: String
    let text: String
    let button: String
    let action: Action
}

/// The whole app state: six layers, one event list, and the few settings around them.
@MainActor final class AppModel: ObservableObject {
    enum Page: String, CaseIterable, Identifiable {
        case overview, events, protections, health, settings
        var id: String { rawValue }
        var title: String { rawValue.prefix(1).uppercased() + rawValue.dropFirst() }
        var icon: String {
            switch self {
            case .overview: return "shield.lefthalf.filled"
            case .events: return "list.bullet.rectangle"
            case .protections: return "square.stack.3d.up"
            case .health: return "stethoscope"
            case .settings: return "gearshape"
            }
        }
    }
    enum EngineState: Equatable { case stopped, starting, running, restarting, failed(String) }

    // Navigation
    @Published var page: Page = .overview
    @Published var onboardingPresented = false
    @Published var selectedEventID: String?
    @Published var eventFilter = EventFilter()
    @Published var testSheet: LayerID?

    // Layers
    @Published var capabilities: Capabilities
    @Published var paused: Bool
    @Published var wanted: Set<LayerID>
    @Published var engineState = EngineState.stopped
    @Published var packageStatus: PackageProtectionStatus?
    @Published var scriptStatus: ScriptProtectionStatus?
    @Published var securityEvents: [SecurityEvent] = []
    @Published var agents: [HostAgents.Connection] = []
    @Published var agentsLoaded = false
    @Published var busyLayers = Set<LayerID>()
    @Published var layerMessages: [LayerID: String] = [:]
    let network = NetworkConnectionsModel()
    let approvals = AgentApprovalWatcher()

    // Approval inbox
    @Published var reviewPolicies = ReviewPolicies()
    @Published var reviewRequests: [ReviewRequest] = []
    @Published var reviewSummaries: [String: ReviewSummary] = [:]
    @Published var reviewLoaded = false
    @Published var reviewError: String?
    @Published var reviewBusy = false

    // Machine health
    @Published var inventory: SoftwareInventoryReport?
    @Published var inventoryBusy = false
    @Published var inventoryCheckedAt: Date?
    @Published var inventoryError: String?
    @Published var ignoredFindings = Set<SoftwareFindingIdentity>()
    @Published var findingFirstSeen: [String: Date] = [:]
    @Published var selectedFixes = Set<String>() { didSet { if oldValue != selectedFixes { fixPlans = [] } } }
    @Published var fixPlans: [SoftwareFixPlan] = []
    @Published var fixResults: [SoftwareFixResult] = []
    @Published var fixStatus = ""
    @Published var fixBusy = false
    @Published var activeFix: SoftwareConsoleSelection?

    // Smart triage
    @Published var judgment: WorkflowJudgmentStatus?
    @Published var triageMessage = ""
    @Published var explanations: [String: String] = [:]

    // Settings
    @Published var notificationsEnabled: Bool
    @Published var notificationMessage = ""
    @Published var loginEnabled = false
    @Published var loginMessage = ""
    @Published var removalMessage = ""

    let preview: Bool
    weak var updater: AppUpdater?
    private let defaults: UserDefaults
    private var window: NSWindow?
    private var client: EngineClient?
    private var epoch: UInt64 = 0
    private var recovery = MonitoringRecovery()
    private var timer: Task<Void, Never>?
    private var ticking = false
    private var tickCount = 0
    private var observers = Set<AnyCancellable>()
    private var knownFixes = Set<String>()
    private var announcedEvents: Set<String>?
    private var announcedScriptBlocks: Set<String>?
    private var announcedNetworkBlocks: Set<String>?
    private let scriptNotice = InterventionNotice()
    private let settingsHelper = SystemSettingsHelper()
    private let reviewer = WorkflowReviewClient()
    private var timeline = WorkflowTimeline(capacity: 1000)
    private var timelineIDs: [UUID: String] = [:]
    private var timelineSeen = Set<String>()
    private var networkImporter = NetworkWorkflowImporter()
    private var journal: WorkflowJournal?
    private var packageEnable: Task<Void, Never>?

    init(defaults: UserDefaults = .standard, preview: Bool = false, capabilities: Capabilities? = nil) {
        self.defaults = defaults
        self.preview = preview
        self.capabilities = capabilities ?? .current
        paused = defaults.bool(forKey: "boxcop.paused")
        wanted = Set(LayerID.allCases.filter { defaults.bool(forKey: Self.key($0)) })
        notificationsEnabled = defaults.object(forKey: "boxcop.notifications") as? Bool ?? true
        ignoredFindings = IgnoredSoftwareFindings.load(from: defaults)
        findingFirstSeen = (defaults.dictionary(forKey: "boxcop.inventory.firstSeen") as? [String: Double] ?? [:]).mapValues(Date.init(timeIntervalSince1970:))
        // Republish layer 3 and approval changes so views that read the model redraw.
        network.objectWillChange.sink { [weak self] _ in self?.objectWillChange.send() }.store(in: &observers)
        approvals.objectWillChange.sink { [weak self] _ in self?.objectWillChange.send() }.store(in: &observers)
    }

    nonisolated static func key(_ layer: LayerID) -> String { "boxcop.layer." + layer.rawValue }
    var setupComplete: Bool { defaults.bool(forKey: "boxcop.setup.complete") }
    func wants(_ layer: LayerID) -> Bool { wanted.contains(layer) }
    private func setWanted(_ layer: LayerID, _ value: Bool) {
        if value { wanted.insert(layer) } else { wanted.remove(layer) }
        defaults.set(value, forKey: Self.key(layer))
    }
    var triageEnabled: Bool { wants(.smartTriage) }

    // MARK: Status

    var layers: [LayerStatus] {
        let running = engineState == .running
        let threat = network.snapshot?.threatProtection
        let extensionState: LayerRules.ExtensionState
        switch network.extensionState {
        case .installed: extensionState = .installed
        case .awaitingApproval: extensionState = .awaitingApproval
        case .upgradeRequired: extensionState = .upgradeRequired
        case .missing: extensionState = .missing
        default: extensionState = network.setupPhase == .extensionApproval ? .awaitingApproval : .unknown
        }
        let agentLayer: LayerStatus = agentsLoaded || !capabilities.engine
            ? LayerRules.agentChecks(engineAvailable: capabilities.engine, wanted: wants(.agentChecks), agents: agents.map { ($0.id, $0.health) })
            : LayerStatus(.agentChecks, wants(.agentChecks) ? .needsSetup : .off, "Checking agent hooks.")
        let setup = judgment?.setup
        let all = [
            LayerRules.installGate(engineAvailable: capabilities.engine, engineRunning: running, wanted: wants(.installGate),
                                   configured: packageStatus?.configured, routed: packageStatus?.routed ?? false, listening: packageStatus?.active ?? false,
                                   stale: packageStatus?.stale ?? false, feedDate: packageStatus?.generatedAt),
            LayerRules.containment(engineAvailable: capabilities.engine, engineRunning: running, wanted: wants(.containment),
                                   routed: scriptStatus?.routed ?? false, listening: scriptStatus?.active ?? false),
            LayerRules.outboundControl(bundled: capabilities.networkExtension, placementIssue: capabilities.networkPlacementIssue,
                                       wanted: wants(.outboundControl), extensionState: extensionState, filterEnabled: network.filterEnabled,
                                       reachable: network.setupReady, threatBlocking: threat?.enabled ?? false, threatError: threat?.error, hosts: threat?.domainCount),
            agentLayer,
            LayerRules.machineHealth(engineAvailable: capabilities.engine, wanted: wants(.machineHealth), hasReport: inventory != nil, findings: activeFindings.count),
            LayerRules.smartTriage(engineAvailable: capabilities.engine, runtimeAvailable: capabilities.triageRuntime, wanted: triageEnabled,
                                   setupState: setup?.state ?? (judgment == nil ? nil : "ready"), fraction: setup?.fraction ?? 0)
        ]
        guard paused else { return all }
        // Pausing unroutes installs and scripts and stops threat blocking. Agent hooks stay connected.
        return all.map { layer in
            [.installGate, .containment, .outboundControl].contains(layer.id) && layer.state != .unavailable
                ? LayerStatus(layer.id, .off, "Paused. Resume protection to turn this back on.") : layer
        }
    }
    /// Whether a Fix button would do anything. A model download only needs time.
    func fixable(_ layer: LayerStatus) -> Bool {
        layer.id != .smartTriage || judgment?.setup?.state == "error"
    }
    func layer(_ id: LayerID) -> LayerStatus { layers.first { $0.id == id }! }
    var summary: ProtectionSummary { ProtectionSummary(layers: layers, paused: paused) }

    // MARK: Events

    var approvalItems: [ApprovalItem] {
        var items = reviewRequests.map(\.item)
        let known = Set(items.map(\.id))
        // The watcher sees a new request before the inbox has been read.
        for pending in approvals.pending where !known.contains(pending.id) {
            items.append(ApprovalItem(id: pending.id, application: pending.application, reasons: pending.reasons, command: "",
                                      status: "pending", created: Date(timeIntervalSince1970: pending.expires - 600), expires: Date(timeIntervalSince1970: pending.expires)))
        }
        return items
    }
    var findingItems: [FindingItem] {
        let checked = inventoryCheckedAt ?? Date()
        return activeFindings.map { item in
            let advisory = item.advisories.first
            // A finding keeps the time it was first seen, so each check does not move it to the top.
            let checked = findingFirstSeen[item.id + "|" + item.version] ?? checked
            return FindingItem(id: item.id, name: item.name, version: item.version, path: item.path, advisories: item.advisories.map(\.id),
                               guidance: advisory?.remediation ?? "", fixedVersions: advisory?.fixedVersions ?? "", checkedAt: checked)
        }
    }
    var events: [FeedEvent] {
        var notes = explanations
        for (id, summary) in reviewSummaries { if let text = summary.summary, !text.isEmpty { notes["approval:" + id] = text } }
        return EventFeed.merge(security: securityEvents, network: network.snapshot?.events ?? [], approvals: approvalItems,
                               findings: wants(.machineHealth) ? findingItems : [], explanations: triageEnabled ? notes : [:])
    }
    var pendingApprovalCount: Int { events.filter(\.pinned).count }
    var attentionNeeded: Bool { pendingApprovalCount > 0 || layers.contains { $0.state == .needsSetup } }

    var needsYou: [NeedsYouItem] {
        var items: [NeedsYouItem] = []
        for event in events where event.pinned {
            let command = event.subject.isEmpty ? "" : ": " + event.subject
            items.append(.init(id: event.id, icon: "hand.raised.fill", text: "\(event.source) is waiting for your approval\(command)", button: "Review", action: .reviewApproval(event.id)))
        }
        if case let .failed(reason) = engineState {
            items.append(.init(id: "engine", icon: "exclamationmark.triangle.fill", text: "BoxCop's engine stopped. \(reason)", button: "Restart", action: .restartEngine))
        }
        for layer in layers where layer.state == .needsSetup {
            switch layer.id {
            case .outboundControl where network.extensionState == .awaitingApproval || network.setupPhase == .extensionApproval:
                items.append(.init(id: "network", icon: "network", text: "macOS is waiting for you to approve the network extension.", button: "Open Settings", action: .openNetworkSettings))
            case .agentChecks where agentsLoaded:
                items.append(.init(id: "hooks", icon: "terminal", text: layer.detail.replacingOccurrences(of: " Choose Fix.", with: "").replacingOccurrences(of: " Choose Fix to connect.", with: ""), button: "Repair", action: .repairHooks))
            case .outboundControl, .installGate, .containment:
                guard !busyLayers.contains(layer.id), engineState != .starting else { continue }
                items.append(.init(id: layer.id.rawValue, icon: "wrench.and.screwdriver", text: "\(layer.id.name): \(layer.detail)", button: "Fix", action: .fix(layer.id)))
            default: break
            }
        }
        let findings = activeFindings.count
        if wants(.machineHealth), findings > 0 {
            items.append(.init(id: "findings", icon: "stethoscope", text: "\(findings) software finding\(findings == 1 ? "" : "s") to review.", button: "Open Health", action: .openHealth))
        }
        return items
    }
    func perform(_ action: NeedsYouItem.Action) {
        switch action {
        case let .reviewApproval(id): showEvent(id)
        case .openNetworkSettings: network.provisioning.openApprovalSettings()
        case .repairHooks: changeHooks(.install)
        case .openHealth: page = .health
        case .restartEngine: restartEngine()
        case let .fix(layer): fixLayer(layer)
        }
    }
    func showEvent(_ id: String) {
        eventFilter = EventFilter(); selectedEventID = id; page = .events
        showWindow()
    }

    // MARK: Lifecycle

    func activate() {
        guard !preview else { return }
        onboardingPresented = !setupComplete
        refreshLogin()
        approvals.onNew = { [weak self] in self?.notifyApproval($0) }
        approvals.onGone = { ids in
            let identifiers = ids.map(AgentApprovalCopy.notificationIdentifier)
            UNUserNotificationCenter.current().removeDeliveredNotifications(withIdentifiers: identifiers)
        }
        approvals.onChange = { [weak self] in self?.refreshReview() }
        approvals.explainEnabled = triageEnabled
        approvals.start()
        inventory = SoftwareInventory.cached()
        if setupComplete { startEngine() }
        Task { await network.upgradeInstalledExtension() }
        refreshReview()
        timer = Task { [weak self] in
            while !Task.isCancelled {
                await self?.tick()
                do { try await Task.sleep(nanoseconds: 3_000_000_000) } catch { return }
            }
        }
        if onboardingPresented { showWindow() }
    }

    /// One timer drives every poll: engine status and events every 3 s, the network extension every 6 s,
    /// agent hooks every 15 s and the software check every 300 s.
    private func tick() async {
        guard !ticking else { return }
        ticking = true; defer { ticking = false; tickCount += 1 }
        if engineState == .running { await refreshEngine() }
        if tickCount % 2 == 0 {
            await network.refresh()
            announceNetworkBlocks()
            updateSettingsHelper()
        }
        if tickCount % 5 == 0, capabilities.engine { await refreshAgents() }
        if tickCount % 100 == 0, setupComplete, wants(.machineHealth) { await refreshInventory() }
        await runTriage()
    }

    func stopAndWait() async {
        timer?.cancel(); approvals.stop(); reviewer.stop(); settingsHelper.stop()
        epoch &+= 1
        let engine = client; client = nil
        await engine?.stop()
        await journal?.flush()
    }

    // MARK: Engine

    private func startEngine() {
        guard !preview, capabilities.engine, client == nil else { return }
        epoch &+= 1; let expected = epoch
        let engine = EngineClient(requestTimeout: 5, onFailure: { [weak self] failure in
            Task { @MainActor [weak self] in
                guard let self, self.epoch == expected else { return }
                self.engineFailed(failure)
            }
        })
        client = engine
        engineState = .starting
        Task { [weak self] in
            do {
                guard let configuration = EngineTools.configuration() else { throw EngineFailure.invalidConfiguration }
                try FileManager.default.createDirectory(at: configuration.dataDirectory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
                try await engine.start(configuration: configuration)
                guard let self, self.epoch == expected else { await engine.stop(); return }
                self.engineState = .running
                self.recovery.started(at: ProcessInfo.processInfo.systemUptime)
                await self.refreshEngine()
                await self.reconcile()
            } catch {
                guard let self, self.epoch == expected else { return }
                self.engineFailed((error as? EngineFailure) ?? .launchFailed)
            }
        }
    }
    private func engineFailed(_ failure: EngineFailure) {
        let engine = client; client = nil
        epoch &+= 1; let expected = epoch
        packageStatus = nil; scriptStatus = nil
        NSLog("BoxCop engine failure: %@", failure.rawValue)
        guard let delay = recovery.nextDelay(for: failure, at: ProcessInfo.processInfo.systemUptime) else {
            engineState = .failed(failure.description)
            Task { await engine?.stop() }
            return
        }
        engineState = .restarting
        Task { [weak self] in
            await engine?.stop()
            try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
            guard let self, self.epoch == expected else { return }
            self.startEngine()
        }
    }
    func restartEngine() {
        recovery = MonitoringRecovery()
        let engine = client; client = nil; epoch &+= 1
        engineState = .stopped
        Task { await engine?.stop(); startEngine() }
    }
    private func request(_ command: EngineCommand) async -> EngineResult? {
        guard let client, engineState == .running else { return nil }
        return try? await client.request(command)
    }
    private func refreshEngine() async {
        if case let .packageProtection(status)? = await request(.packageProtection(.status)) { packageStatus = status }
        if case let .scriptProtection(status)? = await request(.scriptProtection(.status)) {
            scriptStatus = status
            announceScriptBlocks(status.blocked)
        }
        if case let .securityEvents(events)? = await request(.securityEvents(200)) {
            securityEvents = events
            announceSecurityEvents(events)
        }
    }
    /// Turns routing back on for layers the person chose, after an engine start or a resume.
    private func reconcile() async {
        guard !paused, engineState == .running else { return }
        if wants(.installGate), let status = packageStatus, status.configured, !status.routed { enablePackages() }
        if wants(.containment), scriptStatus?.routed == false {
            if case let .scriptProtection(status)? = await request(.scriptProtection(.enable)) { scriptStatus = status }
        }
    }
    /// The engine drops an enable that arrives during its startup check, so wait until it is not busy.
    private func enablePackages() {
        guard packageEnable == nil else { return }
        busyLayers.insert(.installGate)
        packageEnable = Task { [weak self] in
            defer { self?.packageEnable = nil; self?.busyLayers.remove(.installGate) }
            for _ in 0..<60 {
                guard let self, self.wants(.installGate), !self.paused,
                      case let .packageProtection(status)? = await self.request(.packageProtection(.status)) else { return }
                if !status.busy {
                    if case let .packageProtection(enabled)? = await self.request(.packageProtection(.enable)) { self.packageStatus = enabled }
                    return
                }
                try? await Task.sleep(nanoseconds: 250_000_000)
            }
        }
    }

    // MARK: Layer switches

    func setLayer(_ id: LayerID, on: Bool) {
        guard !preview else { return }
        setWanted(id, on)
        layerMessages[id] = nil
        if on { requestNotificationsOnce() }
        switch id {
        case .installGate:
            if on {
                if engineState == .running { enablePackages() } else { startEngine() }
            } else {
                packageEnable?.cancel()
                Task { if case let .packageProtection(status)? = await request(.packageProtection(.disable)) { packageStatus = status } }
            }
        case .containment:
            if engineState != .running, on { startEngine(); return }
            Task { if case let .scriptProtection(status)? = await request(.scriptProtection(on ? .enable : .disable)) { scriptStatus = status } }
        case .outboundControl:
            if on { network.enable() } else { network.disable() }
        case .agentChecks:
            changeHooks(on ? .install : .remove)
        case .machineHealth:
            if on { Task { await refreshInventory() } }
        case .smartTriage:
            approvals.explainEnabled = on
            if !on { reviewer.stop(); judgment = nil; triageMessage = ""; explanations = [:] }
        }
    }
    func fixLayer(_ id: LayerID) {
        guard !preview else { return }
        switch id {
        case .installGate, .containment:
            if engineState == .running { Task { await reconcile() } } else { restartEngine() }
        case .outboundControl:
            setWanted(.outboundControl, true)
            if network.extensionState == .awaitingApproval { network.provisioning.openApprovalSettings() }
            else if network.setupReady { network.setThreatBlocking(true) }
            else { network.enable() }
        case .agentChecks: setWanted(.agentChecks, true); changeHooks(.install)
        case .machineHealth: Task { await refreshInventory() }
        case .smartTriage: reviewer.stop(); judgment = nil
        }
    }

    func pause() {
        guard !paused else { return }
        paused = true; defaults.set(true, forKey: "boxcop.paused")
        packageEnable?.cancel()
        Task {
            if case let .packageProtection(status)? = await request(.packageProtection(.disable)) { packageStatus = status }
            if case let .scriptProtection(status)? = await request(.scriptProtection(.disable)) { scriptStatus = status }
            if network.snapshot?.threatProtection?.enabled == true {
                defaults.set(true, forKey: "boxcop.paused.threatBlocking")
                _ = await NetworkServiceClient.send("network-threat-blocking-off")
                await network.refresh()
            }
        }
    }
    func resume() {
        guard paused else { return }
        paused = false; defaults.set(false, forKey: "boxcop.paused")
        Task {
            if engineState == .running { await reconcile() } else { startEngine() }
            if defaults.bool(forKey: "boxcop.paused.threatBlocking") {
                defaults.set(false, forKey: "boxcop.paused.threatBlocking")
                _ = await NetworkServiceClient.send("network-threat-blocking-on")
                await network.refresh()
            }
        }
    }

    // MARK: Containment

    func allowScriptDestination(package: String, host: String) {
        Task {
            if case let .scriptProtection(status)? = await request(.scriptProtection(.allow, package: package, host: host)) {
                scriptStatus = status
                layerMessages[.containment] = "\(package) may now reach \(host). Run the install again."
            } else { layerMessages[.containment] = "The exception could not be saved because the engine is not running." }
        }
    }
    func revokeScriptDestination(_ exception: ScriptDestinationException) {
        Task {
            if case let .scriptProtection(status)? = await request(.scriptProtection(.revoke, package: exception.package, host: exception.host)) { scriptStatus = status }
        }
    }
    private func announceScriptBlocks(_ blocked: [BlockedScriptConnection]) {
        // The first read after launch is history, not news.
        guard let seen = announcedScriptBlocks else { announcedScriptBlocks = Set(blocked.map(\.id)); return }
        guard let item = blocked.first(where: { !seen.contains($0.id) }) else { return }
        announcedScriptBlocks = seen.union(blocked.map(\.id))
        let allow: (() -> Void)? = item.package.map { package in
            { [weak self] in self?.scriptNotice.dismiss(); self?.allowScriptDestination(package: package, host: item.host) }
        }
        scriptNotice.show(title: "Install script blocked from the network",
                          message: item.message + (allow == nil ? "" : " Allowing applies to this package and host only. Run the install again afterwards."),
                          actionTitle: "Allow for this package", allow: allow,
                          details: { [weak self] in self?.page = .events; self?.eventFilter = EventFilter(kind: .blocked, layer: .containment); self?.showWindow() })
    }

    // MARK: Agent hooks and approvals

    func refreshAgents() async {
        guard !preview, !busyLayers.contains(.agentChecks) else { return }
        if let snapshot = await HostAgents.refresh(.status) { agents = snapshot.connections; agentsLoaded = true }
    }
    func changeHooks(_ mode: HostAgents.Mode) {
        guard !preview, !busyLayers.contains(.agentChecks) else { return }
        busyLayers.insert(.agentChecks)
        Task {
            let snapshot = await HostAgents.refresh(mode)
            busyLayers.remove(.agentChecks)
            if let snapshot { agents = snapshot.connections; agentsLoaded = true; layerMessages[.agentChecks] = nil }
            else { layerMessages[.agentChecks] = "The hooks could not be changed because the engine did not answer." }
        }
    }
    func refreshReview() { review(["op": "status"]) }
    func resolve(approvalID: String, approve: Bool) { review(["op": "resolve", "id": approvalID, "approve": approve]) }
    func savePolicies(_ policies: ReviewPolicies) {
        if policies.external || policies.spending { requestNotificationsOnce() }
        reviewPolicies = policies
        review(["op": "configure", "policies": ["external": policies.external, "destructive": false, "spending": policies.spending,
                                                 "threshold_cents": policies.threshold_cents, "currency": policies.currency]])
    }
    private var reviewQueue: [[String: Any]] = []
    private func review(_ payload: [String: Any]) {
        guard !preview, capabilities.engine else { return }
        if reviewBusy {
            // A status read is replaceable; an answer or a rule change is not.
            if payload["op"] as? String != "status" || reviewQueue.isEmpty { reviewQueue.append(payload) }
            return
        }
        reviewBusy = true
        Task {
            let result = await ReviewService.request(payload)
            reviewBusy = false
            if let result, result.ok, let policies = result.policies, let requests = result.requests {
                reviewError = nil; reviewLoaded = true
                reviewPolicies = policies; reviewRequests = requests; reviewSummaries = result.summaries ?? [:]
            } else if payload["op"] as? String != "status" {
                reviewError = result?.error ?? "The approval inbox did not answer. Try again."
            }
            if payload["op"] as? String == "resolve" { approvals.touch() }
            if !reviewQueue.isEmpty { review(reviewQueue.removeFirst()) }
        }
    }

    // MARK: Machine health

    var activeFindings: [SoftwareObservation] {
        (inventory?.findings ?? []).compactMap { observation in
            var active = observation
            active.advisories = observation.advisories.filter { $0.needsReview && !ignoredFindings.contains(observation.identity(for: $0)) }
            return active.advisories.isEmpty ? nil : active
        }
    }
    var activeFixItems: [SoftwareFixItem] {
        let activeIDs = Set(activeFindings.map(\.id))
        let ignoredIDs = Set((inventory?.findings ?? []).map(\.id)).subtracting(activeIDs)
        // Keep actions without matching findings; only an explicit dismissal hides an action.
        return (inventory?.remediationItems ?? []).filter { $0.observationIds.isEmpty || !$0.observationIds.allSatisfy(ignoredIDs.contains) }
    }
    func ignoreFinding(_ observation: SoftwareObservation) {
        guard !inventoryBusy, !fixBusy else { return }
        ignoredFindings.formUnion(observation.advisories.filter(\.needsReview).map { observation.identity(for: $0) })
        saveIgnoredFindings()
    }
    func restoreFinding(_ identity: SoftwareFindingIdentity) {
        guard !inventoryBusy, !fixBusy else { return }
        ignoredFindings.remove(identity)
        saveIgnoredFindings()
    }
    private func saveIgnoredFindings() {
        IgnoredSoftwareFindings.save(ignoredFindings, to: defaults)
        selectedFixes.formIntersection(Set(activeFixItems.filter(\.automatic).map(\.id)))
        fixPlans = []
    }
    func refreshInventory() async {
        guard !preview, capabilities.engine, !inventoryBusy, !fixBusy else { return }
        inventoryBusy = true
        defer { inventoryBusy = false }
        guard let report = await SoftwareInventory.refresh() else {
            inventoryError = "The software check did not finish. Results below are from the previous check."
            return
        }
        inventoryError = nil
        inventory = report
        if fixPlans.isEmpty { fixStatus = "" }
        fixResults = report.remediationResults ?? fixResults
        let available = Set(activeFixItems.filter(\.automatic).map(\.id))
        selectedFixes.formIntersection(available)
        selectedFixes.formUnion(available.subtracting(knownFixes))
        knownFixes = available
        inventoryCheckedAt = Date()
        let keys = Set(report.findings.map { $0.id + "|" + $0.version })
        findingFirstSeen = findingFirstSeen.filter { keys.contains($0.key) }
        for key in keys where findingFirstSeen[key] == nil { findingFirstSeen[key] = Date() }
        defaults.set(findingFirstSeen.mapValues(\.timeIntervalSince1970), forKey: "boxcop.inventory.firstSeen")
        await notifyFindings(report)
    }
    func cancelFixPlan() { fixPlans = []; fixStatus = "" }
    func prepareFixes() async {
        guard !fixBusy, !inventoryBusy, !selectedFixes.isEmpty else { return }
        fixBusy = true
        fixPlans = []
        let selected = selectedFixes.sorted()
        var plans: [SoftwareFixPlan] = []
        // One request per selection keeps progress visible and bounds each request.
        for (index, id) in selected.enumerated() {
            fixStatus = "Preparing update \(index + 1) of \(selected.count)."
            if let response = await SoftwareRemediation.request("prepare", payload: ["ids": [id]]), response.error == nil {
                plans.append(contentsOf: response.plans)
                fixResults = response.results
            }
        }
        let status = plans.count == selected.count ? "Review the plan, then apply it."
            : "Some selections could not be prepared or changed since the check. Check again and retry those."
        fixBusy = false
        // Refresh classifications without clearing the reviewed plan.
        await refreshInventory()
        fixPlans = plans; fixStatus = status
    }
    func applyFixes() async {
        guard !fixBusy, !inventoryBusy else { return }
        let plans = fixPlans.filter(\.ready)
        guard !plans.isEmpty else { return }
        fixBusy = true
        fixPlans = []
        for (index, plan) in plans.enumerated() {
            activeFix = SoftwareConsoleSelection(id: plan.id, name: plan.name)
            fixResults.removeAll { $0.id == plan.id }
            fixResults.insert(SoftwareFixResult(id: plan.id, status: "in_progress", detail: "Applying the approved plan. Open the live console for progress.", name: plan.name), at: 0)
            fixStatus = "Applying \(plan.name) (\(index + 1) of \(plans.count)). Source builds can take a while."
            let response = await SoftwareRemediation.request("apply", payload: ["id": plan.id, "fingerprint": plan.fingerprint])
            let result = response?.results.first ?? SoftwareFixResult(id: plan.id, status: "unverified",
                detail: response?.error ?? "No response from the update. Check again before retrying; changes may have been made.")
            fixResults.removeAll { $0.id == result.id }
            fixResults.insert(result, at: 0)
        }
        fixBusy = false
        await refreshInventory()
        activeFix = nil
        fixStatus = fixResults.contains { result in result.status == "restart_needed" && plans.contains { $0.id == result.id } }
            ? "Updates finished. Restart the apps or services you updated to use the new versions."
            : "Updates finished. Anything still open is listed above."
    }

    // MARK: Smart triage

    /// The timeline holds network history and engine security events only.
    private func runTriage() async {
        guard !preview, triageEnabled, capabilities.engine, capabilities.triageRuntime, !paused else { return }
        if journal == nil, let created = try? WorkflowJournal(directory: EngineTools.dataDirectory.appendingPathComponent("workflows")) {
            journal = created
            timeline.onAppend = { created.append($0) }
        }
        for event in securityEvents.reversed() where timelineSeen.insert("engine:" + event.id).inserted {
            let id = timeline.append(kind: "security_event", collector: "engine", at: event.time, phase: "decided", provenance: "reported", fields: [
                "layer": WorkflowField(event.layer.rawValue), "outcome": WorkflowField(event.outcome.rawValue),
                "title": WorkflowField(event.title), "reason": WorkflowField(event.reason), "subject": WorkflowField(event.subject),
                "agent": WorkflowField(event.agent, provenance: "reported"), "command": WorkflowField(event.command, provenance: "reported"),
                "package": WorkflowField(event.package), "host": WorkflowField(event.host)])
            timelineIDs[id] = "engine:" + event.id
        }
        var networkState = "disabled_or_unavailable"
        if network.setupReady {
            // Bounded catch-up per poll; the cursor continues through retained history on the next one.
            for _ in 0..<4 {
                guard let reply = await NetworkServiceClient.send("network-workflow " + (networkImporter.cursor?.uuidString ?? "start")),
                      let page = try? JSONDecoder().decode(NetworkWorkflowPage.self, from: Data(reply.utf8)) else { networkState = "unavailable"; break }
                let before = timeline.events.count
                networkImporter.ingest(page, into: &timeline)
                for event in timeline.events.suffix(max(0, timeline.events.count - before)) {
                    if let id = event.fields["network_event_id"]?.value { timelineIDs[event.id] = "network:" + id }
                }
                networkState = page.cursorExpired || page.loggingDropped > 0 || page.writeFailures > 0 ? "incomplete" : page.hasMore ? "catching_up" : "active"
                if !page.hasMore { break }
            }
        }
        if timelineIDs.count > 4000 { timelineIDs = timelineIDs.filter { id, _ in timeline.events.contains { $0.id == id } } }
        let sources = [WorkflowSourceState("engine", engineState == .running ? "active" : "unavailable", "Install gate, containment and agent action decisions"),
                       WorkflowSourceState("network", networkState, "New connections recorded by the network extension")]
        reviewer.submit(WorkflowContext.build(from: timeline, sources: sources)) { [weak self] message, judgment in
            guard let self, self.triageEnabled else { return }
            self.triageMessage = message
            self.judgment = judgment
            var notes: [String: String] = [:]
            for finding in judgment?.result?.findings ?? [] {
                for id in finding.eventIDs { if let row = self.timelineIDs[id] { notes[row] = finding.summary + " " + finding.recommendation } }
            }
            if judgment?.result != nil { self.explanations = notes }
        }
    }

    // MARK: Notifications

    private func requestNotificationsOnce() {
        guard notificationsEnabled, !defaults.bool(forKey: "boxcop.notifications.asked") else { return }
        defaults.set(true, forKey: "boxcop.notifications.asked")
        setNotifications(true)
    }
    func setNotifications(_ enabled: Bool) {
        notificationsEnabled = enabled
        defaults.set(enabled, forKey: "boxcop.notifications")
        notificationMessage = ""
        guard enabled, !preview else { return }
        Task {
            let center = UNUserNotificationCenter.current()
            center.setNotificationCategories([UNNotificationCategory(identifier: "boxcop.event",
                actions: [UNNotificationAction(identifier: "boxcop.view", title: "View details", options: [.foreground])], intentIdentifiers: [])])
            let granted = (try? await center.requestAuthorization(options: [.alert, .sound])) ?? false
            if !granted { notificationMessage = "macOS is not allowing BoxCop notifications. Turn them on in System Settings, under Notifications." }
        }
    }
    /// One notification per block or hold: what, why in a few words, and a way to the event.
    private func notify(_ event: FeedEvent, identifier: String? = nil) {
        guard notificationsEnabled, !preview else { return }
        Task {
            let center = UNUserNotificationCenter.current()
            let settings = await center.notificationSettings()
            guard settings.authorizationStatus == .authorized || settings.authorizationStatus == .provisional else { return }
            let content = UNMutableNotificationContent()
            content.title = event.title
            let why = event.reason.split(separator: ".").first.map(String.init) ?? event.reason
            content.body = [event.subject, why].filter { !$0.isEmpty }.joined(separator: "\n")
            content.sound = .default
            content.categoryIdentifier = "boxcop.event"
            content.threadIdentifier = "boxcop-" + event.layer.rawValue
            content.userInfo = ["event": event.id]
            try? await center.add(UNNotificationRequest(identifier: identifier ?? "boxcop-event-" + event.id, content: content, trigger: nil))
        }
    }
    private func announceSecurityEvents(_ events: [SecurityEvent]) {
        guard let seen = announcedEvents else { announcedEvents = Set(events.map(\.id)); return }
        let pending = Set(approvals.pending.map(\.id))
        // A waiting approval already has its own notification.
        for event in events.reversed() where !seen.contains(event.id) && (event.outcome == .blocked || event.outcome == .held) && !pending.contains(event.id) {
            notify(FeedEvent(event))
        }
        announcedEvents = seen.union(events.map(\.id))
    }
    private func announceNetworkBlocks() {
        let blocked = (network.snapshot?.events ?? []).filter { $0.threat != nil }
        guard let seen = announcedNetworkBlocks else {
            if network.snapshot != nil { announcedNetworkBlocks = Set(blocked.map(\.id.uuidString)) }
            return
        }
        // Retries to one host arrive in bursts; one notification per host per poll is enough.
        var hosts = Set<String>()
        for event in blocked.reversed() where !seen.contains(event.id.uuidString) {
            if let row = FeedEvent(network: event), hosts.insert(event.threat?.hostname ?? "").inserted { notify(row) }
        }
        announcedNetworkBlocks = seen.union(blocked.map(\.id.uuidString))
    }
    private func notifyApproval(_ request: PendingApproval) {
        let item = ApprovalItem(id: request.id, application: request.application, reasons: request.reasons, command: "", status: "pending",
                                created: Date(), expires: Date(timeIntervalSince1970: request.expires))
        notify(FeedEvent(approval: item, now: Date()), identifier: AgentApprovalCopy.notificationIdentifier(request.id))
    }
    private func notifyFindings(_ report: SoftwareInventoryReport) async {
        // Stable metadata only: check times and ordering must not cause repeat notifications.
        let current = Set(activeFindings.flatMap { item in item.advisories.map { [item.id, item.version, $0.id, $0.state].joined(separator: "|") } })
        let previous = Set(defaults.stringArray(forKey: "boxcop.inventory.notified") ?? [])
        defaults.set(Array(report.incomplete ? previous.union(current) : current), forKey: "boxcop.inventory.notified")
        guard notificationsEnabled, !current.subtracting(previous).isEmpty else { return }
        let center = UNUserNotificationCenter.current()
        let settings = await center.notificationSettings()
        guard settings.authorizationStatus == .authorized || settings.authorizationStatus == .provisional else { return }
        let content = UNMutableNotificationContent()
        let count = activeFindings.count
        content.title = "\(count) software finding\(count == 1 ? "" : "s") to review"
        content.body = "Installed software on this Mac has a known security issue. This does not mean an attack was detected."
        content.userInfo = ["page": Page.health.rawValue]
        try? await center.add(UNNotificationRequest(identifier: "boxcop-software-review", content: content, trigger: nil))
    }
    func openNotification(userInfo: [AnyHashable: Any], identifier: String) {
        if let event = userInfo["event"] as? String { showEvent(event) }
        else if let id = AgentApprovalCopy.requestID(notificationIdentifier: identifier) { showEvent("approval:" + id) }
        else if let page = (userInfo["page"] as? String).flatMap(Page.init(rawValue:)) { self.page = page; showWindow() }
        else { showWindow() }
    }
    private func updateSettingsHelper() {
        if network.setupPhase == .extensionApproval && network.extensionState != .installed {
            settingsHelper.show("Turn on BoxCop under Network Extensions")
        } else { settingsHelper.stop() }
    }

    // MARK: Settings

    func setLoginEnabled(_ enabled: Bool) {
        Task {
            do {
                if enabled { try await Task.detached(priority: .utility) { try SMAppService.mainApp.register() }.value }
                else { try await SMAppService.mainApp.unregister() }
                refreshLogin()
            } catch { refreshLogin(); loginMessage = "The login item could not be changed. Check System Settings, under General, Login Items." }
        }
    }
    private func refreshLogin() {
        let status = SMAppService.mainApp.status
        loginEnabled = status == .enabled
        switch status {
        case .requiresApproval: loginMessage = "Approve BoxCop in System Settings, under General, Login Items."
        case .notFound: loginMessage = "Start at login needs BoxCop installed in Applications."
        default: loginMessage = ""
        }
    }
    /// Takes BoxCop out of npm, pip, the agents and the network. Data and history stay.
    func removeIntegrations() {
        removalMessage = "Removing."
        for layer in [LayerID.installGate, .containment, .outboundControl, .agentChecks] { setWanted(layer, false) }
        packageEnable?.cancel()
        Task {
            var problems: [String] = []
            if engineState == .running {
                if case let .packageProtection(status)? = await request(.packageProtection(.disable)) { packageStatus = status } else { problems.append("package routing") }
                if case let .scriptProtection(status)? = await request(.scriptProtection(.disable)) { scriptStatus = status } else { problems.append("script routing") }
            } else if packageStatus?.routed == true || scriptStatus?.routed == true || capabilities.engine { problems.append("package and script routing (the engine is not running)") }
            if let snapshot = await HostAgents.refresh(.remove) { agents = snapshot.connections; agentsLoaded = true } else if capabilities.engine { problems.append("agent hooks") }
            if capabilities.networkExtension { await network.removeProtection() }
            removalMessage = problems.isEmpty ? "Hooks, package routing, script routing and the network filter were removed. You can now delete BoxCop."
                : "Could not remove: \(problems.joined(separator: ", ")). Start BoxCop's engine and try again."
        }
    }
    func finishOnboarding(_ chosen: Set<LayerID>) {
        defaults.set(true, forKey: "boxcop.setup.complete")
        onboardingPresented = false
        page = .overview
        guard !preview else { return }
        for layer in LayerID.allCases where chosen.contains(layer) { setLayer(layer, on: true) }
        if chosen.contains(.installGate) || chosen.contains(.containment) || chosen.isEmpty { startEngine() }
        setLoginEnabled(true)
    }

    // MARK: Window

    func showWindow(page: Page? = nil) {
        if let page { self.page = page }
        if window == nil {
            let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 880, height: 600),
                                  styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView], backing: .buffered, defer: false)
            window.title = "BoxCop"
            window.titleVisibility = .hidden
            window.titlebarAppearsTransparent = true
            window.minSize = NSSize(width: 760, height: 520)
            window.contentView = NSHostingView(rootView: MainView(model: self))
            window.isReleasedWhenClosed = false
            window.center()
            self.window = window
            // The menu bar icon can be hidden, so while the window is open BoxCop is also in the Dock and app switcher.
            NotificationCenter.default.addObserver(forName: NSWindow.willCloseNotification, object: window, queue: .main) { _ in
                MainActor.assumeIsolated { _ = NSApp.setActivationPolicy(.accessory) }
            }
        }
        _ = NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
        window?.makeKeyAndOrderFront(nil)
        refreshReview()
    }
}
#endif
