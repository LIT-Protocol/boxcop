#if os(macOS)
import AppKit
import OSLog
import SwiftUI
import ServiceManagement
import UserNotifications
import PDFKit
import UniformTypeIdentifiers
import BoxCopCore

@MainActor final class EndpointModel: ObservableObject {
    let releaseProfile = ReleaseProfile.resolve(bundleProfile: Bundle.main.object(forInfoDictionaryKey: "BoxCopReleaseProfile") as? String,
                                                arguments: CommandLine.arguments)
    var developmentMode: Bool { releaseProfile.automaticDevelopmentCollection }
    var requiresMonitoringConsent: Bool { releaseProfile.requiresMonitoringConsent }
    let releaseChannel = ReleaseChannel.resolve(bundleChannel: Bundle.main.object(forInfoDictionaryKey: "BoxCopReleaseChannel") as? String)
    @Published var onboardingPresented = false { didSet { if onboardingPresented != oldValue { applySetupWindowMode() } } }
    let productSupport: ProductSupport
    @Published var alertFeedbackCategory: AlertFeedbackCategory?
    func showAlertFeedback(_ category: AlertFeedbackCategory) {
        guard alertFeedbackCategory == nil else { return }
        showWindow(page: .activity)
        alertFeedbackCategory = category
    }
    let teamConnection = TeamConnection()
    @Published private(set) var teamInvitation: TeamInvitation?
    private var pendingTeamInvitation: TeamInvitation?
    func openTeamInvitation(_ invitation: TeamInvitation) {
        // Do not replace a form, password or consent decision already in progress.
        if teamInvitation == nil && pendingTeamInvitation == nil { pendingTeamInvitation = invitation }
        presentPendingTeamInvitation()
    }
    private func presentPendingTeamInvitation() {
        guard ownsSession else { return }
        if let pending = pendingTeamInvitation, teamInvitation == nil {
            teamInvitation = pending
            pendingTeamInvitation = nil
            onboardingPresented = false
            softwareReviewPresented = false
        }
        if teamInvitation != nil { showWindow(page: .settings) }
    }
    func closeTeamInvitation() {
        guard !teamConnection.busy else { return }
        teamInvitation = nil
        teamConnection.invalidateInvitation()
        onboardingPresented = requiresMonitoringConsent && !defaults.bool(forKey: "boxcop.setup.complete")
    }
    private var applyingTeamPolicy = false
    let networkConnections = NetworkConnectionsModel()
    let approvals = AgentApprovalWatcher()
    @Published private(set) var networkSetupRequired = false
    private var lastNetworkSetupCheck = Date.distantPast
    var wantsNetworkProtection: Bool { releaseProfile.usesStandaloneNetworkProtection && defaults.bool(forKey: "boxcop.setup.network") }
    @Published private(set) var choices: ConsentChoices
    @Published private(set) var running = false
    @Published private(set) var starting = false
    @Published private(set) var stopping = false
    @Published private(set) var engineStatus = "Stopped — no app or clipboard collection."
    @Published private(set) var clipboardStatus = "Copy new plain text after Start. Existing clipboard is not read."
    @Published private(set) var guardStatus = "Paste protection is off."
    @Published private(set) var guardActive = false
    @Published private(set) var errorMessage: String?
    @Published private(set) var frontmostBundle: String?
    @Published private(set) var frontmostPID: Int32?
    @Published private(set) var records: [SafeRecord] = []
    @Published private(set) var policies: [SafePolicy] = []
    @Published private(set) var notificationsStatus = "Notifications off."
    @Published private(set) var onScreenAlertsEnabled = true
    @Published private(set) var keepReviewAlertsVisible = false
    @Published private(set) var testNotificationStatus: String?
    private let actionableAlertPanel = ActionableAlertPanel()
    @Published private(set) var loginEnabled = false
    @Published private(set) var loginStatus = "Launch at login is off."
    @Published private(set) var loginBusy = false
    @Published private(set) var workflow = WorkflowTimeline()
    @Published private(set) var workflowContextStatus = "Unified context is waiting for enabled inputs."
    private var networkWorkflow = NetworkWorkflowImporter()
    private var networkWorkflowState = "not_connected"
    private var lastProcessSnapshot = Date.distantPast
    private var lastWorkflowContextBuild = Date.distantPast
    private var lastAgentEventAt: Date?
    @Published private(set) var workflowReviewEnabled = true
    /// Advisory "Review before sending" (Gmail). Separate from rules+sequence enforcement and model review.
    @Published private(set) var reviewBook = ReviewReminderBook()
    @Published private(set) var reviewPolicyEnabled = false
    @Published private(set) var reviewNotifications: ReviewReminderNotifier.Authorization?
    @Published private(set) var lastCompositionAt: Date?
    @Published private(set) var reviewNotice: String?
    @Published var focusedReviewReminder: UUID?
    private let emailReviewCache = EmailReviewCache()
    private var recordedEmailReviews = Set<String>()
    private var recordedEmailAnnotations = Set<String>()
    @Published private(set) var workflowJudgment: WorkflowJudgmentStatus?
    @Published private var pendingEmailReviewTargets: Set<UUID> = []
    private var dismissedEmailReviewTargets: Set<UUID> = []
    private let workflowReviewer = WorkflowReviewClient()
    @Published private(set) var codeVerificationEnabled = false
    @Published private(set) var codeFindings: [CodeVerificationFinding] = []
    @Published private(set) var dismissedCodeFindings: Set<UUID> = []
    private var codeNotificationIDs: Set<String> = []
    private var codeGeneration = UUID()
    private var codeRecorded: [UUID: String] = [:]
    private var codeStartSequence = 0
    private var codeLastRevision = -1
    private var codeLastUpdate = Date.distantPast
    @Published private(set) var pdfReviewEnabled = false
    @Published private(set) var pdfReviewBook = PDFReviewBook()
    @Published var pdfPreview: LocalPDFPreview?
    @Published private(set) var pdfPreviewLoading = false
    @Published private(set) var pdfPreviewMessage: String?
    private var pdfReviewGeneration = UUID()
    private var pdfNotificationIDs: Set<String> = []
    private var lastPDFNotification = Date.distantPast

    /// Window titles, selected text, clicks, process lists, home-folder changes and routine captures.
    /// Off on new installs: paste protection needs only copied text and the destination app.
    @Published private(set) var activityCollection = false
    private var collectWindowTitles: Bool { activityCollection }
    @Published private(set) var workflowStatus = "App focus and lifecycle events stay in memory until you export them."
    private var collectSelectedText: Bool { activityCollection }
    private var collectClicks: Bool { activityCollection }
    private var collectPointerMotion: Bool { activityCollection }
    private var collectWindowFrames = false
    private let frameCollector = WindowFrameCollector()
    private var frameTask: Task<Void, Never>?
    @Published private(set) var browserConnected = false
    /// Browser and agent events arrive only for the features that use them.
    var collectAdapters: Bool { activityCollection || browserConnected || reviewPolicyEnabled || codeVerificationEnabled || pdfReviewEnabled }
    private var captureRiskWindows: Bool { activityCollection }
    private var fileWatchRoot: URL? { activityCollection ? FileManager.default.homeDirectoryForCurrentUser : nil }
    private var clipboardChecksEnabled: Bool { choices.guardShortcut || activityCollection }
    /// One request from setup. A later opt-out in Connections must not be replayed.
    @Published private(set) var packageSetupPending = false
    @Published private(set) var collectionStatus = "Activity collection is off."
    private let clickCollector = ClickCollector()
    private let fileCollector = FileChangeCollector()
    private let adapterTransport = CollectorTransport()
    private let draftAdmission = DraftAdmission()
    private var extraCollectorGeneration: UInt64 = 0
    private let visualCollector = VisualCollector()
    private var backgroundScreenMonitor: BackgroundScreenMonitor?
    @Published private(set) var backgroundScreenEnabled = true
    @Published private(set) var backgroundScreenFullScreen = true
    func setBackgroundScreenFullScreen(_ enabled: Bool) {
        guard applyingTeamPolicy || teamConnection.state.settings["screen_cover"] == nil else { return }
        if applyingTeamPolicy && backgroundScreenFullScreen == enabled { return }
        backgroundScreenFullScreen = enabled
        if !applyingTeamPolicy { defaults.set(enabled, forKey: preferencesKey + ".backgroundScreenFullScreen") }
        restartBackgroundScreenMonitoring()
    }
    @Published private(set) var backgroundScreenStatus = "Screen checks paused. Resume monitoring to start."
    func setBackgroundScreenMonitoring(_ enabled: Bool) {
        guard applyingTeamPolicy || teamConnection.state.settings["background_screen"] == nil else { return }
        if applyingTeamPolicy && backgroundScreenEnabled == enabled { return }
        backgroundScreenEnabled = enabled
        if !applyingTeamPolicy { defaults.set(enabled, forKey: preferencesKey + ".backgroundScreenWarnings") }
        restartBackgroundScreenMonitoring()
    }
    private func restartBackgroundScreenMonitoring() {
        backgroundScreenMonitor?.stop(); backgroundScreenMonitor = nil
        guard backgroundScreenEnabled, running else {
            backgroundScreenStatus = backgroundScreenEnabled ? "Screen checks paused. Resume monitoring to start." : "Background screen warnings are off."
            return
        }
        let monitor = BackgroundScreenMonitor(fullScreen: backgroundScreenFullScreen, update: { [weak self] in self?.backgroundScreenStatus = $0 }, observation: { [weak self] availability, decision in
            guard let self, self.running else { return }
            self.workflow.append(kind: "screen_assessment", collector: "ScreenCaptureKit.background", availability: availability,
                fields: ["assessment": WorkflowField(decision, provenance: "derived"),
                         "pixels": WorkflowField(nil, availability: "not_retained"),
                         "recognized_text": WorkflowField(nil, availability: "not_retained_by_this_collector")])
        })
        backgroundScreenMonitor = monitor
        monitor.start()
    }
    private var screenShareGuard: ScreenShareGuard?
    private var protectedPresentation: ProtectedPresentation?
    @Published private(set) var presentationSources: [ProtectedPresentation.Source] = []
    @Published private(set) var presentationStatus = "Choose a window, then share BoxCop’s presentation window in your meeting."
    @Published private(set) var presentationRunning = false
    @Published private(set) var presentationLoading = false
    func refreshPresentationSources() {
        guard !presentationLoading else { return }
        presentationLoading = true
        Task { @MainActor in
            defer { presentationLoading = false }
            do { presentationSources = try await ProtectedPresentation.sources() }
            catch { presentationSources = []; presentationStatus = "Window list unavailable. Grant Screen Recording in Settings and retry." }
        }
    }
    func startPresentation(windowID: UInt32) {
        guard running, let source = presentationSources.first(where: { $0.id == windowID }) else { return }
        if protectedPresentation == nil {
            protectedPresentation = ProtectedPresentation { [weak self] status in
                self?.presentationStatus = status
                self?.presentationRunning = self?.protectedPresentation?.isRunning ?? false
            }
        }
        protectedPresentation?.start(source: source)
    }
    func stopPresentation() { protectedPresentation?.stop() }
    @Published private(set) var screenShareStatus = "Screen-share preflight is off."
    @Published private(set) var screenShareEnabled = false
    @Published private(set) var screenShareActive = false
    func setScreenSharePreflight(_ enabled: Bool) {
        screenShareEnabled = enabled
        screenShareGuard?.stop(); screenShareGuard = nil; screenShareActive = false
        guard enabled, running else { screenShareStatus = "Screen-share preflight is off."; return }
        let guarder = ScreenShareGuard(update: { [weak self] in
            self?.screenShareStatus = $0
            self?.screenShareActive = self?.screenShareGuard?.isActive ?? false
        }, audit: { [weak self] event in
            self?.workflow.append(kind: "screen_share_preflight", collector: "CGEventTap.AX.OCR", availability: event)
        })
        screenShareGuard = guarder; guarder.start()
    }
    private var visualTask: Task<Void, Never>?
    private var lastCapture: TimeInterval = 0
    private var lastExternalApp: (String, Int32)?
    private var lastContextEvent: UUID?
    @Published private(set) var lastBrowserEventAt: Date?
    @Published private(set) var browserSetupStatus = "Browser bridge has not been verified this session."
    @Published private(set) var agentRepairBusy = false
    private var browserContexts: [String: UUID] = [:]
    private let windowReader = WindowContextReader()
    private var windowTask: Task<Void, Never>?
    private var windowGeneration: UInt64 = 0
    private var lastWindowPoll: TimeInterval = 0
    private var lastWindowSignature: String?
    @Published private(set) var developmentLogging = false
    @Published private(set) var developmentStatus = "Development logging off."
    @Published private(set) var pasteTestStatus = "Dev paste test idle. Uses fake text and overwrites the clipboard."
    private var pasteSelfTest: PasteSelfTest?
    private var collectionSelfTest: CollectionSelfTest?
    private var pasteTestStarting = false
    private var developmentLog: DevelopmentLog?
    private var workflowJournal: WorkflowJournal?
    @Published private(set) var agentConnections: [HostAgents.Connection] = []
    @Published private(set) var hostAgentStatus = "Agent hooks: checking installed harnesses"
    @Published private(set) var ignoredSoftwareFindings = Set<SoftwareFindingIdentity>()
    @Published private(set) var softwareInventory: SoftwareInventoryReport?
    @Published private(set) var inventoryStatus = "Check your installed software for known security issues."
    @Published private(set) var inventoryBusy = false
    @Published private(set) var inventoryCheckedAt: Date?
    @Published var softwareReviewPresented = false
    @Published var selectedSoftwareFixes = Set<String>() {
        didSet { if oldValue != selectedSoftwareFixes { softwareFixPlans = [] } }
    }
    @Published var softwareFixPlans: [SoftwareFixPlan] = []
    @Published private(set) var softwareFixResults: [SoftwareFixResult] = []
    @Published private(set) var softwareFixNames: [String: String] = [:]
    @Published private(set) var softwareFixBusy = false
    @Published private(set) var activeSoftwareFix: SoftwareConsoleSelection?
    @Published private(set) var softwareFixStatus = ""
    private var knownSoftwareFixes = Set<String>()
    private var permissionCheckTask: Task<Void, Never>?
    private var lastMissingPermission: SetupPermission?
    private var packageEnableTask: Task<Void, Never>?
    @Published private(set) var scriptProtectionStatus: ScriptProtectionStatus?
    private var scriptWatchTask: Task<Void, Never>?
    private var announcedScriptBlocks = Set<String>()
    private let scriptNotice = InterventionNotice()
    private var lastAccessibility = false
    private var lastScreenRecording = false
    private var inventoryTask: Task<Void, Never>?
    private var hostAgentTask: Task<Void, Never>?
    @Published private(set) var endpointSecurityStatus = "Endpoint Security service not connected"
    private var lastEndpointSecurityPoll: TimeInterval = 0
    private func controlEndpointSecurity(_ command: String) {
        guard releaseProfile.usesEndpointSecurity else { return }
        let expectedEpoch = epoch
        EndpointSecurityControl.submit(command) { [weak self] reply in
            Task { @MainActor [weak self] in
                guard let self, self.epoch == expectedEpoch else { return }
                self.endpointSecurityStatus = EndpointSecurityControl.summary(reply)
            }
        }
    }
    @Published private(set) var journalStatus = "Workflow journal not started."
    private let defaults: UserDefaults
    private let collectors = NativeCollectors()
    private let clipboardReader = ClipboardReader()
    private var monitor = MonitoringState()
    private var gate = PasteGate()
    private var pasteOverride = PasteOverride()
    private let pasteNotice = InterventionNotice()
    private var blockedPasteKey: SnapshotKey?
    private let systemNotice = InterventionNotice()
    private var interventionObserver: NSObjectProtocol?
    private var tap: ShortcutTap?
    private var client: EngineClient?
    private var startup: Task<Void, Never>?
    private var work: [UUID: Task<Void, Never>] = [:]
    private var stopTask: Task<Void, Never>?
    @Published private(set) var recovering = false
    private var recoveryTask: Task<Void, Never>?
    private var recovery = MonitoringRecovery()
    private var pasteRecovery = PasteProtectionRecovery()
    private let monitoringLogger = Logger(subsystem: "app.boxcop.monitoring", category: "recovery")
    private var healthTask: Task<Void, Never>?
    private var epoch: UInt64 = 0
    private var lastHealthCheck: TimeInterval = 0
    private var unsupportedRevision: (Int, ClipboardUnsupported)?
    @Published var selectedPage: EndpointPage = .protection
    private var window: NSWindow?
    private var notificationGeneration: UInt64 = 0
    private var lastPasteNotification = Date.distantPast
    private var personalChoicesForSaving: ConsentChoices {
        var value = choices
        if teamConnection.state.settings["guard_shortcut"] != nil {
            let saved = defaults.data(forKey: preferencesKey).flatMap { try? JSONDecoder().decode(ConsentChoices.self, from: $0) }
            value.guardShortcut = saved?.guardShortcut ?? developmentMode
        }
        return value
    }
    private var preferencesKey: String { releaseProfile.consentKey }
    private var sleepResume = SleepResume()
    private var sleepObserver: NSObjectProtocol?
    private var wakeObserver: NSObjectProtocol?
    /// Set only after the per-user owner lock is held; a rejected duplicate instance can never start collection.
    private var ownsSession = false

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        productSupport = ProductSupport(defaults: defaults)
        onScreenAlertsEnabled = defaults.object(forKey: "boxcop.onScreenAlerts.enabled") as? Bool ?? true
        keepReviewAlertsVisible = defaults.bool(forKey: "boxcop.keepReviewAlertsVisible")
        ignoredSoftwareFindings = IgnoredSoftwareFindings.load(from: defaults)
        workflowReviewEnabled = defaults.object(forKey: "boxcop.workflowReview.enabled") as? Bool ?? false
        codeVerificationEnabled = defaults.bool(forKey: "boxcop.codeVerification.enabled")
        pdfReviewEnabled = defaults.bool(forKey: "boxcop.pdfReview.enabled")
        reviewPolicyEnabled = defaults.bool(forKey: ReviewPolicy.enabledKey)
        humanChecksRequested = defaults.bool(forKey: "boxcop.humanChecks.shown")
        choices = ConsentChoices()
        if let bytes = defaults.data(forKey: preferencesKey), let choices = try? JSONDecoder().decode(ConsentChoices.self, from: bytes) { self.choices = choices }
        else { choices = ConsentChoices() }
        // New installs start with everything off. Earlier installs keep what they had.
        let established = !requiresMonitoringConsent || defaults.bool(forKey: "boxcop.setup.complete")
        for key in [preferencesKey + ".activityCollection", preferencesKey + ".backgroundScreenWarnings", "boxcop.setup.network", "boxcop.setup.screen"]
        where defaults.object(forKey: key) == nil { defaults.set(established, forKey: key) }
        if defaults.object(forKey: "boxcop.setup.notificationsAsked") == nil {
            defaults.set(established || defaults.object(forKey: "boxcop.setup.notifications") != nil, forKey: "boxcop.setup.notificationsAsked")
        }
        activityCollection = defaults.bool(forKey: preferencesKey + ".activityCollection")
        collectWindowFrames = activityCollection
        browserConnected = defaults.bool(forKey: preferencesKey + ".browserConnected")
        packageSetupPending = defaults.bool(forKey: "boxcop.setup.packagePending")
        if activityCollection { collectionStatus = "Activity collection starts automatically with monitoring." }
        backgroundScreenFullScreen = defaults.object(forKey: preferencesKey + ".backgroundScreenFullScreen") as? Bool ?? true
        backgroundScreenEnabled = defaults.object(forKey: preferencesKey + ".backgroundScreenWarnings") as? Bool ?? true
        if !backgroundScreenEnabled { backgroundScreenStatus = "Background screen warnings are off." }
        // Development builds also start monitoring and paste protection automatically.
        // All profiles collect available activity once monitoring is running.
        if developmentMode {
            choices.monitoring = true
            choices.autoStart = true
            choices.guardShortcut = true
        }
        if releaseProfile.usesStandaloneNetworkProtection { endpointSecurityStatus = "Endpoint Security is not included. Outgoing protection uses the Network Extension independently." }
        if releaseProfile == .limitedDevelopment {
            endpointSecurityStatus = "This limited development build excludes native file enforcement and the network extension. Use a distribution build for outgoing protection."
            if activityCollection { collectionStatus = "Activity collection starts automatically with monitoring. SIP stays enabled." }
        }
        if choices.notifications { notificationsStatus = "Security notifications enabled; macOS permission controls delivery." }
        refreshLoginStatus()
        interventionObserver = DistributedNotificationCenter.default().addObserver(forName: InterventionSignal.name, object: nil, queue: .main) { [weak self] notification in
            // This channel is feedback only. It never grants permission or trusts supplied UI text.
            guard let category = notification.userInfo?["category"] as? String,
                  let kind = InterventionKind(rawValue: category),
                  let audience = notification.object as? String,
                  audience == String(getuid()) || audience == "unknown" else { return }
            Task { @MainActor [weak self] in
                guard let self, self.ownsSession else { return }
                self.systemNotice.show(title: kind.title, message: kind.message, actionTitle: "Open BoxCop", allow: { [weak self] in
                    self?.systemNotice.dismiss()
                    self?.showWindow(page: .protection)
                }, feedback: { [weak self] in self?.showAlertFeedback(kind == .network ? .network : .system) })
            }
        }
    }
    var activeSoftwareFindings: [SoftwareObservation] {
        (softwareInventory?.findings ?? []).compactMap { observation in
            var active = observation
            active.advisories = observation.advisories.filter {
                $0.needsReview && !ignoredSoftwareFindings.contains(observation.identity(for: $0))
            }
            return active.advisories.isEmpty ? nil : active
        }
    }
    var activeSoftwareFixItems: [SoftwareFixItem] {
        let activeIDs = Set(activeSoftwareFindings.map(\.id))
        let ignoredIDs = Set((softwareInventory?.findings ?? []).map(\.id)).subtracting(activeIDs)
        // Keep actions without matching findings; only an explicit dismissal hides an action.
        return (softwareInventory?.remediationItems ?? []).filter {
            $0.observationIds.isEmpty || !$0.observationIds.allSatisfy(ignoredIDs.contains)
        }
    }
    func ignoreSoftwareFinding(_ observation: SoftwareObservation) {
        guard !inventoryBusy, !softwareFixBusy else { return }
        ignoredSoftwareFindings.formUnion(observation.advisories.filter(\.needsReview).map { observation.identity(for: $0) })
        saveIgnoredSoftwareFindings()
    }
    func restoreSoftwareFinding(_ identity: SoftwareFindingIdentity) {
        guard !inventoryBusy, !softwareFixBusy else { return }
        ignoredSoftwareFindings.remove(identity)
        saveIgnoredSoftwareFindings()
    }
    private func saveIgnoredSoftwareFindings() {
        IgnoredSoftwareFindings.save(ignoredSoftwareFindings, to: defaults)
        selectedSoftwareFixes.formIntersection(Set(activeSoftwareFixItems.filter(\.automatic).map(\.id)))
        softwareFixPlans = []
        updateSoftwareInventoryStatus()
    }
    private func updateSoftwareInventoryStatus() {
        guard let report = softwareInventory else { return }
        let count = activeSoftwareFindings.count
        inventoryStatus = count == 0
            ? (report.findings.isEmpty
                ? (report.incomplete ? "No issues found in the software checked" : "No known issues found in the software checked")
                : "No software findings need your attention · current findings are ignored")
            : "\(count) software installation\(count == 1 ? " needs" : "s need") your attention"
    }
    func refreshSoftwareInventory() async {
        guard ownsSession, !inventoryBusy, !softwareFixBusy else { return }
        inventoryBusy = true
        defer { inventoryBusy = false }
        inventoryStatus = "Checking installed software…"
        let (report, _) = await SoftwareInventory.refresh()
        guard let report else {
            inventoryStatus = "Couldn’t check software. Try again; any results below are from the previous check."
            return
        }
        softwareInventory = report
        if softwareFixPlans.isEmpty { softwareFixStatus = "" }
        softwareFixResults = report.remediationResults ?? softwareFixResults
        let available = Set(activeSoftwareFixItems.filter(\.automatic).map(\.id))
        selectedSoftwareFixes.formIntersection(available)
        selectedSoftwareFixes.formUnion(available.subtracting(knownSoftwareFixes))
        knownSoftwareFixes = available
        inventoryCheckedAt = Date()
        await notifyInventory(report)
        workflow.append(kind: "software_inventory", collector: "offline_metadata", availability: report.incomplete ? "partial" : "selected_roots_scanned", fields: [
            "reviewed_at": WorkflowField(report.reviewedAt), "generated_at": WorkflowField(report.generatedAt),
            "observations": WorkflowField(String(report.records.count)), "review_findings": WorkflowField(String(report.findings.count)),
            "enforcement": WorkflowField("finding_only")
        ])
        for record in report.records.prefix(128) {
            workflow.append(kind: "software_observation", collector: "offline_metadata", availability: report.incomplete ? "partial" : "available", fields: [
                "observation_id": WorkflowField(record.id), "name": WorkflowField(record.name), "version": WorkflowField(record.version),
                "path": WorkflowField(record.path), "kind": WorkflowField(record.kind),
                "advisories": WorkflowField(record.advisories.map { $0.id + ":" + $0.state }.joined(separator: ",")),
                "inventory_generated_at": WorkflowField(report.generatedAt), "enforcement": WorkflowField("finding_only")])
        }
        if report.records.count > 128 { workflow.append(kind: "collector_health", collector: "offline_metadata", availability: "inventory_truncated") }
        updateSoftwareInventoryStatus()
    }
    func cancelSoftwareFixPlan() {
        softwareFixPlans = []
        softwareFixStatus = ""
    }
    func prepareSoftwareFixes() async {
        guard ownsSession, !softwareFixBusy, !inventoryBusy, !selectedSoftwareFixes.isEmpty else { return }
        softwareFixBusy = true
        softwareFixPlans = []
        softwareFixStatus = "Checking available versions and preparing selected updates…"
        let selected = selectedSoftwareFixes.sorted()
        var plans: [SoftwareFixPlan] = []
        // One request per selection keeps progress visible and bounds each request.
        for (index, id) in selected.enumerated() {
            softwareFixStatus = "Preparing update \(index + 1) of \(selected.count)…"
            if let response = await SoftwareRemediation.request("prepare", payload: ["ids": [id]]), response.error == nil {
                plans.append(contentsOf: response.plans)
                softwareFixResults = response.results
            }
        }
        softwareFixPlans = plans
        softwareFixStatus = plans.count == selected.count
            ? "Review the plan, then apply the available updates."
            : "Some selections could not be prepared or changed since the scan. Recheck and retry those items."
        softwareFixBusy = false
        // Refresh classifications (e.g. migration) without clearing the reviewed plan.
        let preparedPlans = softwareFixPlans
        let preparationStatus = softwareFixStatus
        await refreshSoftwareInventory()
        softwareFixPlans = preparedPlans
        softwareFixStatus = preparationStatus
    }
    func applySoftwareFixes() async {
        guard ownsSession, !softwareFixBusy, !inventoryBusy else { return }
        let plans = softwareFixPlans.filter(\.ready)
        guard !plans.isEmpty else { return }
        softwareFixBusy = true
        softwareFixPlans = []
        for (index, plan) in plans.enumerated() {
            softwareFixNames[plan.id] = plan.name + " " + plan.versions
            activeSoftwareFix = SoftwareConsoleSelection(id: plan.id, name: plan.name)
            softwareFixResults.removeAll { $0.id == plan.id }
            softwareFixResults.insert(SoftwareFixResult(id: plan.id, status: "in_progress", detail: "Applying the approved plan. Open the live console for progress.", name: plan.name), at: 0)
            softwareFixStatus = "Applying \(plan.name) (\(index + 1) of \(plans.count))… Source builds can take a while; there is no install time limit."
            let response = await SoftwareRemediation.request("apply", payload: ["id": plan.id, "fingerprint": plan.fingerprint])
            let result = response?.results.first ?? SoftwareFixResult(id: plan.id, status: "unverified", detail: response?.error ?? "Update response unavailable. Recheck installed software before retrying; changes may have occurred.")
            softwareFixResults.removeAll { $0.id == result.id }
            softwareFixResults.insert(result, at: 0)
            workflow.append(kind: "software_remediation", collector: "package_manager", availability: result.status,
                            fields: ["name": WorkflowField(plan.name), "target_version": WorkflowField(plan.target), "result": WorkflowField(result.status), "update_id": WorkflowField(plan.id), "detail": WorkflowField(result.detail)])
        }
        softwareFixBusy = false
        await refreshSoftwareInventory()
        activeSoftwareFix = nil
        softwareFixStatus = softwareFixResults.contains { result in result.status == "restart_needed" && plans.contains { $0.id == result.id } }
            ? "Updates finished. Restart the apps or services you updated to use the new versions."
            : "Updates finished. Any remaining issues are shown above."
    }
    var health: MonitoringHealth {
        MonitoringHealth(starting: starting, stopping: stopping, running: running, consent: choices.monitoring,
                         guardRequested: choices.guardShortcut, guardActive: guardActive, failed: errorMessage != nil, recovering: recovering)
    }
    var actionableAlerts: [ActionableAlert] {
        var alerts: [ActionableAlert] = []
        func add(_ category: ActionableAlert.Category, _ ids: [String]) {
            if !ids.isEmpty { alerts.append(ActionableAlert(category: category, itemIDs: Set(ids))) }
        }
        // Item/version identity survives inventory rescans without repeating the same panel.
        add(.software, activeSoftwareFindings.map { item in
            [item.id, item.version, item.advisories.map { $0.id + ":" + $0.state }.sorted().joined(separator: ",")].joined(separator: "|")
        })
        // Held agent actions block the agent, so they count whether or not monitoring runs.
        add(.approval, approvals.pending.map(\.id))
        if running {
            if reviewPolicyEnabled { add(.draft, reviewBook.reminders.filter(\.needsReviewAttention).map { $0.id.uuidString }) }
            if codeVerificationEnabled { add(.code, codeFindings.filter { $0.alerts && !dismissedCodeFindings.contains($0.id) }.map { $0.id.uuidString + "|" + $0.outcome }) }
            if pdfReviewEnabled { add(.pdf, pdfReviewBook.selections.filter { !$0.dismissed && Date().timeIntervalSince($0.observedAt) <= PDFReviewBook.retention && pdfReviewBook.status(for: $0).needsReminder }.map { $0.id.uuidString }) }
            if workflowReviewEnabled { add(.email, pendingEmailReviewAssessments.compactMap { $0.relatedEventIDs.first?.uuidString }) }
        }
        return alerts
    }
    var pendingActivityReviewCount: Int { actionableAlerts.filter { $0.category != .software && $0.category != .protection && $0.category != .approval }.reduce(0) { $0 + $1.itemIDs.count } }
    var pendingReviewCount: Int { actionableAlerts.reduce(0) { $0 + $1.itemIDs.count } }
    func refreshActionableAlerts() {
        let keys = actionableAlerts.filter { alert in
            choices.notifications || (alert.category != .code && alert.category != .pdf)
        }.reduce(into: Set<String>()) { $0.formUnion($1.keys) }
        actionableAlertPanel.update(liveKeys: keys, enabled: onScreenAlertsEnabled, keepVisible: keepReviewAlertsVisible)
    }
    func closeActionableAlerts() { actionableAlertPanel.close() }
    private func startApprovalWatcher() {
        approvals.onNew = { [weak self] in self?.notifyApproval($0) }
        approvals.onGone = { ids in
            let identifiers = ids.map(AgentApprovalCopy.notificationIdentifier)
            let center = UNUserNotificationCenter.current()
            center.removePendingNotificationRequests(withIdentifiers: identifiers)
            center.removeDeliveredNotifications(withIdentifiers: identifiers)
        }
        approvals.onChange = { [weak self] in
            self?.objectWillChange.send()
            self?.refreshActionableAlerts()
        }
        approvals.start()
    }
    /// The agent is blocked until someone answers, so this uses a persistent macOS notification
    /// rather than the short-lived heads-up panel. The copy never includes command content.
    private func notifyApproval(_ request: PendingApproval) {
        guard ownsSession, choices.notifications else { return }
        let identifier = AgentApprovalCopy.notificationIdentifier(request.id)
        Task { @MainActor [weak self] in
            let settings = await UNUserNotificationCenter.current().notificationSettings()
            guard let self, settings.authorizationStatus == .authorized || settings.authorizationStatus == .provisional,
                  self.choices.notifications, self.approvals.pending.contains(where: { $0.id == request.id }) else { return }
            let content = UNMutableNotificationContent()
            content.title = AgentApprovalCopy.title(application: request.application)
            content.body = AgentApprovalCopy.body(reasons: request.reasons)
            content.sound = .default
            content.threadIdentifier = "boxcop-approval"
            try? await UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: identifier, content: content, trigger: nil))
            if !self.approvals.pending.contains(where: { $0.id == request.id }) {
                UNUserNotificationCenter.current().removeDeliveredNotifications(withIdentifiers: [identifier])
            }
        }
    }
    /// Asked when the person turns on an approval rule: without notifications, held actions wait unseen.
    func requestApprovalNotificationsIfUndecided() {
        Task { @MainActor [weak self] in
            let settings = await UNUserNotificationCenter.current().notificationSettings()
            guard let self, settings.authorizationStatus == .notDetermined else { return }
            self.setNotifications(true)
        }
    }
    private func offerHeadsUp(_ category: ActionableAlert.Category, itemID: String,
                             settings: UNNotificationSettings, stillCurrent: () -> Bool) async -> ReviewHeadsUpOutcome {
        guard ownsSession else { return .notUsed }
        refreshActionableAlerts()
        return await actionableAlertPanel.offer(ReviewHeadsUpItem(category: category, itemID: itemID),
            bannersAllowed: settings.authorizationStatus == .authorized && settings.alertSetting == .enabled,
            stillCurrent: stillCurrent) { [weak self] items in
                guard let self else { return }
                if items.count == 1, let item = items.first, item.category == .draft, let id = UUID(uuidString: item.itemID) {
                    self.openReviewReminder(id)
                } else { self.showWindow(page: .activity) }
            }
    }
    var pendingEmailReviewAssessments: [WorkflowEvent] {
        guard running, workflowReviewEnabled else { return [] }
        var seen = Set<UUID>()
        let retained = Set(workflow.events.map(\.id))
        return workflow.events.reversed().filter { event in
            guard event.kind == "email_review_assessment", event.fields["outcome"]?.value == "high_risk", let target = event.relatedEventIDs.first,
                  pendingEmailReviewTargets.contains(target), seen.insert(target).inserted else { return false }
            return retained.contains(target)
        }
    }
    func dismissEmailReviewAlert(_ target: UUID) {
        dismissedEmailReviewTargets.insert(target)
        pendingEmailReviewTargets.remove(target)
        removeEmailReviewNotifications([target])
        workflow.append(kind: "email_review_notice_dismissed", collector: "workflow.review",
                        fields: ["resolution": WorkflowField("dismissed_not_verified")], relatedEventIDs: [target])
    }
    var menuStatus: String { health.summary }
    /// Beta setup dismissed with "Set up later" stays in the menu until it is finished.
    var setupPending: Bool { requiresMonitoringConsent && (!defaults.bool(forKey: "boxcop.setup.complete") || networkSetupRequired) }
    var setupComplete: Bool { defaults.bool(forKey: "boxcop.setup.complete") }
    var canStart: Bool { ownsSession && teamConnection.ready && choices.monitoring && !starting && !stopping && !running }
    private func saveChoices() { if let bytes = try? JSONEncoder().encode(personalChoicesForSaving) { defaults.set(bytes, forKey: preferencesKey) } }
    private var setupStartAttempted = false
    /// A click in setup asks to start, even with automatic startup off. macOS may relaunch BoxCop before the permission arrives.
    private var setupStartRequested: Bool {
        get { defaults.bool(forKey: "boxcop.setup.startRequested") }
        set { defaults.set(newValue, forKey: "boxcop.setup.startRequested") }
    }
    func finishSetup() {
        guard ownsSession else { return }
        if choices.monitoring && !defaults.bool(forKey: "boxcop.setup.complete") { setAutoStart(true) }
        defaults.set(true, forKey: "boxcop.setup.complete")
        onboardingPresented = false
        startSoftwareInventory()
    }
    private func startSoftwareInventory() {
        guard ownsSession, inventoryTask == nil, developmentMode || choices.monitoring else { return }
        // A permission-triggered relaunch can happen before the wizard is done.
        guard !requiresMonitoringConsent || defaults.bool(forKey: "boxcop.setup.complete") else { return }
        inventoryTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                await self.refreshSoftwareInventory()
                do { try await Task.sleep(nanoseconds: 300_000_000_000) }
                catch { return }
            }
        }
    }
    private func startAfterSetupPermissions() {
        guard !setupStartAttempted, canStart else { return }
        guard setupStartRequested || !defaults.bool(forKey: "boxcop.setup.complete") || choices.autoStart else { return }
        setupStartAttempted = true
        setupStartRequested = false
        start()
    }
    /// Turning on a protection is the consent. BoxCop's engine starts the first time one needs it.
    func turnOnPasteProtection() {
        setupStartRequested = true
        setMonitoringConsent(true)
        setGuardConsent(true)
        if ShortcutTap.accessibilityGranted { startSetupSession() } else { requestAccessibility() }
    }
    func turnOnScreenProtection() {
        setupStartRequested = true
        setMonitoringConsent(true)
        defaults.set(true, forKey: "boxcop.setup.screen")
        defaults.set(true, forKey: "boxcop.setup.screenNeedsAccessibility")
        setBackgroundScreenMonitoring(true)
        requestNextScreenPermission()
    }
    func requestNextScreenPermission() {
        switch SetupRequirements.nextForScreen(accessibility: ShortcutTap.accessibilityGranted, screenRecording: CGPreflightScreenCaptureAccess()) {
        case .screenRecording: requestScreenRecording()
        case .accessibility: requestAccessibility()
        default: startSetupSession()
        }
    }
    func turnOnPackageProtection() {
        setMonitoringConsent(true)
        packageSetupPending = true
        defaults.set(true, forKey: "boxcop.setup.packagePending")
        if running { sendPendingPackageEnable() } else { startSetupSession() }
    }
    private func sendPendingPackageEnable() {
        guard packageSetupPending, running, packageEnableTask == nil else { return }
        packageEnableTask = Task { [weak self] in
            defer { self?.packageEnableTask = nil }
            var sent = false
            while let self, self.running, self.packageSetupPending, !Task.isCancelled {
                do {
                    // The engine drops an enable that arrives during its startup check.
                    let busy = try await self.packageProtection(.status).busy
                    guard self.packageSetupPending else { return }
                    if !busy {
                        if sent { self.clearPackageSetupPending(); return }
                        _ = try await self.packageProtection(.enable)
                        sent = true
                    }
                    try await Task.sleep(nanoseconds: 250_000_000)
                } catch {
                    // An engine that stopped picks the request up on its next start.
                    if self.running { self.clearPackageSetupPending() }
                    return
                }
            }
        }
    }
    private func clearPackageSetupPending() {
        packageSetupPending = false
        defaults.set(false, forKey: "boxcop.setup.packagePending")
    }
    func startSetupSession() {
        guard choices.monitoring else { return }
        guard running else { if canStart { start() }; return }
        if choices.guardShortcut && !guardActive { enableGuard() }
        if backgroundScreenEnabled && backgroundScreenMonitor == nil { restartBackgroundScreenMonitoring() }
    }
    // MARK: Checks on your own actions
    /// Paste, screen and email/PDF review protect against the person's own mistakes. Teams use
    /// them as policy; individuals opt in. Until then the app presents agent protection only.
    @Published private(set) var humanChecksRequested = false
    var humanChecksInUse: Bool {
        (choices.monitoring && choices.guardShortcut) || (backgroundScreenEnabled && defaults.bool(forKey: "boxcop.setup.screen"))
            || screenShareEnabled || presentationRunning || workflowReviewEnabled || reviewPolicyEnabled || pdfReviewEnabled
    }
    var showsHumanChecks: Bool { teamConnection.isTeam || humanChecksRequested || humanChecksInUse }
    /// Hiding also turns the checks off, so nothing keeps running out of view. Team members
    /// cannot hide them; team-locked settings keep their team value.
    func setHumanChecksShown(_ shown: Bool) {
        humanChecksRequested = shown
        defaults.set(shown, forKey: "boxcop.humanChecks.shown")
        guard !shown, !teamConnection.isTeam else { return }
        // Only what is on: each setter records withdrawals and may touch notifications.
        if choices.guardShortcut { setGuardConsent(false) }
        if backgroundScreenEnabled { setBackgroundScreenMonitoring(false) }
        defaults.set(false, forKey: "boxcop.setup.screen")
        if screenShareEnabled { setScreenSharePreflight(false) }
        if presentationRunning { stopPresentation() }
        if workflowReviewEnabled { setWorkflowReviewEnabled(false) }
        if reviewPolicyEnabled { setReviewPolicyEnabled(false) }
        if pdfReviewEnabled { setPDFReviewEnabled(false) }
    }
    var agentSetupStatus: AgentSetupStatus? { AgentSetupCopy.status(of: agentSetupTools, attempted: false) }
    var agentSetupTools: [(id: String, state: String)] {
        agentConnections.map { (id: $0.id, state: AgentSetupCopy.effectiveState(summary: $0.state, actions: $0.actions.map(\.state))) }
    }
    private var anyProtectionOn: Bool {
        if running || networkConnections.setupReady { return true }
        switch AgentSetupCopy.status(of: agentSetupTools, attempted: false) {
        case .on, .added: return true
        default: return false
        }
    }
    private func requestNotificationsAfterFirstProtection() {
        guard !defaults.bool(forKey: "boxcop.setup.notificationsAsked") else { return }
        defaults.set(true, forKey: "boxcop.setup.notificationsAsked")
        setNotifications(true)
    }
    func setActivityCollection(_ enabled: Bool) {
        updatingAdapterCollection {
            activityCollection = enabled
            defaults.set(enabled, forKey: preferencesKey + ".activityCollection")
        }
        collectionStatus = enabled ? "Activity collection starts automatically with monitoring." : "Activity collection is off."
        // A capture already underway must not be saved after the opt-out.
        if !enabled { visualTask?.cancel() }
        if running { setFrameCollection(enabled) } else { collectWindowFrames = enabled }
        restartAdditionalCollectors()
    }
    /// Starting or stopping the receiver follows the features that depend on it.
    private func updatingAdapterCollection(_ change: () -> Void) {
        let before = collectAdapters
        change()
        guard collectAdapters != before else { return }
        if collectAdapters { reviewBook.admitOnlyAfter() } else { withdrawReviewReminders(reason: "browser_receiving_off", record: true) }
        restartAdditionalCollectors()
    }
    private func applySetupWindowMode() {
        guard let window else { return }
        let setup = onboardingPresented && teamInvitation == nil
        if setup { window.styleMask.insert(.fullSizeContentView) } else { window.styleMask.remove(.fullSizeContentView) }
        window.titlebarAppearsTransparent = setup
        window.titleVisibility = setup ? .hidden : .visible
        window.minSize = setup ? NSSize(width: 720, height: 580) : NSSize(width: 780, height: 590)
        window.setContentSize(setup ? NSSize(width: 720, height: 580) : NSSize(width: 900, height: 680))
    }
    /// Recheck while open as well as on launch, including a return from System Settings.
    private func monitorSetupPermissions() {
        guard requiresMonitoringConsent, permissionCheckTask == nil, !CommandLine.arguments.contains(where: { $0.hasPrefix("--dev-") }) else { return }
        permissionCheckTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                await self.checkSetupPermissions()
                do { try await Task.sleep(nanoseconds: 1_000_000_000) } catch { return }
            }
        }
    }
    private func checkSetupPermissions() async {
        guard teamInvitation == nil && pendingTeamInvitation == nil else { return }
        let complete = defaults.bool(forKey: "boxcop.setup.complete")
        let pastWelcome = complete || SetupPage(storedStep: defaults.integer(forKey: "boxcop.setup.step")) != .welcome
        // Settings and Connections can turn things on before setup has started.
        guard pastWelcome || choices.monitoring || networkConnections.filterEnabled else { return }
        if releaseProfile.usesStandaloneNetworkProtection && Date().timeIntervalSince(lastNetworkSetupCheck) >= 5 {
            await networkConnections.refresh()
            await importNetworkWorkflow()
            lastNetworkSetupCheck = Date()
        }
        networkSetupRequired = wantsNetworkProtection && !networkConnections.setupReady
        updateWorkflowContext()
        guard !Task.isCancelled else { return }
        // Asked once, when the first protection is really on, even if setup has since closed.
        if anyProtectionOn { requestNotificationsAfterFirstProtection() }
        let accessibility = ShortcutTap.accessibilityGranted, screen = CGPreflightScreenCaptureAccess()
        // Warnings turned on from Connections count once they have what they need.
        if choices.monitoring && backgroundScreenEnabled && screen { defaults.set(true, forKey: "boxcop.setup.screen") }
        let wantsPaste = choices.monitoring && choices.guardShortcut
        let wantsScreen = choices.monitoring && backgroundScreenEnabled && defaults.bool(forKey: "boxcop.setup.screen")
        let missing = SetupRequirements.missing(wantsNetwork: wantsNetworkProtection, wantsPaste: wantsPaste, wantsScreen: wantsScreen,
                                                screenNeedsAccessibility: defaults.bool(forKey: "boxcop.setup.screenNeedsAccessibility"),
                                                network: networkConnections.approved, accessibility: accessibility, screenRecording: screen)
        // During setup the row is already on screen. Afterward a lost approval brings the list back.
        if complete, let missing, missing != lastMissingPermission {
            defaults.set(SetupPage.protections.rawValue, forKey: "boxcop.setup.step")
            onboardingPresented = true
            showWindow()
        }
        let newlyGranted = (accessibility && !lastAccessibility) || (screen && !lastScreenRecording)
        lastAccessibility = accessibility; lastScreenRecording = screen
        let screenReady = wantsScreen && SetupRequirements.nextForScreen(accessibility: accessibility, screenRecording: screen) == nil
        let needsSession = (wantsPaste && accessibility) || screenReady || packageSetupPending || defaults.bool(forKey: "boxcop.setup.packagesRouted")
        if running {
            // The engine is up, so a click in setup has been answered.
            if setupStartRequested { setupStartRequested = false }
            if newlyGranted { startSetupSession() }
        } else if choices.monitoring && (needsSession || (complete && missing == nil)) {
            startAfterSetupPermissions()
        }
        lastMissingPermission = missing
    }
    func setMonitoringConsent(_ enabled: Bool) {
        choices.monitoring = enabled; saveChoices()
        refreshLoginStatus()
        if !enabled { pause() }
    }
    func setGuardConsent(_ enabled: Bool) {
        guard applyingTeamPolicy || teamConnection.state.settings["guard_shortcut"] == nil else { return }
        if applyingTeamPolicy && choices.guardShortcut == enabled { return }
        if enabled && !choices.guardShortcut && !activityCollection && running { monitor.rebaseline(revision: NSPasteboard.general.changeCount) }
        choices.guardShortcut = enabled
        if !applyingTeamPolicy { saveChoices(); defaults.set(enabled, forKey: "boxcop.setup.accessibility") }
        disableGuard()
        if enabled && running { enableGuard() }
    }
    func setRole(_ role: Role) {
        guard role != choices.role else { return }
        choices.role = role; saveChoices()
        if running || starting || recovering { pause(); engineStatus = "Role changed. Start a new collection session." }
    }
    /// Separate explicit opt-in. Monitoring consent is still required for any automatic start.
    func setAutoStart(_ enabled: Bool) { choices.autoStart = enabled; saveChoices(); refreshLoginStatus() }
    /// Called once after the single-owner lock is held: checks setup and installs lifecycle observers.
    func activateLifecycle() {
        productSupport.activate()
        Task { await networkConnections.upgradeInstalledExtension() }
        teamConnection.policyChanged = { [weak self] in self?.applyTeamPolicy() }
        Task { [weak self] in
            guard let self else { return }
            await teamConnection.start()
            activateLocalLifecycle()
            presentPendingTeamInvitation()
        }
    }
    private func applyTeamPolicy() {
        applyingTeamPolicy = true
        defer { applyingTeamPolicy = false }
        let settings = teamConnection.state.settings
        let saved = defaults.data(forKey: preferencesKey).flatMap { try? JSONDecoder().decode(ConsentChoices.self, from: $0) }
        setGuardConsent(settings["guard_shortcut"] ?? saved?.guardShortcut ?? developmentMode)
        setWorkflowReviewEnabled(settings["workflow_review"] ?? (defaults.object(forKey: "boxcop.workflowReview.enabled") as? Bool ?? false))
        setBackgroundScreenMonitoring(settings["background_screen"] ?? (defaults.object(forKey: preferencesKey + ".backgroundScreenWarnings") as? Bool ?? true))
        setBackgroundScreenFullScreen(settings["screen_cover"] ?? (defaults.object(forKey: preferencesKey + ".backgroundScreenFullScreen") as? Bool ?? true))
        objectWillChange.send()
    }
    private func activateLocalLifecycle() {
        ownsSession = true
        onboardingPresented = pendingTeamInvitation == nil && requiresMonitoringConsent && !defaults.bool(forKey: "boxcop.setup.complete") && !CommandLine.arguments.contains(where: { $0.hasPrefix("--dev-") })
        // Upgrade existing installations to automatic startup once. Subsequent
        // explicit changes to the setting and pauses within a session are honored.
        if requiresMonitoringConsent && !defaults.bool(forKey: "boxcop.setup.automaticStartupMigrated") {
            setAutoStart(true)
            defaults.set(true, forKey: "boxcop.setup.automaticStartupMigrated")
        }
        monitorSetupPermissions()
        startSoftwareInventory()
        refreshReviewNotificationState()
        startApprovalWatcher()
        do {
            let autoInstall = developmentMode
            hostAgentTask = Task { [weak self] in
                var first = autoInstall
                while !Task.isCancelled {
                    let status = await HostAgents.refresh(install: first)
                    self?.hostAgentStatus = status.summary
                    self?.agentConnections = status.connections
                    first = false
                    try? await Task.sleep(nanoseconds: 15_000_000_000)
                }
            }
        }
        if sleepObserver == nil {
            sleepObserver = NSWorkspace.shared.notificationCenter.addObserver(forName: NSWorkspace.willSleepNotification, object: nil, queue: .main) { [weak self] _ in
                Task { @MainActor [weak self] in self?.sleepPause() }
            }
        }
        if wakeObserver == nil {
            wakeObserver = NSWorkspace.shared.notificationCenter.addObserver(forName: NSWorkspace.didWakeNotification, object: nil, queue: .main) { [weak self] _ in
                Task { @MainActor [weak self] in self?.handleWake() }
            }
        }
        // Auto-start is visible in the menu bar; otherwise first-run/setup opens the window.
        if developmentMode || ProcessInfo.processInfo.environment["BOXCOP_DEV_LOG"] == "1" { setDevelopmentLogging(true) }
        if CommandLine.arguments.contains("--dev-es-lifecycle-test") {
            showWindow()
            Task { @MainActor in
                func serviceState() async -> String? {
                    let reply = await EndpointSecurityControl.send("status")
                    guard let bytes = reply.data(using: .utf8), let row = (try? JSONSerialization.jsonObject(with: bytes)) as? [String: Any] else { return nil }
                    return row["state"] as? String
                }
                var checks: [String: Bool] = [:]
                for action in ["start", "pause", "resume"] {
                    if action == "pause" { pause(); await stopTask?.value }
                    else {
                        start()
                        for _ in 0..<250 {
                            if !starting { break }
                            try? await Task.sleep(nanoseconds: 100_000_000)
                        }
                    }
                    // The serial control queue makes this status request a barrier.
                    checks[action] = await serviceState() == (action == "pause" ? "paused" : "running")
                }
                let status = checks.count == 3 && checks.values.allSatisfy { $0 } ? "PASS" : "FAIL"
                let args = CommandLine.arguments
                if let i = args.firstIndex(of: "--dev-report"), args.count > i + 1, args[i + 1].hasPrefix("/") {
                    let url = URL(fileURLWithPath: args[i + 1])
                    if let data = try? JSONSerialization.data(withJSONObject: ["status": status, "checks": checks, "synthetic": true], options: [.sortedKeys]) {
                        try? data.write(to: url, options: .atomic)
                        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
                    }
                }
                collectionStatus = "Endpoint Security app lifecycle test: " + status
            }
        } else if CommandLine.arguments.contains("--dev-request-permissions") {
            showWindow(); beginPermissionSetup()
        } else if CommandLine.arguments.contains("--dev-protected-presentation-test") {
            let args = CommandLine.arguments
            if let i = args.firstIndex(of: "--dev-report"), args.count > i + 1, args[i + 1].hasPrefix("/") {
                Task { @MainActor in
                    self.collectionStatus = await ProtectedPresentationSelfTest.run(report: URL(fileURLWithPath: args[i + 1]))
                }
            }
        } else if CommandLine.arguments.contains("--dev-visual-test") {
            let args = CommandLine.arguments
            let report: URL
            if let i = args.firstIndex(of: "--dev-report"), args.count > i + 1, args[i + 1].hasPrefix("/") {
                report = URL(fileURLWithPath: args[i + 1])
            } else { report = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/BoxCop/visual-test.json") }
            Task { @MainActor in
                self.collectionStatus = await VisualSelfTest.run(report: report)
                self.showWindow()
            }
        } else if CommandLine.arguments.contains("--dev-collection-test") {
            let args = CommandLine.arguments
            let report: URL
            if let i = args.firstIndex(of: "--dev-report"), args.count > i + 1, args[i + 1].hasPrefix("/") {
                report = URL(fileURLWithPath: args[i + 1])
            } else { report = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/BoxCop/collection-test.json") }
            setDevelopmentLogging(true)
            collectionSelfTest = CollectionSelfTest(report: report) { [weak self] result in
                self?.collectionStatus = result; self?.collectionSelfTest = nil; self?.showWindow()
            }
            collectionSelfTest?.start()
        } else if CommandLine.arguments.contains("--dev-paste-test") {
            let args = CommandLine.arguments
            let report: URL?
            if let i = args.firstIndex(of: "--dev-report"), args.count > i + 1, args[i + 1].hasPrefix("/") {
                report = URL(fileURLWithPath: args[i + 1])
            } else { report = nil }
            runPasteSelfTest(reportURL: report)
        } else if !requiresMonitoringConsent && choices.startsAutomatically { start(); showWindow(); if developmentMode { beginPermissionSetup() } } else { showWindow() }
    }
    func runPasteSelfTest(reportURL: URL? = nil) {
        guard !pasteTestStarting, pasteSelfTest == nil else { return }
        setDevelopmentLogging(true)
        let report = reportURL ?? FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("BoxCop/paste-test.json")
        pasteTestStarting = true
        pasteTestStatus = "Preparing the in-app paste test…"
        // Explicit dev invocation can start an already-consented session, never grant consent or TCC.
        if canStart { start() }
        Task { [weak self] in
            guard let self else { return }
            for _ in 0..<250 {
                if !starting { break }
                try? await Task.sleep(nanoseconds: 100_000_000)
            }
            pasteTestStarting = false
            let test = PasteSelfTest(reportURL: report, guardReady: { [weak self] in
                self?.running == true && self?.guardActive == true
            }, completion: { [weak self] result in
                self?.pasteTestStatus = result
                self?.diagnostic("dev_paste_test_finished")
                self?.pasteSelfTest = nil
                self?.showWindow()
            })
            pasteSelfTest = test
            test.start()
        }
    }
    func setDevelopmentLogging(_ enabled: Bool) {
        developmentLogging = enabled
        if enabled, let directory = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first {
            let path = directory.appendingPathComponent("BoxCop/development.jsonl")
            developmentLog = DevelopmentLog(url: path)
            developmentStatus = "Logging encrypted timing, guard transitions and process IDs to " + path.path + ". No clipboard text or window titles. Bounded to 1 MiB; oldest entries are discarded at the limit."
            diagnostic("logging_enabled")
        } else { developmentLog = nil; developmentStatus = "Development logging off. Existing log remains on disk." }
    }
    private func diagnostic(_ event: String, key: SnapshotKey? = nil, ticket: UUID? = nil, decision: String? = nil) {
        developmentLog?.write(GuardDiagnostic(event: event, snapshot: key, ticket: ticket, decision: decision))
    }
    func showWindow(page: EndpointPage? = nil) {
        if let page { selectedPage = page }
        if window == nil {
            let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 900, height: 680), styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
            window.title = "BoxCop"
            window.minSize = NSSize(width: 780, height: 590)
            window.contentView = NSHostingView(rootView: EndpointView(model: self))
            window.isReleasedWhenClosed = false
            window.center(); self.window = window
            applySetupWindowMode(); window.center()
            // The menu bar icon can be hidden (notch overflow, or "Allow in the Menu Bar" off), so while
            // this window is open BoxCop also lives in the Dock and app switcher, and leaves them on close.
            NotificationCenter.default.addObserver(forName: NSWindow.willCloseNotification, object: window, queue: .main) { _ in
                MainActor.assumeIsolated { _ = NSApp.setActivationPolicy(.accessory) }
            }
        }
        _ = NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
        window?.makeKeyAndOrderFront(nil)
    }
    func packageProtection(_ action: PackageProtectionAction) async throws -> PackageProtectionStatus {
        guard let client, running else { throw EngineFailure.notReady }
        // Routed installs need the engine after a relaunch. Opting out ends any queued setup request.
        if action == .enable { defaults.set(true, forKey: "boxcop.setup.packagesRouted") }
        if action == .disable { defaults.set(false, forKey: "boxcop.setup.packagesRouted"); clearPackageSetupPending() }
        guard case let .packageProtection(value) = try await client.request(.packageProtection(action)) else {
            throw EngineFailure.protocolViolation
        }
        return value
    }

    @discardableResult
    func scriptProtection(_ action: ScriptProtectionAction, package: String = "", host: String = "") async throws -> ScriptProtectionStatus {
        guard let client, running else { throw EngineFailure.notReady }
        guard case let .scriptProtection(value) = try await client.request(.scriptProtection(action, package: package, host: host)) else {
            throw EngineFailure.protocolViolation
        }
        scriptProtectionStatus = value
        announceScriptBlocks(value.blocked)
        return value
    }
    /// The first status request resumes routing the user enabled earlier; later ones surface new blocks.
    private func watchScriptProtection() {
        scriptWatchTask?.cancel()
        scriptWatchTask = Task { [weak self] in
            while let self, self.running, !Task.isCancelled {
                _ = try? await self.scriptProtection(.status)
                do { try await Task.sleep(nanoseconds: 3_000_000_000) } catch { return }
            }
            self?.scriptProtectionStatus = nil
        }
    }
    private func announceScriptBlocks(_ blocked: [BlockedScriptConnection]) {
        // Newest first. One panel per refused package/destination, never a replay of older rows.
        guard let item = blocked.first(where: { !announcedScriptBlocks.contains($0.id) }) else { return }
        announcedScriptBlocks.formUnion(blocked.map(\.id))
        let allow: (() -> Void)? = item.package.map { package in
            { [weak self] in
                self?.scriptNotice.dismiss()
                Task { try? await self?.scriptProtection(.allow, package: package, host: item.host) }
            }
        }
        scriptNotice.show(title: "Suspicious connection blocked", message: item.message + (allow == nil ? "" : " Allowing applies to this package and destination only; run the install again afterwards."),
                          actionTitle: "Allow for this package", allow: allow)
    }

    func start() { startMonitoring(automaticRecovery: false) }
    private func startMonitoring(automaticRecovery: Bool) {
        guard canStart else { return }
        recoveryTask?.cancel(); recoveryTask = nil; recovering = false
        if !automaticRecovery { recovery = MonitoringRecovery() }
        reviewBook.admitOnlyAfter()
        epoch &+= 1; let expectedEpoch = epoch
        let engine = EngineClient(onFailure: { [weak self] failure in
            Task { @MainActor [weak self] in
                guard let self, self.epoch == expectedEpoch else { return }
                self.failEngine(failure)
            }
        })
        client = engine
        starting = true; errorMessage = nil
        engineStatus = "Starting local checks…"
        startup = Task { [weak self] in
            guard let self else { return }
            do {
                guard let directory = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else { throw EngineFailure.invalidConfiguration }
                let configuration = try EngineConfiguration.resolve(bundleURL: Bundle.main.bundleURL,
                    environment: ProcessInfo.processInfo.environment, dataDirectory: directory.appendingPathComponent("BoxCop", isDirectory: true))
                try await engine.start(configuration: configuration)
                guard !Task.isCancelled, epoch == expectedEpoch, choices.monitoring else { await engine.stop(); return }
                let state = await engine.snapshot()
                guard state.ready else { throw EngineFailure.notReady }
                // Baseline only: no string read on Start or Resume.
                monitor.start(consent: true, baselineRevision: NSPasteboard.general.changeCount)
                diagnostic("monitor_started_baseline", key: liveSnapshot())
                clipboardReader.activate(generation: monitor.generation)
                starting = false; running = true; startup = nil
                recovery.started(at: ProcessInfo.processInfo.systemUptime)
                monitoringLogger.info("Monitoring started")
                controlEndpointSecurity("resume")
                engineStatus = "Local checks are ready."
                // Restore explicitly enabled package routing in this app-owned engine.
                _ = try? await engine.request(.packageProtection(.status))
                watchScriptProtection()
                guard !Task.isCancelled, epoch == expectedEpoch, running else { return }
                sendPendingPackageEnable()
                clipboardStatus = ClipboardUnsupported.baseline.message
                if (developmentMode || requiresMonitoringConsent) && workflowJournal == nil {
                    do {
                        let journal = try WorkflowJournal(directory: directory.appendingPathComponent("BoxCop/workflows", isDirectory: true))
                        workflowJournal = journal
                        workflow.onAppend = { event in journal.append(event) }
                        journalStatus = "Saving encrypted workflow events locally · up to 64 MiB retained."
                    } catch { journalStatus = "Workflow persistence unavailable; events are in memory only." }
                }
                clearWorkflow(); browserContexts.removeAll(); lastBrowserEventAt = nil
                workflow.append(kind: "collector_health", collector: "EndpointSecurity", availability: releaseProfile.usesEndpointSecurity ? EndpointSecurityProbe.status() : "deferred_beta", fields: [
                    "coverage": WorkflowField("System-wide file access and process execution are not subscribed.")])
                lastWindowSignature = nil
                updateFrontmost()
                collectors.start(onActivation: { [weak self] _, _ in
                    guard let self, self.monitor.running else { return }
                    self.diagnostic("app_activation_invalidated_gate", key: self.liveSnapshot())
                    self.gate.invalidate()
                    self.clearPasteIntervention()
                    self.updateFrontmost()
                    self.tick()
                }, onLifecycle: { [weak self] kind, bundle, pid in
                    guard let self, self.monitor.running, self.activityCollection else { return }
                    self.workflow.append(kind: kind, collector: "NSWorkspace", bundleID: bundle, pid: pid,
                                         availability: bundle == nil ? "missing_app_identity" : "available")
                }, onTick: { [weak self] in self?.tick() })
                restartAdditionalCollectors()
                restartBackgroundScreenMonitoring()
                if choices.guardShortcut { enableGuard() }
                if screenShareEnabled || CommandLine.arguments.contains("--dev-screen-share-guard") { setScreenSharePreflight(true) }
                await loadHistory(engine: engine, expectedEpoch: expectedEpoch)
            } catch {
                guard epoch == expectedEpoch else { return }
                failEngine((error as? EngineFailure) ?? .launchFailed)
            }
        }
    }
    /// User pause, consent revocation, role change or quit: cancels any pending wake resume.
    func pause() { setupStartAttempted = true; sleepResume.userStopped(); recovery = MonitoringRecovery(); halt() }
    /// System sleep stops like a pause; wake resumes this session once if it was active and consent remains.
    private func sleepPause() {
        let wasActive = running || starting || recovering
        halt()
        sleepResume.sleep(wasRunning: wasActive)
        if wasActive { engineStatus = "Paused for system sleep. Resumes after wake while consent remains." }
    }
    private func handleWake() {
        guard sleepResume.wake(consent: choices.monitoring) else { return }
        let pendingStop = stopTask, resumeEpoch = epoch
        Task { @MainActor [weak self] in
            await pendingStop?.value
            // Any pause/start in the meantime changes the epoch and wins over this resume.
            guard let self, self.epoch == resumeEpoch, self.choices.monitoring else { return }
            self.start()
        }
    }
    /// Synchronous invalidation first; owned child termination is asynchronous.
    private func halt() {
        closeActionableAlerts()
        recoveryTask?.cancel(); recoveryTask = nil; recovering = false
        epoch &+= 1
        clearPDFReview()
        clearCodeVerification()
        withdrawReviewReminders(reason: "monitoring_paused", record: false)
        workflowReviewer.clear(); clearEmailReviewCache(); recordedEmailReviews.removeAll(); recordedEmailAnnotations.removeAll(); workflowJudgment = nil
        stopPresentation()
        backgroundScreenMonitor?.stop(); backgroundScreenMonitor = nil
        backgroundScreenStatus = backgroundScreenEnabled ? "Screen checks paused. Resume monitoring to start." : "Background screen warnings are off."
        setFrameCollection(false)
        collectWindowFrames = activityCollection
        lastExternalApp = nil
        controlEndpointSecurity("pause")
        startup?.cancel(); startup = nil
        collectors.stop(); clipboardReader.stop(); monitor.pause()
        extraCollectorGeneration &+= 1
        clickCollector.stop(); fileCollector.stop(); adapterTransport.stop(); draftAdmission.reset()
        diagnostic("additional_collectors_stopped")
        visualTask?.cancel()
        screenShareGuard?.stop(); screenShareGuard = nil; screenShareActive = false
        screenShareStatus = "Screen-share preflight is off."
        lastContextEvent = nil
        windowGeneration &+= 1
        windowTask?.cancel()
        lastWindowSignature = nil
        disableGuard(); unsupportedRevision = nil
        for task in work.values { task.cancel() }; work.removeAll()
        healthTask?.cancel(); healthTask = nil
        running = false; starting = false; frontmostBundle = nil; frontmostPID = nil
        engineStatus = "Stopped — no app or clipboard collection."
        clipboardStatus = "Clipboard content discarded. Resume baselines without reading existing text."
        let owned = client; client = nil
        if let owned {
            stopping = true
            let previousStop = stopTask
            stopTask = Task { [weak self] in
                await previousStop?.value
                await owned.stop()
                self?.stopping = false
            }
        }
    }
    func stopAndWait() async {
        productSupport.stop()
        workflowReviewer.stop()
        pause(); await stopTask?.value
        if releaseProfile.usesEndpointSecurity { _ = await EndpointSecurityControl.send("status") }
        await workflowJournal?.flush()
    }
    func retry() {
        if running && choices.guardShortcut {
            // A retry must discard failed reads and tickets even when the tap is healthy.
            diagnostic("explicit_guard_retry", key: liveSnapshot())
            unsupportedRevision = nil
            enableGuard()
            clipboardStatus = guardActive
                ? "Retry ready. Return to the destination and press Command-V to evaluate again. Copy new text if it predates Start."
                : "Paste protection is still unavailable. Check the live guard status and macOS permission controls; recheck does not grant permission."
            return
        }
        errorMessage = nil
        if canStart { start() }
    }
    private func failEngine(_ failure: EngineFailure) {
        setupStartAttempted = true
        let interruptedPaste = blockedPasteKey != nil
        let delay = recovery.nextDelay(for: failure, at: ProcessInfo.processInfo.systemUptime)
        sleepResume.userStopped()
        halt()
        monitoringLogger.error("Monitoring failed: \(failure.rawValue, privacy: .public)")
        diagnostic("engine_failed_" + failure.rawValue)
        if interruptedPaste {
            systemNotice.show(title: "Paste stopped", message: "BoxCop couldn’t finish checking your paste and paused protection. Try pasting again once monitoring resumes. Open BoxCop to check its status.", actionTitle: "Open BoxCop", allow: { [weak self] in
                self?.systemNotice.dismiss()
                self?.showWindow(page: .protection)
            })
        }
        errorMessage = failure.description
        engineStatus = "Monitoring stopped because local checks failed. Retry to resume."
        guard let delay, choices.monitoring, ownsSession else { return }
        recovering = true
        engineStatus = "Local checks stopped. Restarting automatically in \(Int(delay)) seconds…"
        monitoringLogger.info("Restart scheduled in \(Int(delay)) seconds")
        let expectedEpoch = epoch, pendingStop = stopTask
        recoveryTask = Task { @MainActor [weak self] in
            do { try await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000)) }
            catch { return }
            await pendingStop?.value
            guard !Task.isCancelled, let self, self.epoch == expectedEpoch else { return }
            self.recoveryTask = nil; self.recovering = false
            guard self.canStart else { return }
            self.startMonitoring(automaticRecovery: true)
        }
    }
    private func disableGuard() {
        diagnostic("guard_stopped")
        pasteRecovery = PasteProtectionRecovery()
        gate.stop(); tap?.stop(); tap = nil; guardActive = false
        clearPasteIntervention()
        guardStatus = "Paste protection is off."
    }
    private func enableGuard(automaticRecovery: Bool = false) {
        let previousRecovery = pasteRecovery
        disableGuard()
        if automaticRecovery { pasteRecovery = previousRecovery }
        monitoringLogger.notice("Paste protection start requested: automatic=\(automaticRecovery)")
        guard running, choices.monitoring, choices.guardShortcut else { return }
        guard ShortcutTap.accessibilityGranted else {
            monitoringLogger.error("Paste protection unavailable: accessibility_missing")
            schedulePasteRecovery()
            guardStatus = "Paste protection needs Accessibility access. Enable BoxCop in System Settings → Privacy & Security → Accessibility, then retry."
            return
        }
        let tap = ShortcutTap(shortcut: { [weak self] repeatKey in self?.shortcut(repeatKey: repeatKey) ?? true }, coverageLost: { [weak self] message in
            guard let self else { return }
            self.gate.stop(); self.guardActive = false
            self.schedulePasteRecovery()
            // Defer observable UI work until after the event callback returns.
            self.deferGuardStatus(message)
        })
        self.tap = tap
        guard tap.start() else {
            tap.stop(); self.tap = nil
            schedulePasteRecovery()
            guardStatus = "Paste protection could not start. Check Accessibility access and retry."
            return
        }
        gate.start(generation: monitor.generation); guardActive = true
        pasteRecovery.started(at: ProcessInfo.processInfo.systemUptime)
        monitoringLogger.notice("Paste protection restored: automatic=\(automaticRecovery)")
        diagnostic("guard_started", key: liveSnapshot())
        guardStatus = "Paste protection is on for supported keyboard shortcuts. Pasting from menus is not checked."
    }
    private func schedulePasteRecovery() {
        let delay = pasteRecovery.failed(at: ProcessInfo.processInfo.systemUptime)
        monitoringLogger.notice("Paste protection retry scheduled: delay=\(Int(delay)) seconds; waits for Accessibility and Secure Input")
    }
    private var permissionSetup: Task<Void, Never>?
    /// Present one permission at a time from the installed GUI app, never from a helper.
    private func beginPermissionSetup() {
        guard permissionSetup == nil else { return }
        permissionSetup = Task { @MainActor [weak self] in
            guard let self else { return }
            defer { permissionSetup = nil }
            if !ShortcutTap.accessibilityGranted {
                collectionStatus = "Allow BoxCop in the Accessibility settings that just opened. Screen Recording comes next."
                requestAccessibility()
                while !ShortcutTap.accessibilityGranted {
                    do { try await Task.sleep(nanoseconds: 1_000_000_000) } catch { return }
                }
            }
            if running && choices.guardShortcut && !guardActive { enableGuard() }
            if !CGPreflightScreenCaptureAccess() {
                collectionStatus = "Allow BoxCop in Screen Recording. If macOS asks, choose Quit & Reopen."
                requestScreenRecording()
                while !CGPreflightScreenCaptureAccess() {
                    do { try await Task.sleep(nanoseconds: 1_000_000_000) } catch { return }
                }
            }
            collectionStatus = "Accessibility and Screen Recording are granted."
        }
    }
    func requestAccessibility() {
        guard !ShortcutTap.accessibilityGranted else { return }
        ShortcutTap.requestAccessibility()
        openPrivacySettings("Privacy_Accessibility")
    }
    private func openPrivacySettings(_ pane: String) {
        if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?" + pane) {
            NSWorkspace.shared.open(url)
        }
    }
    func revealBundledResource(_ name: String) {
        let url = Bundle.main.bundleURL.appendingPathComponent("Contents/Resources").appendingPathComponent(name)
        guard FileManager.default.fileExists(atPath: url.path) else {
            browserSetupStatus = "Resource missing. Install a complete packaged BoxCop.app."; return
        }
        NSWorkspace.shared.activateFileViewerSelecting([url])
    }
    func repairAgentHooks(remove: Bool = false, recheck: Bool = false) {
        guard !agentRepairBusy else { return }
        agentRepairBusy = true
        Task {
            let status = await HostAgents.refresh(install: !recheck, remove: remove, explicit: true)
            hostAgentStatus = status.summary
            agentConnections = status.connections
            agentRepairBusy = false
            // Agents can be connected from Connections, where the setup check may not be running yet.
            if anyProtectionOn && requiresMonitoringConsent { requestNotificationsAfterFirstProtection() }
        }
    }
    func installBrowserHost(extensionID: String) {
        do {
            try BrowserHostInstaller.install(extensionID: extensionID.trimmingCharacters(in: .whitespacesAndNewlines), appURL: Bundle.main.bundleURL)
            updatingAdapterCollection {
                browserConnected = true
                defaults.set(true, forKey: preferencesKey + ".browserConnected")
            }
            browserSetupStatus = "Bridge registered. Reload the extension and an HTTP(S) tab; wait for a browser event below."
        } catch { browserSetupStatus = "Browser setup failed. Use the 32-letter extension ID shown by Chrome/Chromium, and an installed BoxCop.app." }
    }
    func setFrameCollection(_ enabled: Bool) {
        collectWindowFrames = enabled
        frameTask?.cancel()
        let expectedEpoch = epoch
        frameTask = Task { [weak self] in
            guard let self else { return }
            await frameCollector.stop()
            guard enabled, !Task.isCancelled, running, epoch == expectedEpoch,
                  let (bundle, pid) = lastExternalApp,
                  NSRunningApplication(processIdentifier: pid)?.bundleIdentifier == bundle,
                  ClipboardPolicy.preflight(types: ["public.utf8-plain-text"], bundleID: bundle) != .passwordManager else {
                if enabled && !Task.isCancelled { collectionStatus = "Focus an external app before starting window observation." }
                return
            }
            await frameCollector.start(pid: pid) { [weak self] availability, fields in
                guard let self, self.running, self.collectWindowFrames, self.epoch == expectedEpoch else { return }
                self.workflow.append(kind: "window_frame", collector: "ScreenCaptureKit.stream", bundleID: bundle, pid: pid,
                                     availability: availability, fields: fields)
                self.collectionStatus = "Window observation: " + availability + ". This does not protect outgoing shares."
            }
        }
    }
    func requestScreenRecording() {
        guard !CGPreflightScreenCaptureAccess() else { return }
        NSApp.activate(ignoringOtherApps: true)
        if !CGRequestScreenCaptureAccess() { openPrivacySettings("Privacy_ScreenCapture") }
    }
    private func restartAdditionalCollectors() {
        extraCollectorGeneration &+= 1
        clickCollector.stop(); fileCollector.stop(); adapterTransport.stop(); draftAdmission.reset()
        diagnostic("additional_collectors_stopped")
        guard running else { return }
        let expectedEpoch = epoch, expectedGeneration = extraCollectorGeneration
        if collectClicks || collectPointerMotion {
            clickCollector.start(includeMotion: collectPointerMotion) { [weak self] observation in
                let pid = observation.pid, bundle = observation.bundleID
                guard let self, self.running, (self.collectClicks || self.collectPointerMotion), self.epoch == expectedEpoch, self.extraCollectorGeneration == expectedGeneration else { return }
                if ClipboardPolicy.preflight(types: ["public.utf8-plain-text"], bundleID: bundle) == .passwordManager { return }
                guard observation.kind != "mouse_click" || self.collectClicks else { return }
                self.workflow.append(kind: observation.kind, collector: "NSEvent.pointer", bundleID: bundle, pid: pid,
                    fields: observation.fields,
                    relatedEventIDs: self.lastContextEvent.map { [$0] } ?? [])
            }
        }
        if let root = fileWatchRoot {
            let ok = fileCollector.start(root: root) { [weak self] path, flags, identifier in
                guard let self, self.running, self.epoch == expectedEpoch, self.extraCollectorGeneration == expectedGeneration, self.fileWatchRoot == root else { return }
                let observedPath = URL(fileURLWithPath: path).resolvingSymlinksInPath().path
                let watchedPath = root.resolvingSymlinksInPath().path
                // Exclude our own journal/log/capture writes to prevent a collection feedback loop.
                let ownSupport = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/BoxCop").resolvingSymlinksInPath().path
                guard observedPath != ownSupport, !observedPath.hasPrefix(ownSupport + "/") else { return }
                guard observedPath == watchedPath || observedPath.hasPrefix(watchedPath == "/" ? "/" : watchedPath + "/") else { return }
                self.workflow.append(kind: "file_change", collector: "FSEvents", availability: flags & 7 == 0 ? "available" : "gap_requires_rescan", fields: [
                    "path": WorkflowField(path), "flags": WorkflowField(String(flags)), "stream_event_id": WorkflowField(String(identifier)),
                    "responsible_process": WorkflowField(nil, provenance: "unknown", availability: "not_provided_by_api"),
                    "file_read": WorkflowField(nil, provenance: "unknown", availability: "not_observed")])
            }
            if !ok { workflow.append(kind: "collector_health", collector: "FSEvents", availability: "start_failed") }
        }
        if collectAdapters {
            do {
                try adapterTransport.start(path: CollectorBridge.socketPath, response: { [emailReviewCache] in emailReviewCache.response($0) }) { [weak self, draftAdmission] event in
                    // Taken on the receiving queue: a clear/pause/restart before the hop below rejects this frame.
                    let ticket = draftAdmission.ticket(receivedAt: event.receivedAt)
                    Task { @MainActor [weak self] in
                        guard let self, self.running, self.collectAdapters, self.epoch == expectedEpoch, self.extraCollectorGeneration == expectedGeneration else { return }
                        if event.kind == "browser_pdf_selected" && !self.pdfReviewEnabled { return }
                        self.diagnostic("adapter_received_" + event.kind)
                        if event.kind == "browser_email_draft" {
                            guard let observed = event.observedAt, Date().timeIntervalSince(observed) <= 30,
                                  observed.timeIntervalSince(Date()) <= 5 else { return }
                        }
                        if DraftEvidence.kinds.contains(event.kind) { self.draftAdmission.admit(event, ticket, into: &self.workflow); return }
                        if event.kind.hasPrefix("browser_") { self.lastBrowserEventAt = Date() }
                        if event.kind.hasPrefix("agent_") { self.lastAgentEventAt = Date() }
                        let contextKey: String? = {
                            guard let session = event.fields["browser_session"]?.value,
                                  let tab = event.fields["tab_id"]?.value,
                                  let document = event.fields["navigation_id"]?.value,
                                  let frame = event.fields["frame_id"]?.value else { return nil }
                            return session + "|" + tab + "|" + frame + "|" + document
                        }()
                        let related = contextKey.flatMap { self.browserContexts[$0] }.map { [$0] } ?? []
                        // Compositions report when the browser observed them; never later than arrival.
                        let eventID = self.workflow.append(kind: event.kind, collector: event.collector,
                                             at: event.observedAt.map { min($0, Date()) } ?? Date(), phase: event.phase,
                                             provenance: "reported", fields: event.fields, relatedEventIDs: related, receivedAt: event.receivedAt)
                        if event.kind == "browser_pdf_selected", let recorded = self.workflow.events.last,
                           recorded.id == eventID,
                           let selection = self.pdfReviewBook.observe(recorded) {
                            self.notifyPDFAttachmentSelection(selection)
                        }
                        // Reminder expiry may append derived events; consume the PDF observation first.
                        self.observeReviewEvidence(event, eventID: eventID)
                        if event.kind == "browser_context", let contextKey {
                            if self.browserContexts.count >= 128 { self.browserContexts.removeAll() }
                            self.browserContexts[contextKey] = eventID
                        }
                    }
                }
                diagnostic("adapter_receiver_started")
                collectionStatus = "Adapter receiver active: local same-user socket; events are reported, not authenticated identity."
            } catch { diagnostic("adapter_receiver_start_failed"); collectionStatus = "Adapter receiver could not start." }
        } else { collectionStatus = "Native collectors updated. Adapter receiver off." }
    }
    func captureLastWindow() {
        guard let (bundle, pid) = lastExternalApp else { collectionStatus = "Focus an external app first, then return here to capture its window."; return }
        captureWindow(bundle: bundle, pid: pid)
    }
    private func captureWindow(bundle: String, pid: Int32) {
        guard running, visualTask == nil, ProcessInfo.processInfo.systemUptime - lastCapture >= 10,
              NSRunningApplication(processIdentifier: pid)?.bundleIdentifier == bundle else { return }
        if ClipboardPolicy.preflight(types: ["public.utf8-plain-text"], bundleID: bundle) == .passwordManager { return }
        lastCapture = ProcessInfo.processInfo.systemUptime
        let expectedEpoch = epoch
        visualTask = Task { [weak self] in
            guard let self else { return }; defer { visualTask = nil }
            let result = await visualCollector.capture(pid: pid)
            guard !Task.isCancelled, running, epoch == expectedEpoch else { return }
            var fields = result.fields
            if let png = result.png {
                let recognition = await visualCollector.recognize(png)
                guard !Task.isCancelled, running, epoch == expectedEpoch else { return }
                fields["recognized_text"] = WorkflowField(recognition.text, provenance: "derived", availability: recognition.availability)
                fields["recognition_confidence"] = WorkflowField(recognition.confidence.map { String($0) }, provenance: "derived", availability: recognition.availability)
                fields.merge(recognition.geometryFields) { _, new in new }
                do {
                    let directory = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/BoxCop/captures")
                    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
                    let file = directory.appendingPathComponent("capture-" + UUID().uuidString + ".png")
                    try png.write(to: file, options: .atomic)
                    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
                    let files = try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: [.creationDateKey])
                        .filter { $0.lastPathComponent.hasPrefix("capture-") && $0.pathExtension == "png" }
                        .sorted { ((try? $0.resourceValues(forKeys: [.creationDateKey]).creationDate) ?? .distantPast) < ((try? $1.resourceValues(forKeys: [.creationDateKey]).creationDate) ?? .distantPast) }
                    for old in files.prefix(max(0, files.count - 20)) { try FileManager.default.removeItem(at: old) }
                    fields["artifact_path"] = WorkflowField(file.path)
                } catch { workflow.append(kind: "visual_context", collector: "ScreenCaptureKit.window", availability: "write_failed"); return }
            }
            workflow.append(kind: "visual_context", collector: "ScreenCaptureKit.window", bundleID: bundle, pid: pid, availability: result.availability, fields: fields)
            collectionStatus = "Window capture: " + result.availability
        }
    }
    func clearWorkflow() {
        closeActionableAlerts()
        clearPDFReview()
        clearCodeVerification()
        withdrawReviewReminders(reason: "live_view_cleared", record: false); lastCompositionAt = nil
        workflow.clear(); codeStartSequence = 0; draftAdmission.reset(); browserContexts.removeAll(); lastWindowSignature = nil; lastContextEvent = nil
        lastBrowserEventAt = nil; lastAgentEventAt = nil; lastProcessSnapshot = .distantPast
        networkWorkflow.clear(); workflowReviewer.clear(); clearEmailReviewCache(); recordedEmailReviews.removeAll(); recordedEmailAnnotations.removeAll(); workflowJudgment = nil
        workflowContextStatus = "Live context cleared. Saved history and captures are retained."
    }
    func setCodeVerificationEnabled(_ enabled: Bool) {
        updatingAdapterCollection { codeVerificationEnabled = enabled }
        defaults.set(enabled, forKey: "boxcop.codeVerification.enabled")
        clearCodeVerification()
    }
    private func clearCodeVerification() {
        codeGeneration = UUID()
        removeCodeNotifications(codeNotificationIDs)
        codeFindings = []; dismissedCodeFindings = []; codeRecorded = [:]
        codeStartSequence = workflow.events.last?.sequence ?? 0
        codeLastRevision = -1; codeLastUpdate = .distantPast
    }
    func dismissCodeFinding(_ finding: CodeVerificationFinding) {
        guard codeVerificationEnabled, running, !dismissedCodeFindings.contains(finding.id) else { return }
        dismissedCodeFindings.insert(finding.id)
        let notificationID = "boxcop-code-review-" + finding.id.uuidString
        if codeNotificationIDs.contains(notificationID) { removeCodeNotifications([notificationID]) }
        workflow.append(kind: "code_verification_dismissed", collector: "workflow.code_verification",
            fields: ["assessment_id": WorkflowField(finding.id.uuidString), "resolution": WorkflowField("dismissed_not_verified")],
            relatedEventIDs: [finding.id])
    }
    private func updateCodeVerification() {
        guard ownsSession, running, codeVerificationEnabled,
              Date().timeIntervalSince(codeLastUpdate) >= 3 else { return }
        codeLastUpdate = Date()
        let revision = workflow.events.last?.sequence ?? 0
        guard revision != codeLastRevision else { return }
        let eligible = workflow.events.filter { $0.sequence > codeStartSequence }
        let combined = CodeVerification.assess(eligible) + CodeReviewVersion.assess(eligible)
        let sequence = Dictionary(uniqueKeysWithValues: eligible.map { ($0.id, $0.sequence) })
        let findings = Array(combined.sorted { (sequence[$0.id] ?? 0) < (sequence[$1.id] ?? 0) }.suffix(16))
        codeFindings = findings
        let activeNotifications = Set(findings.filter { $0.alerts && !dismissedCodeFindings.contains($0.id) }.map { "boxcop-code-review-" + $0.id.uuidString })
        removeCodeNotifications(codeNotificationIDs.subtracting(activeNotifications))
        let retained = Set(findings.map(\.id))
        codeRecorded = codeRecorded.filter { retained.contains($0.key) }
        dismissedCodeFindings.formIntersection(retained)
        for finding in findings where codeRecorded[finding.id] != finding.outcome {
            codeRecorded[finding.id] = finding.outcome
            if finding.alerts && !dismissedCodeFindings.contains(finding.id) { notifyCodeVerification(finding) }
            workflow.append(kind: "code_verification_assessment", collector: "workflow.code_verification", provenance: "inferred",
                fields: ["assessment_id": WorkflowField(finding.id.uuidString), "outcome": WorkflowField(finding.outcome),
                    "alert_id": WorkflowField(finding.alertID), "rules_version": WorkflowField(finding.rulesVersion), "advisory_only": WorkflowField("true"),
                    "coverage": WorkflowField("cooperative_hooks_only")], relatedEventIDs: finding.eventIDs)
        }
        codeLastRevision = workflow.events.last?.sequence ?? 0
    }
    private func removeCodeNotifications(_ ids: Set<String>) {
        defer { refreshActionableAlerts() }
        guard !ids.isEmpty else { return }
        let center = UNUserNotificationCenter.current()
        center.removePendingNotificationRequests(withIdentifiers: Array(ids))
        center.removeDeliveredNotifications(withIdentifiers: Array(ids))
        codeNotificationIDs.subtract(ids)
    }
    private func notifyCodeVerification(_ finding: CodeVerificationFinding) {
        guard choices.notifications else { return }
        let token = codeGeneration, expectedEpoch = epoch
        let identifier = "boxcop-code-review-" + finding.id.uuidString
        codeNotificationIDs.insert(identifier)
        Task { @MainActor [weak self] in
            guard let self else { return }
            let settings = await UNUserNotificationCenter.current().notificationSettings()
            let allowed = settings.authorizationStatus == .authorized || settings.authorizationStatus == .provisional
            @MainActor func current() -> Bool {
                self.running && self.codeVerificationEnabled && self.choices.notifications && self.epoch == expectedEpoch &&
                self.codeGeneration == token && self.codeNotificationIDs.contains(identifier) &&
                !self.dismissedCodeFindings.contains(finding.id) && self.codeFindings.contains { $0.id == finding.id && $0.outcome == finding.outcome }
            }
            guard allowed, current() else { return }
            if await offerHeadsUp(.code, itemID: finding.id.uuidString + "|" + finding.outcome, settings: settings, stillCurrent: current) != .notUsed {
                if !current() { refreshActionableAlerts() }
                return
            }
            guard current() else { return }
            let content = UNMutableNotificationContent()
            content.title = finding.category == "review_version" ? "Review current PR changes" : "Review code checks"
            content.body = "A recent instrumented code action has failed or stale evidence. Open Activity to review it. The action was not blocked."
            try? await UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: identifier, content: content, trigger: nil))
            if !current() { self.removeCodeNotifications([identifier]) }
        }
    }
    func setPDFReviewEnabled(_ enabled: Bool) {
        updatingAdapterCollection { pdfReviewEnabled = enabled }
        defaults.set(enabled, forKey: "boxcop.pdfReview.enabled")
        if !enabled { clearPDFReview() }
    }
    private func clearPDFReview() {
        defer { refreshActionableAlerts() }
        pdfReviewGeneration = UUID(); pdfReviewBook.clear(); pdfPreview = nil
        pdfPreviewMessage = nil; pdfPreviewLoading = false
        let center = UNUserNotificationCenter.current()
        center.removePendingNotificationRequests(withIdentifiers: Array(pdfNotificationIDs))
        center.removeDeliveredNotifications(withIdentifiers: Array(pdfNotificationIDs))
        pdfNotificationIDs.removeAll()
    }
    func dismissPDFReminder(_ id: UUID) {
        defer { refreshActionableAlerts() }
        pdfReviewBook.dismiss(id)
        let identifier = "boxcop-pdf-review-" + id.uuidString
        UNUserNotificationCenter.current().removePendingNotificationRequests(withIdentifiers: [identifier])
        UNUserNotificationCenter.current().removeDeliveredNotifications(withIdentifiers: [identifier])
        pdfNotificationIDs.remove(identifier)
        workflow.append(kind: "pdf_review_dismissed", collector: "boxcop.pdf_review", fields: ["selection_id": WorkflowField(id.uuidString)])
    }
    func openPDFPreview(expected: PDFContentIdentity? = nil) {
        guard running, pdfReviewEnabled, !pdfPreviewLoading else { return }
        let generation = pdfReviewGeneration
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.pdf]; panel.allowsMultipleSelection = false; panel.canChooseDirectories = false
        panel.message = expected == nil ? "Choose a PDF to preview locally." : "Choose the selected attachment. BoxCop will check that the file contents match."
        guard panel.runModal() == .OK, let url = panel.url, running, pdfReviewEnabled,
              pdfReviewGeneration == generation else { return }
        pdfPreviewLoading = true; pdfPreviewMessage = nil
        Task { @MainActor [weak self] in
            do {
                let (snapshot, renderCheck) = try await Task.detached(priority: .userInitiated) {
                    let snapshot = try LocalPDFSnapshot.read(url)
                    if let expected, snapshot.identity != expected { throw PDFPreviewError.wrongFile }
                    return (snapshot, PDFRenderCheck.inspect(snapshot.data))
                }.value
                guard let self, self.pdfReviewGeneration == generation, self.pdfReviewEnabled, self.running else { return }
                defer { self.pdfPreviewLoading = false }
                if let expected, snapshot.identity != expected { throw PDFPreviewError.wrongFile }
                guard let document = PDFDocument(data: snapshot.data), !document.isLocked, document.pageCount > 0,
                      document.pageCount <= PDFReviewBook.maximumPages else { throw PDFPreviewError.unsupported }
                self.installPDFPreview(snapshot: snapshot, document: document, renderCheck: renderCheck, generation: generation)
            } catch {
                guard let self, self.pdfReviewGeneration == generation else { return }
                self.pdfPreviewLoading = false
                self.pdfPreviewMessage = (error as? PDFPreviewError) == .wrongFile
                    ? "Those file contents do not match the selected attachment. No preview was credited. Choose the intended file."
                    : "This PDF could not be previewed. Choose an unlocked PDF up to 16 MB and 2,000 pages."
            }
        }
    }
    private func installPDFPreview(snapshot: LocalPDFSnapshot, document: PDFDocument,
                                   renderCheck: PDFRenderCheck?, generation: UUID) {
        guard running, pdfReviewEnabled, pdfReviewGeneration == generation else { return }
        self.pdfPreview = LocalPDFPreview(snapshot: snapshot, document: document, renderCheck: renderCheck)
        self.workflow.append(kind: "pdf_render_check", collector: "boxcop.pdf_review", fields: [
            "artifact_sha256": WorkflowField(snapshot.identity.sha256),
            "file_size": WorkflowField(String(snapshot.identity.byteCount)),
            "rules_version": WorkflowField(PDFRenderCheck.version),
            "page_count": WorkflowField(String(document.pageCount)),
            "scanned_pages": WorkflowField(String(renderCheck?.scannedPages ?? 0)),
            "unknown_pages": WorkflowField(String(renderCheck?.unknownPages ?? document.pageCount)),
            "potentially_blank_pages": WorkflowField((renderCheck?.potentiallyBlankPages ?? []).map { String($0 + 1) }.joined(separator: ",")),
            "assessment": WorkflowField(renderCheck == nil ? "unavailable" : "heuristic_not_verification")])
    }
    func recordPDFPage(previewID: UUID, page: Int) {
        guard running, pdfReviewEnabled, let preview = pdfPreview, preview.id == previewID else { return }
        if let prior = pdfReviewBook.previews[preview.snapshot.identity], prior.pages.contains(page),
           Date().timeIntervalSince(prior.updatedAt) <= PDFReviewBook.retention { return }
        guard pdfReviewBook.displayed(identity: preview.snapshot.identity, filename: preview.snapshot.filename,
                  pageCount: preview.document.pageCount, pages: [page]) else { return }
        workflow.append(kind: "pdf_page_displayed", collector: "boxcop.pdf_review", fields: [
            "artifact_sha256": WorkflowField(preview.snapshot.identity.sha256),
            "file_size": WorkflowField(String(preview.snapshot.identity.byteCount)),
            "page_index": WorkflowField(String(page)), "page_count": WorkflowField(String(preview.document.pageCount))])
        let resolved = pdfReviewBook.selections.filter { !pdfReviewBook.status(for: $0).needsReminder }
            .map { "boxcop-pdf-review-" + $0.id.uuidString }
        if !resolved.isEmpty {
            UNUserNotificationCenter.current().removePendingNotificationRequests(withIdentifiers: resolved)
            UNUserNotificationCenter.current().removeDeliveredNotifications(withIdentifiers: resolved)
        }
        pdfNotificationIDs.subtract(resolved)
    }
    private func notifyPDFAttachmentSelection(_ selection: PDFAttachmentSelection) {
        let retained = Set(pdfReviewBook.selections.map { "boxcop-pdf-review-" + $0.id.uuidString })
        let expired = Array(pdfNotificationIDs.subtracting(retained))
        UNUserNotificationCenter.current().removePendingNotificationRequests(withIdentifiers: expired)
        UNUserNotificationCenter.current().removeDeliveredNotifications(withIdentifiers: expired)
        pdfNotificationIDs.formIntersection(retained)
        guard choices.notifications, pdfReviewBook.status(for: selection).needsReminder,
              Date().timeIntervalSince(lastPDFNotification) >= 5 else { return }
        lastPDFNotification = Date()
        let generation = pdfReviewGeneration, notificationEpoch = notificationGeneration
        let identifier = "boxcop-pdf-review-" + selection.id.uuidString
        pdfNotificationIDs.insert(identifier)
        Task { @MainActor [weak self] in
            let center = UNUserNotificationCenter.current(), settings = await center.notificationSettings()
            guard let self else { return }
            @MainActor func current() -> Bool {
                self.running && self.pdfReviewEnabled && self.pdfReviewGeneration == generation &&
                    self.notificationGeneration == notificationEpoch && self.choices.notifications &&
                    self.pdfNotificationIDs.contains(identifier) && self.pdfReviewBook.selections.contains {
                        $0.id == selection.id && !$0.dismissed && Date().timeIntervalSince($0.observedAt) <= PDFReviewBook.retention && self.pdfReviewBook.status(for: $0).needsReminder
                    }
            }
            guard current(), settings.authorizationStatus == .authorized || settings.authorizationStatus == .provisional else { return }
            if await offerHeadsUp(.pdf, itemID: selection.id.uuidString, settings: settings, stillCurrent: current) != .notUsed {
                if !current() { refreshActionableAlerts() }
                return
            }
            guard current() else { return }
            let content = UNMutableNotificationContent()
            content.title = "Review your PDF attachment"
            content.body = "A selected PDF has no complete preview recorded in BoxCop. Open Activity to preview the file or dismiss this reminder."
            try? await center.add(UNNotificationRequest(identifier: identifier, content: content, trigger: nil))
            if !current() {
                center.removePendingNotificationRequests(withIdentifiers: [identifier])
                center.removeDeliveredNotifications(withIdentifiers: [identifier])
            }
        }
    }
    private func ensureWorkflowJournal() {
        guard workflowJournal == nil, developmentMode || requiresMonitoringConsent else { return }
        do {
            let directory = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/BoxCop/workflows")
            let journal = try WorkflowJournal(directory: directory)
            workflowJournal = journal; workflow.onAppend = { event in journal.append(event) }
            journalStatus = "Saving encrypted unified workflow events locally · up to 64 MiB retained."
        } catch { journalStatus = "Workflow persistence unavailable; events are in memory only." }
    }
    private func importNetworkWorkflow() async {
        // A running filter is the choice, whether setup or Connections turned it on.
        guard ownsSession, releaseProfile.usesStandaloneNetworkProtection, networkConnections.setupReady else {
            networkWorkflowState = "disabled_or_unavailable"; return
        }
        ensureWorkflowJournal()
        // Bounded catch-up per poll; cursor continues through retained history on the next poll.
        for _ in 0..<4 {
            let reply = await EndpointSecurityControl.send("network-workflow " + (networkWorkflow.cursor?.uuidString ?? "start"))
            guard ownsSession, releaseProfile.usesStandaloneNetworkProtection, networkConnections.setupReady else { return }
            guard let bytes = reply.data(using: .utf8), let page = try? JSONDecoder().decode(NetworkWorkflowPage.self, from: bytes) else {
                if networkWorkflowState != "unavailable" {
                    workflow.append(kind: "collector_health", collector: "NetworkExtension", availability: "workflow_history_unavailable")
                }
                networkWorkflowState = "unavailable"; return
            }
            networkWorkflow.ingest(page, into: &workflow)
            networkWorkflowState = page.cursorExpired || page.loggingDropped > 0 || page.writeFailures > 0 || page.oversizedRecords > 0 ? "incomplete" : page.hasMore ? "catching_up" : "active"
            if !page.hasMore { break }
        }
    }
    private func collectProcessSnapshot() {
        guard running, activityCollection, Date().timeIntervalSince(lastProcessSnapshot) >= 30 else { return }
        lastProcessSnapshot = Date()
        let apps = NSWorkspace.shared.runningApplications
        for app in apps.prefix(128) where app.processIdentifier > 0 {
            workflow.append(kind: "process_snapshot", collector: "NSWorkspace", bundleID: app.bundleIdentifier, pid: app.processIdentifier,
                fields: ["executable": WorkflowField(app.executableURL?.path), "name": WorkflowField(app.localizedName),
                         "launch_time": WorkflowField(app.launchDate.map { ISO8601DateFormatter().string(from: $0) }),
                         "coverage": WorkflowField("Running GUI applications only; network records also identify CLI/helper processes"),
                         "pid_version": WorkflowField(nil, provenance: "unknown", availability: "not_provided_by_api")])
        }
        if apps.count > 128 { workflow.append(kind: "collector_health", collector: "NSWorkspace", availability: "process_snapshot_truncated") }
    }
    private var workflowSources: [WorkflowSourceState] {
        [
            .init("network", networkConnections.setupReady ? networkWorkflowState : "disabled_or_unavailable", "New flows delivered by the network extension; no payload inspection"),
            .init("processes", running ? (activityCollection ? "active" : "disabled") : "paused", "GUI app snapshots/lifecycle; network events add CLI/helper identities; no universal process audit"),
            .init("window_context", running && collectWindowTitles ? (ShortcutTap.accessibilityGranted ? "active" : "permission_missing") : "disabled", "Accessibility metadata and selected text, subject to macOS permissions"),
            .init("screenshots_ocr", running && (collectWindowFrames || captureRiskWindows) ? (CGPreflightScreenCaptureAccess() ? "active" : "permission_missing") : "disabled", "Window capture/frame OCR; image references can expire; no new capture permission implied"),
            .init("background_screen", running && backgroundScreenEnabled ? (CGPreflightScreenCaptureAccess() ? "active" : "permission_missing") : "disabled", "Assessment metadata only; this path does not retain pixels or OCR text"),
            .init("browser_hooks", running && collectAdapters ? (lastBrowserEventAt == nil ? "awaiting_events" : "active") : "disabled", "Same-user reported events; no authenticated browser identity"),
            .init("agent_hooks", running && collectAdapters ? (lastAgentEventAt == nil ? "awaiting_events" : "active") : "disabled", "Reported prompts/tool calls/results only for connected hooks; no universal agent coverage"),
            .init("files", running && fileWatchRoot != nil ? "active" : "disabled", "Selected-root FSEvents changes, not file reads or responsible-process attribution"),
            .init("clipboard", running ? (clipboardChecksEnabled ? "active" : "disabled") : "paused", "Attempt/decision metadata only; raw clipboard content is not persisted in context"),
            .init("endpoint_security", releaseProfile.usesEndpointSecurity ? "separate_journal" : "not_available", "Privileged file/exec journal remains an explicit offline input; no entitlement assumed"),
            .init("software_inventory", softwareInventory == nil ? "not_available" : "snapshot", "Periodic inventory findings; not a running-process audit")
        ]
    }
    private func currentWorkflowContext() -> WorkflowContext {
        WorkflowContext.build(from: workflow, sources: workflowSources, networkOnly: !running)
    }
    func setWorkflowReviewEnabled(_ enabled: Bool) {
        guard applyingTeamPolicy || teamConnection.state.settings["workflow_review"] == nil else { return }
        if applyingTeamPolicy && workflowReviewEnabled == enabled { return }
        workflowReviewEnabled = enabled
        if !applyingTeamPolicy { defaults.set(enabled, forKey: "boxcop.workflowReview.enabled") }
        if !enabled {
            workflowReviewer.stop(); clearEmailReviewCache(); workflowJudgment = nil
            workflowContextStatus = "Local AI review is off. Timeline collection and existing protections continue."
        }
        lastWorkflowContextBuild = .distantPast
    }
    private func updateWorkflowContext() {
        if running, pdfReviewEnabled, pdfReviewBook.selections.contains(where: { Date().timeIntervalSince($0.observedAt) > PDFReviewBook.retention }) {
            pdfReviewBook.prune(now: Date())
        }
        updateCodeVerification()
        guard ownsSession, workflowReviewEnabled else { return }
        guard running || (releaseProfile.usesStandaloneNetworkProtection && networkConnections.setupReady) else { workflowReviewer.stop(); clearEmailReviewCache(); workflowJudgment = nil; return }
        guard Date().timeIntervalSince(lastWorkflowContextBuild) >= 3 else { return }
        lastWorkflowContextBuild = Date()
        let context = currentWorkflowContext()
        workflowReviewer.submit(context) { [weak self] status, judgment in
            self?.workflowContextStatus = status; self?.workflowJudgment = judgment
            self?.recordEmailReviews(judgment)
        }
    }
    private func recordEmailReviews(_ status: WorkflowJudgmentStatus?) {
        guard running, workflowReviewEnabled, let status, status.isValid, let result = status.result else { return }
        let retained = Set(workflow.events.map(\.id))
        removeEmailReviewNotifications(pendingEmailReviewTargets.subtracting(retained))
        pendingEmailReviewTargets.formIntersection(retained)
        dismissedEmailReviewTargets.formIntersection(retained)
        for annotation in result.emailReviewAnnotations ?? [] where !recordedEmailAnnotations.contains(annotation.key) {
            guard annotation.eventIDs.allSatisfy({ id in workflow.events.contains { $0.id == id } }) else { continue }
            recordedEmailAnnotations.insert(annotation.key)
            if recordedEmailAnnotations.count > 2000 { recordedEmailAnnotations = [annotation.key] }
            workflow.append(kind: "email_review_annotation", collector: "workflow.review", provenance: "inferred", fields: [
                "label": WorkflowField(annotation.label), "prompt_version": WorkflowField(annotation.annotationVersion),
                "model": WorkflowField(status.model)
            ], relatedEventIDs: annotation.eventIDs)
        }
        for review in result.emailReviews ?? [] {
            guard let target = workflow.events.first(where: { $0.id == review.targetEventID }) else { continue }
            emailReviewCache.store(review, target: target)
            if review.outcome == "high_risk", review.phase == "send_attempted", !dismissedEmailReviewTargets.contains(target.id) {
                pendingEmailReviewTargets.insert(target.id)
            } else {
                if pendingEmailReviewTargets.remove(target.id) != nil { removeEmailReviewNotifications([target.id]) }
            }
            let assessmentKey = "\(target.id)|\(review.scoreVersion ?? status.promptVersion)|\(review.probability.map { String($0) } ?? "unknown")"
            guard !recordedEmailReviews.contains(assessmentKey) else { continue }
            recordedEmailReviews.insert(assessmentKey)
            if recordedEmailReviews.count > 2000 { recordedEmailReviews = [assessmentKey] }
            if pendingEmailReviewTargets.contains(target.id) { notifyEmailReview(targetID: target.id) }
            workflow.append(kind: "email_review_assessment", collector: "workflow.review", provenance: "inferred", fields: [
                "composition_id": WorkflowField(review.compositionID), "draft_version": WorkflowField(review.draftVersion),
                "probability": WorkflowField(review.probability.map { String($0) }), "threshold": WorkflowField(String(review.threshold)),
                "outcome": WorkflowField(review.outcome), "reason": WorkflowField(review.reason),
                "review_phase": WorkflowField(review.phase), "model": WorkflowField(review.scoreVersion == nil ? status.model : "timeline-rules"),
                "prompt_version": WorkflowField(review.scoreVersion ?? status.promptVersion),
                "linked_outputs": WorkflowField(review.signals.map { String($0.linkedOutputs) }),
                "revision_pairs": WorkflowField(review.signals.map { String($0.revisionPairs) }),
                "interaction_seconds": WorkflowField(review.signals.map { String($0.interactionSeconds) }),
                "paste_to_action_seconds": WorkflowField(review.signals?.pasteToActionSeconds.map { String($0) }), "incomplete": WorkflowField(String(result.incomplete))
            ], relatedEventIDs: [target.id] + review.eventIDs.filter { $0 != target.id })
        }
    }
    private func clearEmailReviewCache() {
        defer { refreshActionableAlerts() }
        emailReviewCache.clear()
        removeEmailReviewNotifications(pendingEmailReviewTargets)
        pendingEmailReviewTargets.removeAll(); dismissedEmailReviewTargets.removeAll()
        guard ownsSession else { return }
        UNUserNotificationCenter.current().removeDeliveredNotifications(withIdentifiers: ["boxcop-email-review"])
        UNUserNotificationCenter.current().removePendingNotificationRequests(withIdentifiers: ["boxcop-email-review"])
    }
    private func removeEmailReviewNotifications(_ targets: Set<UUID>) {
        guard ownsSession, !targets.isEmpty else { return }
        let identifiers = targets.map { "boxcop-email-review-" + $0.uuidString }
        let center = UNUserNotificationCenter.current()
        center.removeDeliveredNotifications(withIdentifiers: identifiers)
        center.removePendingNotificationRequests(withIdentifiers: identifiers)
    }
    private func notifyEmailReview(targetID: UUID) {
        guard ownsSession else { return }
        let expectedEpoch = epoch
        let identifier = "boxcop-email-review-" + targetID.uuidString
        Task { @MainActor [weak self] in
            guard let self else { return }
            let settings = await UNUserNotificationCenter.current().notificationSettings()
            let authorized = settings.authorizationStatus == .authorized || settings.authorizationStatus == .provisional
            guard self.running, self.workflowReviewEnabled, self.epoch == expectedEpoch,
                  self.pendingEmailReviewTargets.contains(targetID),
                  self.workflow.events.contains(where: { $0.id == targetID }) else { return }
            var delivery = "in_app_only"
            var headsUp = ReviewHeadsUpOutcome.notUsed
            if authorized {
                headsUp = await offerHeadsUp(.email, itemID: targetID.uuidString, settings: settings) {
                    self.running && self.workflowReviewEnabled && self.epoch == expectedEpoch &&
                        self.pendingEmailReviewTargets.contains(targetID) && self.workflow.events.contains { $0.id == targetID }
                }
            }
            guard self.pendingEmailReviewTargets.contains(targetID), self.running, self.epoch == expectedEpoch else { return }
            if headsUp == .requested { delivery = "heads_up_requested" }
            else if headsUp == .duplicate { delivery = "duplicate_suppressed" }
            else if authorized {
                let content = UNMutableNotificationContent()
                content.title = "Review your AI-assisted email"
                content.body = "A recent Gmail Send attempt has a high review-risk score. Open Activity for the evidence. Sending was not blocked; delivery is unconfirmed."
                do {
                    try await UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: identifier, content: content, trigger: nil))
                    delivery = "notification_requested"
                } catch { }
            }
            guard self.running, self.workflowReviewEnabled, self.epoch == expectedEpoch,
                  self.pendingEmailReviewTargets.contains(targetID),
                  self.workflow.events.contains(where: { $0.id == targetID }) else {
                removeEmailReviewNotifications([targetID])
                return
            }
            self.workflow.append(kind: "email_review_notice", collector: "workflow.review", fields: ["review_phase": WorkflowField(delivery)], relatedEventIDs: [targetID])
        }
    }
    func exportWorkflowContext() {
        let panel = NSSavePanel(); panel.nameFieldStringValue = "boxcop-workflow-context.json"
        panel.title = "Export linked local context (may contain private text and paths)"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            try currentWorkflowContext().exportData().write(to: url, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
            workflowContextStatus = "Exported linked context, source coverage and explicit omissions."
        } catch { workflowContextStatus = "Could not export workflow context." }
    }
    func exportWorkflow() {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "boxcop-workflow.json"
        panel.title = "Export observed workflow (may include private window titles)"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            try workflow.exportData().write(to: url, options: [.atomic])
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
            workflowStatus = "Workflow exported. This file contains observed metadata, not raw clipboard text or policy ground truth."
        } catch { workflowStatus = "Could not export workflow." }
    }
    private func pollWindowContext() {
        let now = ProcessInfo.processInfo.systemUptime
        guard collectWindowTitles, monitor.running, windowTask == nil, now - lastWindowPoll >= 2,
              let app = NSWorkspace.shared.frontmostApplication, let bundle = app.bundleIdentifier,
              IdentityValidation.bundle(bundle), app.processIdentifier > 0 else { return }
        lastWindowPoll = now
        let pid = app.processIdentifier, expectedEpoch = epoch, generation = windowGeneration
        // Use the same password-manager exclusions as clipboard collection.
        if ClipboardPolicy.preflight(types: ["public.utf8-plain-text"], bundleID: bundle) == .passwordManager { return }
        windowTask = Task { [weak self] in
            guard let self else { return }
            defer { windowTask = nil }
            let observation = await windowReader.read(pid: pid, includeSelection: collectSelectedText)
            guard !Task.isCancelled, running, collectWindowTitles, epoch == expectedEpoch, windowGeneration == generation,
                  NSWorkspace.shared.frontmostApplication?.processIdentifier == pid else { return }
            let signature = "\(pid)|\(observation.availability)|\(observation.title ?? "")|" + observation.fields.keys.sorted().map { "\($0)=\(observation.fields[$0]?.value ?? "")" }.joined(separator: "|")
            guard signature != lastWindowSignature else { return }
            lastWindowSignature = signature
            lastContextEvent = workflow.append(kind: "window_context", collector: "Accessibility.focusedWindow", bundleID: bundle, pid: pid,
                            windowTitle: observation.title, availability: observation.availability, fields: observation.fields)
            workflowStatus = observation.availability == "available" ? "Window context observed. Titles are application-provided text, not verified URLs or account identities." : "Window context unavailable: " + observation.availability
        }
    }
    private func updateFrontmost() {
        guard monitor.running, let app = NSWorkspace.shared.frontmostApplication,
              let bundle = app.bundleIdentifier, IdentityValidation.bundle(bundle), app.processIdentifier > 0 else {
            frontmostBundle = nil; frontmostPID = nil; return
        }
        if frontmostBundle != bundle || frontmostPID != app.processIdentifier {
            lastContextEvent = nil
            if activityCollection { workflow.append(kind: "app_focus", collector: "NSWorkspace", bundleID: bundle, pid: app.processIdentifier) }
        }
        if bundle != Bundle.main.bundleIdentifier {
            let changed = lastExternalApp?.0 != bundle || lastExternalApp?.1 != app.processIdentifier
            lastExternalApp = (bundle, app.processIdentifier)
            if changed && collectWindowFrames { setFrameCollection(true) }
        }
        frontmostBundle = bundle; frontmostPID = app.processIdentifier
    }
    private func liveSnapshot() -> SnapshotKey? {
        guard monitor.running else { return nil }
        let revision = NSPasteboard.general.changeCount
        guard let app = NSWorkspace.shared.frontmostApplication, app.processIdentifier > 0,
              let bundle = app.bundleIdentifier, IdentityValidation.bundle(bundle), NSPasteboard.general.changeCount == revision else { return nil }
        return SnapshotKey(revision: revision, pid: app.processIdentifier, bundleID: bundle, generation: monitor.generation)
    }
    private func tick() {
        guard monitor.running else { return }
        tap?.checkHealth()
        if !guardActive, pasteRecovery.shouldRetry(at: ProcessInfo.processInfo.systemUptime,
                                     requested: running && choices.monitoring && choices.guardShortcut && !guardActive,
                                     accessibility: ShortcutTap.accessibilityGranted,
                                     secureInput: ShortcutTap.secureInputActive) {
            enableGuard(automaticRecovery: true)
        }
        let currentPasteKey = liveSnapshot()
        let hadOverride = pasteOverride.isGranted
        pasteOverride.observe(live: currentPasteKey, now: ProcessInfo.processInfo.systemUptime)
        if !guardActive || blockedPasteKey != currentPasteKey || (hadOverride && !pasteOverride.isGranted) { clearPasteIntervention() }
        pollWindowContext()
        collectProcessSnapshot()
        updateWorkflowContext()
        let revision = NSPasteboard.general.changeCount
        if monitor.observe(revision: revision), clipboardChecksEnabled {
            unsupportedRevision = nil
            gate.observe(live: liveSnapshot())
            if let key = liveSnapshot() { scheduleEvaluation(key: key, ticket: nil) }
            else { clipboardStatus = ClipboardUnsupported.missingIdentity.message }
        }
        let now = ProcessInfo.processInfo.systemUptime
        preparePasteIfIdle()
        if now - lastEndpointSecurityPoll >= 3 {
            lastEndpointSecurityPoll = now
            controlEndpointSecurity("status")
        }
        if let state = workflowJournal?.state() {
            journalStatus = "Encrypted journal: \(state.written) saved · \(state.dropped) lost · \(state.evictedSegments) segments expired" + (state.failed ? " · write failure" : "")
        }
        if let state = developmentLog?.state(), state.failed || state.dropped > 0 {
            developmentStatus = "Development log write failure: \(state.failed); dropped entries: \(state.dropped)."
        }
        if now - lastHealthCheck >= 2, healthTask == nil, let engine = client {
            lastHealthCheck = now; let expectedEpoch = epoch
            healthTask = Task { [weak self] in
                guard let self else { return }
                defer { if epoch == expectedEpoch { healthTask = nil } }
                do {
                    if case let .status(classification) = try await engine.request(.status), let classification,
                       epoch == expectedEpoch, !Task.isCancelled {
                        engineStatus = classification.summary
                    }
                }
                catch {
                    guard epoch == expectedEpoch, !Task.isCancelled else { return }
                    if (error as? EngineFailure) != .backpressure { failEngine((error as? EngineFailure) ?? .disconnected) }
                }
            }
        }
    }
    private func deferGuardStatus(_ message: String) {
        let expectedEpoch = epoch
        Task { @MainActor [weak self] in
            guard let self, self.epoch == expectedEpoch, self.monitor.running else { return }
            self.guardStatus = message
        }
    }
    private func snapshotWorkflowFields(_ key: SnapshotKey) -> [String: WorkflowField] {
        ["clipboard_revision": WorkflowField(String(key.revision)), "monitor_generation": WorkflowField(String(key.generation))]
    }
    private func clearPasteIntervention() {
        pasteOverride.clear()
        blockedPasteKey = nil
        pasteNotice.dismiss()
    }
    private func showPasteBlocked(key: SnapshotKey?, message: String) {
        // Never construct UI inside the event-tap callback.
        let expectedEpoch = epoch
        Task { @MainActor [weak self] in
            guard let self, self.epoch == expectedEpoch, self.running, self.guardActive,
                  self.liveSnapshot() == key, !self.pasteOverride.isGranted else { return }
            self.blockedPasteKey = key
            let allow: (() -> Void)? = key.map { requested in
                { [weak self] in self?.allowBlockedPaste(requested) }
            }
            self.pasteNotice.show(message: message, allow: allow, feedback: { [weak self] in self?.showAlertFeedback(.paste) })
            self.notifyBlockedPaste()
        }
    }
    private func allowBlockedPaste(_ key: SnapshotKey) {
        guard running, guardActive, blockedPasteKey == key,
              pasteOverride.grant(for: key, live: liveSnapshot(), now: ProcessInfo.processInfo.systemUptime) else {
            clearPasteIntervention()
            return
        }
        workflow.append(kind: "paste_override_granted", collector: "user", bundleID: key.bundleID, pid: key.pid,
                        fields: snapshotWorkflowFields(key))
        guardStatus = "Paste override ready. Press Command-V within ten seconds in the same app."
        pasteNotice.show(title: "Paste allowed once", message: "Allowed once. Press Command-V again within ten seconds. Keep the same clipboard and app.", allow: nil)
    }
    private func shortcut(repeatKey: Bool) -> Bool {
        // Only this path can pass a guarded shortcut; it ALWAYS reads live OS identity/revision first.
        guard running, guardActive else { return true }
        let live = liveSnapshot()
        diagnostic(repeatKey ? "shortcut_repeat" : "shortcut_pressed", key: live)
        if pasteOverride.consume(live: live, now: ProcessInfo.processInfo.systemUptime, isRepeat: repeatKey) {
            diagnostic("shortcut_user_override", key: live)
            let expectedEpoch = epoch
            Task { @MainActor [weak self] in
                guard let self, self.epoch == expectedEpoch else { return }
                self.clearPasteIntervention()
                self.workflow.append(kind: "paste_override_passed", collector: "CGEventTap", bundleID: live?.bundleID, pid: live?.pid,
                                     fields: live.map { self.snapshotWorkflowFields($0) } ?? [:])
            }
            deferGuardStatus("One paste shortcut allowed by you.")
            return true
        }
        if let live, let skipped = unsupportedRevision, skipped.0 == live.revision {
            diagnostic("shortcut_cached_unsupported", key: live)
            gate.invalidate()
            deferGuardStatus("Paste allowed without a check. " + skipped.1.message)
            return true
        }
        let result = gate.shortcut(live: live, now: ProcessInfo.processInfo.systemUptime, isRepeat: repeatKey)
        switch result {
        case .passThrough:
            diagnostic("shortcut_pass_through", key: live)
            return result.permitsPaste
        case .allowOnce:
            diagnostic("shortcut_allow_once", key: live)
            let expectedEpoch = epoch
            Task { @MainActor [weak self] in
                guard let self, self.running, self.epoch == expectedEpoch else { return }
                self.clearPasteIntervention()
                self.workflow.append(kind: "paste_shortcut_passed", collector: "CGEventTap", bundleID: live?.bundleID, pid: live?.pid,
                                     fields: (live.map { self.snapshotWorkflowFields($0) } ?? [:]).merging(["insertion": WorkflowField(nil, provenance: "unknown", availability: "not_observed")]) { _, new in new })
            }
            deferGuardStatus("One fresh rule-allowed shortcut passed. Insertion and network egress are not confirmed.")
            return result.permitsPaste
        case let .evaluate(ticket):
            diagnostic("shortcut_evaluate", key: live, ticket: ticket.nonce)
            deferGuardStatus("Paste allowed; checking asynchronously for future pastes.")
            Task { @MainActor [weak self] in self?.scheduleEvaluation(key: ticket.key, ticket: ticket) }
            return result.permitsPaste
        case let .hold(reason):
            diagnostic("shortcut_hold_" + String(describing: reason), key: live)
            guard reason == .policy else {
                deferGuardStatus("Paste allowed without a completed check.")
                return result.permitsPaste
            }
            showPasteBlocked(key: live, message: "BoxCop’s protection rules blocked this paste. Allow once if you trust this destination.")
            deferGuardStatus("Shortcut held by policy. See the recent decision reasons.")
            return result.permitsPaste
        }
    }
    /// Copy evaluation must finish first so preparation sees its lineage. PasteGate
    /// coalesces pending work, preserves holds, and refreshes allows only after 4s.
    private func preparePasteIfIdle() {
        guard monitor.running, guardActive, work.isEmpty, let live = liveSnapshot(),
              monitor.mayRead(revision: live.revision), monitor.lastRevision == live.revision,
              unsupportedRevision?.0 != live.revision,
              let ticket = gate.prepare(live: live, now: ProcessInfo.processInfo.systemUptime) else { return }
        scheduleEvaluation(key: live, ticket: ticket, preparation: true)
    }

    private func scheduleEvaluation(key: SnapshotKey, ticket: EvaluationTicket?, preparation: Bool = false) {
        guard monitor.running, key.generation == monitor.generation, let engine = client else { return }
        if !monitor.mayRead(revision: key.revision) {
            diagnostic("capture_baseline_refused", key: key, ticket: ticket?.nonce)
            if let ticket { gate.fail(ticket, reason: .unsupported) }
            clipboardStatus = ClipboardUnsupported.baseline.message; return
        }
        if ClipboardPolicy.preflight(types: ["public.utf8-plain-text"], bundleID: key.bundleID) == .passwordManager {
            unsupportedRevision = (key.revision, .passwordManager)
            if let ticket { gate.fail(ticket, reason: .unsupported) }
            clipboardStatus = ClipboardUnsupported.passwordManager.message; return
        }
        guard work.count < 4 else {
            diagnostic("capture_backpressure", key: key, ticket: ticket?.nonce)
            if let ticket { gate.fail(ticket, reason: .engineError) }
            clipboardStatus = "Busy: this clipboard change was not evaluated. Copy again or Retry."
            return
        }
        let id = UUID(), expectedEpoch = epoch, role = choices.role
        if ticket != nil && !preparation { guardStatus = "Paste allowed. A background check is still in progress." }
        work[id] = Task { [weak self] in
            guard let self else { return }
            defer {
                work.removeValue(forKey: id)
                // Do not wait for another polling tick after the copy response.
                if epoch == expectedEpoch && !Task.isCancelled && liveSnapshot() == key { preparePasteIfIdle() }
            }
            guard epoch == expectedEpoch, liveSnapshot() == key else { if let ticket { gate.fail(ticket, reason: .unsupported) }; return }
            let captured = await clipboardReader.capture(key: key, kind: ticket == nil ? .clipboardCopy : (preparation ? .pastePreparation : .pasteAttempt), role: role)
            guard epoch == expectedEpoch, !Task.isCancelled else { return }
            switch captured {
            case let .unsupported(reason):
                diagnostic("capture_" + reason.rawValue, key: key, ticket: ticket?.nonce)
                if NSPasteboard.general.changeCount == key.revision, [.passwordManager, .sensitiveType, .notPlainText, .oversized, .unreadable, .empty].contains(reason) {
                    unsupportedRevision = (key.revision, reason)
                }
                if let ticket { gate.fail(ticket, reason: .unsupported) }
                clipboardStatus = reason.message
                if ticket != nil { guardStatus = "Paste allowed without a check. " + reason.message }
            case let .event(event):
                let observationID = workflow.append(kind: ticket == nil ? "clipboard_change_observed" : (preparation ? "paste_policy_preparation" : "paste_attempt"), collector: "NSPasteboard+CGEventTap", bundleID: key.bundleID, pid: key.pid, phase: ticket == nil ? "observed" : (preparation ? "prepared" : "attempted"), fields: snapshotWorkflowFields(key), relatedEventIDs: lastContextEvent.map { [$0] } ?? [])
                guard liveSnapshot() == key else {
                    if let ticket { gate.fail(ticket, reason: .unsupported) }
                    clipboardStatus = ClipboardUnsupported.changed.message; return
                }
                do {
                    let result = try await engine.request(.evaluate(event))
                    guard epoch == expectedEpoch, !Task.isCancelled else { return }
                    guard case let .record(record) = result else { throw EngineFailure.protocolViolation }
                    diagnostic(preparation ? "prepared_engine_decision" : "engine_decision", key: key, ticket: ticket?.nonce, decision: record.action.rawValue)
                    addRecord(record)
                    workflow.append(kind: "policy_decision", collector: "rules+sequence", bundleID: key.bundleID, pid: key.pid,
                                    fields: snapshotWorkflowFields(key).merging(["action": WorkflowField(record.action.rawValue), "audit_record_id": WorkflowField(record.id.uuidString)]) { _, new in new }, relatedEventIDs: [observationID])
                    if captureRiskWindows, record.action != .allow { captureWindow(bundle: key.bundleID, pid: key.pid) }
                    clipboardStatus = "Plain text evaluated; no raw content retained. App attribution is frontmost-when-observed only."
                    if let ticket {
                        if gate.resolve(ticket, action: record.action, live: liveSnapshot(), now: ProcessInfo.processInfo.systemUptime) {
                            diagnostic("gate_resolved", key: key, ticket: ticket.nonce, decision: record.action.rawValue)
                            guardStatus = record.action == .block
                                ? "Policy match found. Further pastes of this clipboard into this app will be blocked."
                                : "Paste allowed. Check complete."
                            if blockedPasteKey == key {
                                if record.action == .block {
                                    showPasteBlocked(key: key, message: "BoxCop’s protection rules blocked this paste. Allow once if you trust this destination.")
                                } else { clearPasteIntervention() }
                            }
                        } else { diagnostic("gate_stale_result", key: liveSnapshot(), ticket: ticket.nonce); guardStatus = "Paste allowed without a current check. Copy the text again to recheck it." }
                    }
                } catch {
                    guard epoch == expectedEpoch, !Task.isCancelled else { return }
                    if let ticket { gate.fail(ticket, reason: .engineError) }
                    let failure = (error as? EngineFailure) ?? .internalError
                    diagnostic("engine_request_failed", key: key, ticket: ticket?.nonce)
                    if failure == .backpressure || failure == .invalidRequest || failure == .internalError {
                        clipboardStatus = failure.description
                        if ticket != nil { guardStatus = "Paste allowed without a check. " + failure.description }
                    } else { failEngine(failure) }
                }
            }
        }
    }
    private func addRecord(_ record: SafeRecord) {
        records.removeAll { $0.id == record.id }; records.insert(record, at: 0)
        if records.count > 30 { records.removeLast(records.count - 30) }
    }
    private func loadHistory(engine: EngineClient, expectedEpoch: UInt64) async {
        do {
            if case let .recent(items, _) = try await engine.request(.recent(30)), epoch == expectedEpoch {
                for item in items.reversed() where !records.contains(where: { $0.id == item.id }) { records.append(item) }
                records = Array(records.sorted { $0.createdAt > $1.createdAt }.prefix(30))
            }
            if case let .policies(items) = try await engine.request(.policies), epoch == expectedEpoch { policies = items }
        } catch {
            guard epoch == expectedEpoch else { return }
            clipboardStatus = "Recent history/policies unavailable. Live requests still require their own decision."
        }
    }
    func setNotificationPreference(_ enabled: Bool) {
        defer { refreshActionableAlerts() }
        notificationGeneration &+= 1
        choices.notifications = enabled
        defaults.set(enabled, forKey: "boxcop.setup.notifications")
        defaults.set(true, forKey: "boxcop.setup.notificationsAsked")
        saveChoices()
        notificationsStatus = enabled ? "Security notifications enabled; macOS permission controls delivery." : "Notifications off."
        if !enabled { UNUserNotificationCenter.current().removeAllPendingNotificationRequests() }
    }
    func setOnScreenAlertsEnabled(_ enabled: Bool) {
        onScreenAlertsEnabled = enabled
        defaults.set(enabled, forKey: "boxcop.onScreenAlerts.enabled")
        refreshActionableAlerts()
    }
    func setKeepReviewAlertsVisible(_ enabled: Bool) {
        keepReviewAlertsVisible = enabled
        defaults.set(enabled, forKey: "boxcop.keepReviewAlertsVisible")
        refreshActionableAlerts()
    }
    func setNotifications(_ enabled: Bool) {
        setNotificationPreference(enabled)
        let generation = notificationGeneration
        guard enabled else { return }
        Task { [weak self] in
            guard let self else { return }
            do {
                let granted = try await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound])
                guard notificationGeneration == generation else { return }
                choices.notifications = granted; saveChoices()
                notificationsStatus = granted ? "Notifications enabled; content is never included." : "Notification permission denied; use the menu-bar status."
            } catch {
                guard notificationGeneration == generation else { return }
                choices.notifications = false; saveChoices(); notificationsStatus = "Notifications unavailable; use the menu-bar status."
            }
        }
    }
    func sendTestNotification() {
        Task { @MainActor [weak self] in
            let center = UNUserNotificationCenter.current()
            let settings = await center.notificationSettings()
            guard let self else { return }
            guard settings.authorizationStatus == .authorized, settings.alertSetting == .enabled else {
                testNotificationStatus = "Banners are not enabled. Enable BoxCop in Notification Settings, then try again."
                return
            }
            let content = UNMutableNotificationContent()
            content.title = "BoxCop — test notification"
            content.body = "This is a test of BoxCop notifications. Open BoxCop to review alert visibility."
            content.sound = .default
            do {
                try await center.add(UNNotificationRequest(identifier: "boxcop-notification-test", content: content, trigger: nil))
                testNotificationStatus = "Test requested. If no banner appears, check Focus and Notification Settings. BoxCop cannot confirm that a banner was visible."
            } catch {
                testNotificationStatus = "The test notification could not be requested. Try again after checking Notification Settings."
            }
        }
    }
    func showSoftwareReview() {
        showWindow(page: .protection)
        softwareReviewPresented = true
    }
    private func notifyBlockedPaste() {
        guard choices.notifications, Date().timeIntervalSince(lastPasteNotification) >= 10 else { return }
        lastPasteNotification = Date()
        let generation = notificationGeneration
        Task { @MainActor [weak self] in
            let center = UNUserNotificationCenter.current()
            let settings = await center.notificationSettings()
            guard let self, self.choices.notifications, self.notificationGeneration == generation,
                  settings.authorizationStatus == .authorized || settings.authorizationStatus == .provisional else { return }
            let content = UNMutableNotificationContent()
            content.title = "BoxCop — paste blocked"
            content.body = "Protection rules blocked a paste. Open BoxCop to review the decision."
            content.sound = .default
            try? await center.add(UNNotificationRequest(identifier: "boxcop-paste-blocked", content: content, trigger: nil))
        }
    }
    private func notifyInventory(_ report: SoftwareInventoryReport) async {
        guard choices.notifications else { return }
        let generation = notificationGeneration
        // Stable metadata only: scan times and ordering must not cause repeat alerts.
        let keys = activeSoftwareFindings.flatMap { item in
            item.advisories.filter(\.needsReview).map { advisory in
                [item.id, item.version, advisory.id, advisory.state].joined(separator: "|")
            }
        }
        let previous = Set(defaults.stringArray(forKey: "boxcop.inventory.notified") ?? [])
        let current = Set(keys)
        guard !current.subtracting(previous).isEmpty else {
            if !report.incomplete { defaults.set(Array(current), forKey: "boxcop.inventory.notified") }
            return
        }
        let center = UNUserNotificationCenter.current()
        var settings = await center.notificationSettings()
        if settings.authorizationStatus == .notDetermined {
            _ = try? await center.requestAuthorization(options: [.alert, .sound])
            settings = await center.notificationSettings()
        }
        guard choices.notifications, notificationGeneration == generation else { return }
        let body = "\(activeSoftwareFindings.count) installed software item(s) need review. These findings do not mean an exploit was detected."
        if settings.authorizationStatus == .authorized || settings.authorizationStatus == .provisional {
            let content = UNMutableNotificationContent()
            content.title = "BoxCop — software needs review"
            content.body = body + " Open this notification to review."
            content.sound = .default
            do {
                try await center.add(UNNotificationRequest(identifier: "boxcop-software-review", content: content, trigger: nil))
            } catch { return }
        }
        // Software remains in the menu and review screen when banners are unavailable.
        defaults.set(Array(report.incomplete ? previous.union(current) : current), forKey: "boxcop.inventory.notified")
    }
    // MARK: Review before sending (advisory; never enters allow/warn/block enforcement)

    /// Explicit user choice. Enabling never turns on monitoring or a collector; it only asks for
    /// notification permission if macOS has not been asked before.
    func setReviewPolicyEnabled(_ enabled: Bool) {
        // Drafts prepared while the policy was off never become reminders, even if they arrive late.
        if enabled && !reviewPolicyEnabled { reviewBook.admitOnlyAfter() }
        updatingAdapterCollection { reviewPolicyEnabled = enabled }
        defaults.set(enabled, forKey: ReviewPolicy.enabledKey)
        if !enabled { withdrawReviewReminders(reason: "policy_disabled", record: true) }
        Task { [weak self] in
            let state: ReviewReminderNotifier.Authorization
            if enabled { state = await ReviewReminderNotifier.requestAuthorizationForUserChoice() }
            else { state = await ReviewReminderNotifier.authorization() }
            self?.reviewNotifications = state
        }
    }
    func refreshReviewNotificationState() {
        Task { [weak self] in self?.reviewNotifications = await ReviewReminderNotifier.authorization() }
    }
    var reviewCoverage: (status: String, active: Bool, detail: String) {
        guard reviewPolicyEnabled else { return ("Off", false, "Optional advisory reminder before sending Gmail drafts. Turn it on in Policies.") }
        guard running else { return ("On · monitoring paused", false, "Reminders need monitoring. Resume monitoring to observe Gmail drafts.") }
        guard collectAdapters else { return ("On · browser receiving off", false, "Turn on browser receiving in Connections. BoxCop never turns it on for you.") }
        guard lastCompositionAt != nil else {
            return ("On · waiting for Gmail", false, "Open Gmail in Chrome or Chromium with the BoxCop extension, then reload Gmail. No Gmail draft has been observed this session.")
        }
        return ("On · Gmail drafts observed", true, "One advisory reminder per draft with content. BoxCop can't tell whether AI helped, and reminders never block sending.")
    }
    /// Notification click: route to the reminder's local context. Records interaction, not reading.
    func openReviewReminder(_ id: UUID) {
        focusedReviewReminder = id
        if let reminder = reviewBook.markOpened(id) {
            recordReviewState(id, "opened")
            reviewNotice = reminder.status == .live ? nil : "This draft is no longer observed. The reminder is kept here for reference."
        } else {
            reviewNotice = "That reminder is from an earlier BoxCop session or is no longer in this view. The encrypted activity journal may still hold its events."
        }
        showWindow(page: .activity)
    }
    private func observeReviewEvidence(_ event: AdapterEvent, eventID: UUID) {
        defer { refreshActionableAlerts() }
        // Capture the appended event before any side effect appends reminder-state events.
        guard event.collector == "browser.extension", let appended = workflow.events.last, appended.id == eventID else { return }
        if event.kind == ReviewPolicy.compositionKind { lastCompositionAt = Date() }
        let result = reviewBook.ingest(appended, policyEnabled: reviewPolicyEnabled)
        ReviewReminderNotifier.remove(result.ended)
        for id in result.ended { recordReviewState(id, "withdrawn") }
        switch result.update {
        case let .deliver(id)?: deliverReviewReminder(id)
        case let .recordedLate(id)?: if let delivery = reviewBook.reminder(id)?.delivery { recordReviewState(id, delivery.rawValue) }
        case let .withdraw(id)?: ReviewReminderNotifier.remove([id])
        case nil: break
        }
    }
    private func deliverReviewReminder(_ id: UUID) {
        Task { @MainActor [weak self] in
            guard let self else { return }
            let outcome = await ReviewReminderNotifier.request(id,
                stillDeliverable: { self.running && self.reviewPolicyEnabled && self.reviewBook.deliverable(id) },
                presentHeadsUp: { settings in
                    await self.offerHeadsUp(.draft, itemID: id.uuidString, settings: settings) {
                        self.running && self.reviewPolicyEnabled && self.reviewBook.deliverable(id)
                    }
                })
            // resolve() turns a request that raced a close, pause, clear, disable or send attempt into
            // withdrawn/skipped_late; remove anything macOS may still hold for it.
            let delivery = reviewBook.resolve(id, outcome)
            if delivery != .notificationRequested { ReviewReminderNotifier.remove([id]) }
            if let delivery { recordReviewState(id, delivery.rawValue) }
            reviewNotifications = await ReviewReminderNotifier.authorization()
        }
    }
    private func withdrawReviewReminders(reason: String, record: Bool) {
        defer { refreshActionableAlerts() }
        let ids = reviewBook.withdrawLive(reason: reason)
        ReviewReminderNotifier.remove(ids)
        if record { for id in ids { recordReviewState(id, "withdrawn") } }
    }
    /// Closed `review_reminder` timeline event (encrypted journal, context export), same session only.
    private func recordReviewState(_ id: UUID, _ state: String) {
        guard running, let reminder = reviewBook.reminder(id), reminder.timelineSessionID == workflow.sessionID else { return }
        workflow.append(kind: ReviewPolicy.reminderKind, collector: ReviewPolicy.collector, provenance: "derived",
                        fields: ReviewReminderBook.timelineFields(reminder, state: state), relatedEventIDs: [reminder.triggerEventID])
    }
    func setLoginEnabled(_ enabled: Bool) {
        guard !loginBusy else { return }; loginBusy = true
        Task { [weak self] in
            guard let self else { return }
            do {
                if enabled { try await Task.detached(priority: .utility) { try SMAppService.mainApp.register() }.value }
                else { try await SMAppService.mainApp.unregister() }
                refreshLoginStatus()
            } catch { refreshLoginStatus(); loginStatus = "Login-item change failed or needs approval. Check System Settings → General → Login Items." }
            loginBusy = false
        }
    }
    private func refreshLoginStatus() {
        let status = SMAppService.mainApp.status
        loginEnabled = status == .enabled
        switch status {
        case .enabled: loginStatus = choices.startsAutomatically
            ? "Launch at login enabled. Monitoring auto-starts at login because auto-start is on."
            : "Launch at login enabled. Collection still starts stopped."
        case .requiresApproval: loginStatus = "Login item needs approval in System Settings."
        case .notFound: loginStatus = "Login item unavailable. Install the packaged app first."
        default: loginStatus = "Launch at login is off."
        }
    }
}

// Only the explicit, collector-free interface renderer may install illustrative state.
extension EndpointModel {
    func configureCodeVerificationInterfacePreview(replayPath: String, expectedOutcomes: [String] = ["failed_check", "passing_check_observed", "different_tree"]) throws {
        precondition(CommandLine.arguments.contains("--dev-interface-preview"))
        choices.notifications = false; running = true; ownsSession = true
        defer { ownsSession = false }
        workflow.clear(); setCodeVerificationEnabled(true)
        for line in try String(contentsOfFile: replayPath, encoding: .utf8).split(separator: "\n") {
            let event = try AdapterEvent.decode(Data(line.utf8))
            workflow.append(kind: event.kind, collector: event.collector, phase: event.phase, fields: event.fields)
        }
        updateCodeVerification()
        precondition(codeFindings.map(\.outcome) == expectedOutcomes)
        precondition(workflow.events.filter { $0.kind == "code_verification_assessment" }.count == expectedOutcomes.count)
        codeLastUpdate = .distantPast; updateCodeVerification()
        precondition(workflow.events.filter { $0.kind == "code_verification_assessment" }.count == expectedOutcomes.count)
        let warning = codeFindings.last(where: { $0.alerts })!
        dismissCodeFinding(warning); dismissCodeFinding(warning)
        precondition(workflow.events.filter { $0.kind == "code_verification_dismissed" }.count == 1)
    }
    func verifyCodeVerificationPreviewCleanup() {
        precondition(CommandLine.arguments.contains("--dev-interface-preview"))
        setCodeVerificationEnabled(false)
        precondition(codeFindings.isEmpty && dismissedCodeFindings.isEmpty)
        setCodeVerificationEnabled(true)
        ownsSession = true; updateCodeVerification(); ownsSession = false
        precondition(codeFindings.isEmpty, "Re-enabling must not resurrect prior warnings")
        setCodeVerificationEnabled(false)
    }
    func configureEmailAlertInterfacePreview() throws {
        precondition(CommandLine.arguments.contains("--dev-interface-preview"))
        running = true; workflowReviewEnabled = true; workflowJudgment = nil
        clearEmailReviewCache()
        for _ in 0..<2 {
            let target = workflow.append(kind: "browser_composition", collector: "browser.extension", fields: ["composition_phase": WorkflowField("send_attempted")])
            func assessment(high: Bool) throws -> WorkflowJudgmentStatus {
                let email: [String: Any] = ["targetEventID": target.uuidString, "compositionID": "owned-fixture", "draftVersion": "1",
                    "phase": "send_attempted", "probability": high ? 0.9 : 0.1, "threshold": 0.75,
                    "reason": high ? "Synthetic fixture: little review activity was observed before this send attempt." : "Synthetic low-risk assessment.",
                    "eventIDs": [target.uuidString], "outcome": high ? "high_risk" : "low_risk"]
                let result: [String: Any] = ["snapshotID": String(repeating: "a", count: 64), "contextID": workflow.sessionID.uuidString,
                    "revision": 1, "observedAt": "2026-11-06T12:00:00Z", "evidenceEventIDs": [target.uuidString],
                    "intent": "Synthetic fixture", "risk": "needs_review", "findings": [], "uncertainties": [], "incomplete": false, "emailReviews": [email]]
                let status: [String: Any] = ["state": "ready", "model": "fixture", "promptVersion": "fixture", "advisoryOnly": true,
                    "superseded": false, "result": result]
                return try JSONDecoder().decode(WorkflowJudgmentStatus.self, from: JSONSerialization.data(withJSONObject: status))
            }
            let high = try assessment(high: true)
            precondition(high.isValid)
            recordEmailReviews(high)
            recordEmailReviews(try assessment(high: false))
            recordEmailReviews(high) // Same-score dedupe must never display the later low-risk reason.
        }
        precondition(pendingEmailReviewAssessments.count == 2)
        precondition(pendingEmailReviewAssessments.allSatisfy { $0.fields["reason"]?.value?.contains("little review activity") == true })
        precondition(actionableAlerts.first { $0.category == .email }?.itemIDs.count == 2)
        precondition(actionableAlerts.allSatisfy { $0.category != .protection && $0.category != .workflow })
    }
    func verifyEmailAlertPreviewLifecycle() {
        precondition(CommandLine.arguments.contains("--dev-interface-preview"))
        let target = pendingEmailReviewAssessments.first!.relatedEventIDs.first!
        dismissEmailReviewAlert(target)
        precondition(pendingEmailReviewAssessments.count == 1)
        precondition(workflow.events.contains { $0.kind == "email_review_assessment" && $0.relatedEventIDs.first == target })
        running = false
        precondition(pendingEmailReviewAssessments.isEmpty)
        running = true
        setWorkflowReviewEnabled(false)
        precondition(pendingEmailReviewAssessments.isEmpty && pendingEmailReviewTargets.isEmpty)
        precondition(!actionableAlerts.contains { $0.category == .email || $0.category == .workflow })
    }
    func verifyCodeReviewInvalidationPreview(clearLiveView: Bool) {
        precondition(CommandLine.arguments.contains("--dev-interface-preview"))
        precondition(codeFindings.contains { $0.alerts })
        if clearLiveView {
            clearWorkflow()
            precondition(workflow.events.isEmpty)
        } else {
            // Exercise the same synchronous code invalidation used by halt(), without
            // starting/stopping real collectors in this collector-free renderer.
            running = false
            clearCodeVerification()
        }
        precondition(codeFindings.isEmpty && dismissedCodeFindings.isEmpty && codeNotificationIDs.isEmpty)
        running = true; ownsSession = true
        updateCodeVerification()
        ownsSession = false
        precondition(codeFindings.isEmpty, "Clear/resume must not resurrect earlier review evidence")
    }
    func configurePDFReviewInterfacePreview(snapshot: LocalPDFSnapshot, document: PDFDocument) {
        precondition(CommandLine.arguments.contains("--dev-interface-preview"))
        running = true; pdfReviewEnabled = true
        let fields = ["url": "https://mail.google.com/mail/u/0/", "tab_id": "1", "frame_id": "0",
            "navigation_id": "owned-ui-fixture", "browser_session": "owned-browser-fixture",
            "selection_id": UUID().uuidString, "artifact_sha256": snapshot.identity.sha256,
            "file_size": String(snapshot.identity.byteCount), "mime_type": "application/pdf", "file_name": snapshot.filename,
            "observed_at_ms": String(Int64(Date().timeIntervalSince1970 * 1000))]
        workflow.append(kind: "browser_pdf_selected", collector: "browser.extension", provenance: "reported",
                        fields: fields.mapValues { WorkflowField($0, provenance: "reported") })
        pdfReviewBook.observe(workflow.events.last!)
        let check = PDFRenderCheck.inspect(snapshot.data)
        let before = workflow.events.count
        installPDFPreview(snapshot: snapshot, document: document, renderCheck: check, generation: UUID())
        precondition(workflow.events.count == before && pdfPreview == nil)
        running = false
        installPDFPreview(snapshot: snapshot, document: document, renderCheck: check, generation: pdfReviewGeneration)
        precondition(workflow.events.count == before && pdfPreview == nil)
        running = true; pdfReviewEnabled = false
        installPDFPreview(snapshot: snapshot, document: document, renderCheck: check, generation: pdfReviewGeneration)
        precondition(workflow.events.count == before && pdfPreview == nil)
        pdfReviewEnabled = true
        installPDFPreview(snapshot: snapshot, document: document, renderCheck: check, generation: pdfReviewGeneration)
        precondition(workflow.events.last?.kind == "pdf_render_check")
        precondition(workflow.events.last?.fields["potentially_blank_pages"]?.value == "2")
    }
    /// Synthetic reminder evidence through the real decode -> timeline -> ReviewReminderBook path.
    /// No notification center, permission, collector, model or team state is touched.
    func configureReviewReminderPreview(notificationsAllowed: Bool) {
        precondition(CommandLine.arguments.contains("--dev-interface-preview"))
        running = true; browserConnected = true
        reviewPolicyEnabled = true
        reviewNotifications = notificationsAllowed ? .allowed : .denied
        reviewNotice = nil
        workflow.clear()
        reviewBook = ReviewReminderBook()
        let base = Date().addingTimeInterval(-900)
        var revisions: [String: Int] = [:]
        func observe(_ phase: String, _ id: String, surface: String, at offset: TimeInterval) -> ReviewReminderBook.Ingest? {
            revisions[id, default: 0] += 1
            var fields = ["url": "https://mail.google.com/mail/u/0/", "tab_id": "11", "frame_id": "0", "navigation_id": "PREVIEW-DOCUMENT",
                          "browser_session": "preview", "composition_id": id, "composition_phase": phase, "composition_surface": surface,
                          "content_state": phase == "opened" ? "empty" : "nonempty", "revision": String(revisions[id] ?? 1),
                          "observed_at_ms": String(Int64(base.addingTimeInterval(offset).timeIntervalSince1970 * 1000))]
            if phase == "prepared" { fields["content_origin"] = "pasted" }
            if phase == "send_attempted" { fields["send_signal"] = "shortcut" }
            guard let bytes = try? JSONSerialization.data(withJSONObject: ["version": 1, "kind": ReviewPolicy.compositionKind, "fields": fields]),
                  let event = try? AdapterEvent.decode(bytes), let observed = event.observedAt else { return nil }
            workflow.append(kind: event.kind, collector: event.collector, at: observed, phase: event.phase, provenance: "reported", fields: event.fields)
            guard let appended = workflow.events.last else { return nil }
            let result = reviewBook.ingest(appended, policyEnabled: true, now: observed.addingTimeInterval(0.05))
            switch result.update {
            case let .deliver(reminder)?:
                if let delivery = reviewBook.resolve(reminder, notificationsAllowed ? .notificationRequested : .inAppOnly, at: observed.addingTimeInterval(0.2)) {
                    recordReviewState(reminder, delivery.rawValue)
                }
            case let .recordedLate(reminder)?:
                if let delivery = reviewBook.reminder(reminder)?.delivery { recordReviewState(reminder, delivery.rawValue) }
            default: break
            }
            return result
        }
        let sent = "aaaaaaaa-1111-4111-8111-000000000001", late = "aaaaaaaa-3333-4333-8333-000000000003"
        let reply = "aaaaaaaa-2222-4222-8222-000000000002"
        _ = observe("opened", sent, surface: "dialog", at: 0)
        _ = observe("prepared", sent, surface: "dialog", at: 4)
        _ = observe("send_attempted", sent, surface: "dialog", at: 95)
        _ = observe("closed", sent, surface: "dialog", at: 96)
        _ = observe("opened", late, surface: "dialog", at: 300)
        _ = observe("send_attempted", late, surface: "dialog", at: 301)
        _ = observe("prepared", late, surface: "dialog", at: 301.1)
        _ = observe("opened", reply, surface: "inline", at: 600)
        _ = observe("prepared", reply, surface: "inline", at: 603)
        if let id = reviewBook.reminders.first(where: { $0.anchor.compositionID == reply })?.id {
            focusedReviewReminder = id
            if notificationsAllowed, reviewBook.markOpened(id, at: base.addingTimeInterval(640)) != nil { recordReviewState(id, "opened") }
        }
        lastCompositionAt = Date()
    }
    func configureActiveInterfacePreview(withFinding: Bool) {
        precondition(CommandLine.arguments.contains("--dev-interface-preview"))
        running = true
        guardActive = true
        hostAgentStatus = "Claude Code and Codex hooks registered; review callback coverage in Connections"
        backgroundScreenStatus = "Screen warnings enabled; waiting for screen capture."
        inventoryCheckedAt = Date()
        let advisory = ExposureAdvisory(id: "Illustrative advisory", state: "review_needed",
            source: "", verification: "Preview only", prerequisites: "Illustrative finding; not a scan of this Mac.",
            remediation: "Install a fixed release of Tailscale, then recheck software to verify the installed version.",
            affectedRange: "Illustrative older release", fixedVersions: "See vendor guidance")
        softwareInventory = SoftwareInventoryReport(schema: "boxcop.software-inventory.v2",
            generatedAt: "Just now · illustrative preview", reviewedAt: "Preview", incomplete: false,
            issues: [], limitations: nil, issueDetails: nil, roots: nil, coverage: "Illustrative data only", elapsedMs: 0, cacheStatus: "saved",
            records: withFinding ? [SoftwareObservation(id: "preview-tailscale", name: "Tailscale", version: "(older release)",
                path: "/Applications/Tailscale.app", kind: "app", advisories: [advisory])] : [])
        if withFinding {
            softwareInventory?.remediationItems = [
                SoftwareFixItem(id: "preview-node", name: "node", versions: "26.0.0", location: "/opt/homebrew/Cellar/node", adapter: "homebrew", detail: "Update through Homebrew. Preview includes dependency changes; restart running consumers afterward.", observationIds: []),
                SoftwareFixItem(id: "preview-pillow", name: "pillow", versions: "12.2.0", location: "~/.pyenv/versions/3.12.4/lib/python3.12/site-packages", adapter: "pillow", detail: "Resolve a fixed Pillow wheel for this Python environment. Review compatibility before applying.", observationIds: []),
                SoftwareFixItem(id: "preview-brotli", name: "brotli", versions: "1.2.0", location: "/opt/homebrew/Cellar/brotli", adapter: "homebrew_cleanup", detail: "Fixed version installed; old copy remains.", observationIds: []),
                SoftwareFixItem(id: "preview-ruby", name: "ruby", versions: "4.0.3", location: "/opt/homebrew/Cellar/ruby", adapter: "homebrew", detail: "Update through Homebrew.", observationIds: []),
                SoftwareFixItem(id: "preview-pillow-old", name: "pillow", versions: "10.4.0", location: "~/.pyenv/versions/3.9.19/lib/python3.9/site-packages", adapter: "pillow", detail: "Review environment compatibility.", observationIds: []),
                SoftwareFixItem(id: "preview-review", name: "node", versions: "20.11.0", location: "~/.nvm/versions/node/v20.11.0", adapter: "review", detail: "Migration needed.", observationIds: []),
                SoftwareFixItem(id: "preview-review-2", name: "node", versions: "24.1.0", location: "~/.nvm/versions/node/v24.1.0", adapter: "review", detail: "Migration needed.", observationIds: []),
                SoftwareFixItem(id: "preview-browser", name: "claude-browser", versions: "2.19675.0", location: "/Applications/Claude.app", adapter: "review", detail: "Verify vendor fix.", observationIds: [])
            ]
            selectedSoftwareFixes = Set((softwareInventory?.remediationItems ?? []).filter(\.automatic).map(\.id))
        }
        networkConnections.extensionState = .installed
        networkConnections.filterEnabled = true
        networkConnections.snapshot = NetworkActivitySnapshot(events: [], observed: 12, dropped: 0,
            writeFailures: 0, lastFlow: Date(), startedAt: Date(), retentionBytes: 1024,
            threatProtection: NetworkThreatStatus(enabled: true, domainCount: 1, source: "Preview", revision: "Preview", publishedAt: "Preview", error: nil))
        workflow.clear()
        workflow.append(kind: "screen_share_preflight", collector: "CGEventTap.AX.OCR", availability: "share_blocked_sensitive", at: Date().addingTimeInterval(-1800))
        workflow.append(kind: "network_connection", collector: "NetworkExtension", at: Date().addingTimeInterval(-300),
            fields: ["decision": WorkflowField("blocked_threat_domain"), "hostname": WorkflowField("example.test"),
                     "threat_reason": WorkflowField("Destination matched the threat domain list. Illustrative event.")])
    }
}

#endif
