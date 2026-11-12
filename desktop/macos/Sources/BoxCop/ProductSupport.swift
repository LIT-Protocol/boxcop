#if os(macOS)
import SwiftUI
import BoxCopCore

@MainActor final class ProductSupport: ObservableObject {
    private static let stateKey = "boxcop.support.crashReporting.v1"
    private let defaults: UserDefaults
    private let client: ProductReportClient
    private let reportDirectories: [URL]
    private var state: CrashReportingState
    private var task: Task<Void, Never>?
    private var generation = UUID()
    private var active = false
    @Published private(set) var crashReportingEnabled: Bool
    @Published private(set) var crashStatus = ""
    let build: ProductBuild

    init(defaults: UserDefaults = .standard, client: ProductReportClient = ProductReportClient(), reportDirectories: [URL]? = nil) {
        self.defaults = defaults; self.client = client
        let base = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Logs/DiagnosticReports")
        let system = URL(fileURLWithPath: "/Library/Logs/DiagnosticReports")
        self.reportDirectories = reportDirectories ?? [base, base.appendingPathComponent("Retired"), system, system.appendingPathComponent("Retired")]
        state = defaults.data(forKey: Self.stateKey).flatMap { try? JSONDecoder().decode(CrashReportingState.self, from: $0) } ?? CrashReportingState()
        crashReportingEnabled = state.enabledSince != nil
        build = ProductBuild(version: Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0.0.0",
                             build: Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "0") ?? ProductBuild(version: "0.0.0", build: "0")!
    }
    func activate() { active = true; startReporting() }
    func stop() { active = false; generation = UUID(); task?.cancel(); task = nil }
    func setCrashReporting(_ enabled: Bool) {
        generation = UUID(); task?.cancel(); task = nil
        state.setEnabled(enabled); crashReportingEnabled = enabled; crashStatus = ""
        save()
        startReporting()
    }
    private func save() {
        if state.enabledSince == nil { defaults.removeObject(forKey: Self.stateKey) }
        else if let data = try? JSONEncoder().encode(state) { defaults.set(data, forKey: Self.stateKey) }
    }
    private func startReporting() {
        guard active, crashReportingEnabled, task == nil else { return }
        let token = generation
        task = Task { [weak self] in
            while !Task.isCancelled {
                guard let self, self.generation == token, self.crashReportingEnabled else { return }
                await self.scan(token: token)
                do { try await Task.sleep(nanoseconds: 30 * 60 * 1_000_000_000) } catch { return }
            }
        }
    }
    private func scan(token: UUID) async {
        state.prune(); save()
        let directories = reportDirectories
        let snapshot = state
        let scan = Task.detached(priority: .utility) { CrashReport.candidates(in: directories, state: snapshot) }
        let candidates = await withTaskCancellationHandler(operation: { await scan.value }, onCancel: { scan.cancel() })
        for candidate in candidates {
            guard !Task.isCancelled, generation == token, state.shouldSend(candidate) else { return }
            do {
                try await client.send(candidate.report)
                guard !Task.isCancelled, generation == token, crashReportingEnabled else { return }
                state.acknowledge(candidate); save()
                crashStatus = "Crash report sent."
            } catch {
                guard !Task.isCancelled, generation == token else { return }
                crashStatus = "Crash report delivery could not be confirmed. BoxCop will retry while reporting is on."
                return
            }
        }
    }
}

struct ProductSupportSettings: View {
    @ObservedObject var support: ProductSupport
    @State private var category = AlertFeedbackCategory.paste
    var body: some View {
        GroupBox("Crash reports & alert feedback") {
            VStack(alignment: .leading, spacing: 12) {
                Toggle("Send crash reports to BoxCop", isOn: Binding(get: { support.crashReportingEnabled }, set: support.setCrashReporting))
                Text("Optional. Sends crash diagnostics for the BoxCop Mac app after you turn this on: app and macOS versions, processor architecture, crash type and stack offsets. No screenshots, activity history, paths or diagnostic messages are attached. Reports are kept for 30 days.")
                    .font(.caption).foregroundStyle(.secondary)
                Text("Reports are sent when BoxCop is open, including after you reopen it following a crash. Turning this off stops future reports and retries. It cannot recall reports already sent.")
                    .font(.caption).foregroundStyle(.secondary)
                if !support.crashStatus.isEmpty { Text(support.crashStatus).font(.caption) }
                Divider()
                Text("Feedback about an alert")
                HStack {
                    Picker("Alert category", selection: $category) { ForEach(AlertFeedbackCategory.allCases) { Text($0.title).tag($0) } }
                    AlertFeedbackButton(category: category)
                }
                Text("You can send written feedback even when crash reporting is off. You can also choose Give feedback beside an alert.")
                    .font(.caption).foregroundStyle(.secondary)
            }.frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

/// A local form per presentation; opening, editing and cancelling produce no requests.
struct AlertFeedbackButton: View {
    let category: AlertFeedbackCategory
    @State private var showing = false
    var body: some View {
        Button("Give feedback…") { showing = true }
            .buttonStyle(.plain).font(.caption).foregroundStyle(.secondary)
            .help("Write optional feedback about this alert")
            .sheet(isPresented: $showing) { AlertFeedbackForm(category: category) }
    }
}

struct AlertFeedbackForm: View {
    let category: AlertFeedbackCategory
    @EnvironmentObject private var support: ProductSupport
    @Environment(\.dismiss) private var dismiss
    @StateObject private var draft = AlertFeedbackDraft()
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Feedback about this alert").font(.title2.bold())
            Text(category.title).font(.headline)
            Text("What was wrong, unclear or helpful? Your message goes to the BoxCop team.")
            TextEditor(text: $draft.text).font(.body).frame(height: 150)
                .border(Color.secondary.opacity(0.3)).disabled(draft.sending || draft.sent)
                .accessibilityLabel("Written feedback")
            Text("\(draft.text.utf8.count) / \(AlertFeedbackReport.maximumTextBytes) bytes").font(.caption).foregroundStyle(.secondary)
            Text("Sends only what you write, the alert category, and BoxCop version \(support.build.version) (\(support.build.build)). Alert details, screenshots and history are not attached. Avoid including private information. Feedback is kept for 30 days.")
                .font(.caption).foregroundStyle(.secondary)
            if let message = draft.message { Text(message).font(.callout).accessibilityIdentifier("feedback-status") }
            HStack {
                Button(draft.sent ? "Done" : "Cancel") { draft.cancel(); dismiss() }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                if draft.sending { ProgressView().controlSize(.small) }
                if !draft.sent {
                    Button(draft.sending ? "Sending…" : "Send feedback") { draft.send(build: support.build, category: category) }
                        .buttonStyle(.borderedProminent)
                        .disabled(draft.sending || !AlertFeedbackReport.validText(draft.text))
                }
            }
        }.padding(24).frame(width: 520).background(AppPalette.canvas).foregroundStyle(AppPalette.ink)
            .interactiveDismissDisabled(draft.sending)
            .onDisappear { draft.cancel() }
    }
}

@MainActor final class AlertFeedbackDraft: ObservableObject {
    @Published var text = "" { didSet { if text != oldValue { reportID = UUID(); message = nil } } }
    @Published private(set) var sending = false
    @Published private(set) var sent = false
    @Published private(set) var message: String?
    private var reportID = UUID()
    private var task: Task<Void, Never>?
    private let client: ProductReportClient
    init(client: ProductReportClient = ProductReportClient()) { self.client = client }
    func cancel() { task?.cancel(); task = nil }
    func send(build: ProductBuild, category: AlertFeedbackCategory) {
        guard !sending, !sent, let report = AlertFeedbackReport(id: reportID, build: build, category: category, text: text) else { return }
        sending = true; message = nil
        task = Task { @MainActor in
            defer { sending = false }
            do {
                try await client.send(report)
                guard !Task.isCancelled else { return }
                sent = true; message = "Thank you. Your feedback was sent."
            } catch {
                guard !Task.isCancelled else { return }
                switch error as? ProductReportError {
                case .rateLimited:
                    message = "Too many reports right now. Your text is still here; please try again later."
                case .rejected:
                    message = "BoxCop couldn’t accept this report. Your text is still here. Check for an app update before trying again."
                default:
                    message = "Couldn’t confirm delivery. Your text is still here. Try again to resend the same report."
                }
            }
        }
    }
}
#endif
