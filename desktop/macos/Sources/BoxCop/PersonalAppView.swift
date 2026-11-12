#if os(macOS)
import SwiftUI

/// Navigation is shared with the menu so each destination opens the actual window.
enum EndpointPage: String, CaseIterable, Identifiable {
    case protection = "Home", approvals = "Approvals", connections = "Connections", activity = "Activity", policies = "Policies", settings = "Settings"
    var id: String { rawValue }
    var symbol: String {
        switch self {
        case .approvals: return "checkmark.shield"
        case .protection: return "house"
        case .connections: return "point.3.connected.trianglepath.dotted"
        case .activity: return "clock"
        case .policies: return "slider.horizontal.3"
        case .settings: return "gearshape"
        }
    }

}

struct EndpointView: View {
    @ObservedObject var model: EndpointModel
    var body: some View {
        if model.onboardingPresented && model.teamInvitation == nil {
            OnboardingView(model: model)
                .background(AppPalette.canvas)
                .foregroundStyle(AppPalette.ink)
                .font(.system(size: 13))
                .tint(AppPalette.accent)
                .frame(minWidth: 720, minHeight: 580)
        } else {
            application
        }
    }
    private var application: some View {
        HStack(spacing: 0) {
            sidebar
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    HStack {
                        Label(model.teamConnection.isTeam ? "Team · \(model.teamConnection.state.organization ?? "This Mac")" : "Personal · This Mac", systemImage: model.teamConnection.isTeam ? "person.2" : "person.crop.circle")
                        Spacer()
                        Text(model.releaseProfile == .distribution ? (model.releaseChannel == .beta ? "Beta" : "Stable") : model.releaseProfile == .limitedDevelopment ? "Limited development" : "Development preview")
                    }.font(.system(size: 11)).foregroundStyle(AppPalette.quiet)
                    Divider()
                    VStack(alignment: .leading, spacing: 8) {
                        Text(model.selectedPage.rawValue).font(.system(size: 23, weight: .semibold))
                    }
                    content
                }.padding(.vertical, 23).padding(.horizontal, 26).frame(maxWidth: 900, alignment: .leading).frame(maxWidth: .infinity)
            }.id(model.selectedPage)
                .background(AppPalette.canvas)
        }
        .background(AppPalette.canvas)
        .foregroundStyle(AppPalette.ink)
        .font(.system(size: 13))
        .tint(AppPalette.accent)
        .groupBoxStyle(AppCardStyle())
        .frame(minWidth: 780, minHeight: 560)
        .sheet(item: $model.alertFeedbackCategory) { AlertFeedbackForm(category: $0) }
        .sheet(item: $model.pdfPreview) { preview in PDFPreviewSheet(model: model, preview: preview) }
        .sheet(isPresented: $model.softwareReviewPresented) {
            VStack(alignment: .leading, spacing: 16) {
                HStack {
                    Text("Software review").font(.title2.bold())
                    Spacer()
                    Button("Done") { model.softwareReviewPresented = false }
                }
                ScrollView { EndpointDetails(model: model, section: .software) }
            }.padding(24).frame(width: 900, height: 700)
        }
        .disabled(model.teamInvitation != nil)
        .overlay {
            if let invitation = model.teamInvitation {
                ZStack {
                    Color.black.opacity(0.16).ignoresSafeArea()
                    TeamInvitationView(connection: model.teamConnection, invitation: invitation, close: model.closeTeamInvitation)
                        .background(AppPalette.canvas, in: RoundedRectangle(cornerRadius: 12))
                        .shadow(color: .black.opacity(0.2), radius: 18, y: 6)
                }
            }
        }
        .environmentObject(model.productSupport)
    }
    private var sidebar: some View {
        VStack(alignment: .leading, spacing: 6) {
            BoxCopBrand()
                .padding(.horizontal, 12).padding(.top, 20).padding(.bottom, 24)
            ForEach(EndpointPage.allCases) { page in
                Button { model.selectedPage = page } label: {
                    HStack(spacing: 4) {
                        Label(page.rawValue, systemImage: page.symbol)
                        Spacer(minLength: 0)
                        if page == .approvals, !model.approvals.pending.isEmpty {
                            Text("\(model.approvals.pending.count)")
                                .font(.caption2.weight(.semibold)).monospacedDigit()
                                .padding(.horizontal, 6).padding(.vertical, 1)
                                .background(Color.orange, in: Capsule()).foregroundStyle(.white)
                                .accessibilityLabel("\(model.approvals.pending.count) waiting for approval")
                        }
                    }
                        .frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal, 10).padding(.vertical, 8)
                        .background(model.selectedPage == page ? AppPalette.selection : .clear, in: RoundedRectangle(cornerRadius: 7))
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .foregroundStyle(model.selectedPage == page ? AppPalette.accent : .secondary)
                .accessibilityAddTraits(model.selectedPage == page ? .isSelected : [])
            }
            Spacer()
            VStack(alignment: .leading, spacing: 6) {
                Text("No account required")
                    .font(.caption).foregroundStyle(.secondary)
                Divider().padding(.vertical, 8)
                Label(model.running ? "Monitoring" : model.starting ? "Starting…" : "Monitoring paused",
                      systemImage: model.running ? "circle.fill" : "circle")
                    .font(.caption).foregroundStyle(.secondary)
                Text("Coverage varies by connection.").font(.caption2).foregroundStyle(.secondary)
            }.padding(12)
        }.padding(.horizontal, 10).padding(.bottom, 10)
            .frame(width: 164).background(AppPalette.sidebar)
    }
    @ViewBuilder private var content: some View {
        switch model.selectedPage {
        case .approvals: HumanReviewView(model: model, approvals: model.approvals)
        case .protection: ProtectionDashboard(model: model, network: model.networkConnections)
        case .connections:
            ProtectionSetupView(model: model)
        case .activity:
            if model.codeVerificationEnabled { CodeVerificationActivity(model: model) }
            if model.pdfReviewEnabled { PDFReviewActivity(model: model) }
            if model.showsHumanChecks { ReviewRemindersCard(model: model) }
            SecurityActivityFeed(records: model.records, events: model.workflow.events)
            if model.releaseProfile.usesNetworkProtection {
                NetworkConnectionsView(model: model.networkConnections, openSetup: { model.selectedPage = .connections })
            }
            if model.showsHumanChecks { EndpointDetails(model: model, section: .paste) }
            if model.workflowReviewEnabled {
                EmailReviewAlertsCard(model: model)
                WorkflowJudgmentView(status: model.workflowJudgment)
            }
            DisclosureGroup("Workflow activity & details") {
                EndpointDetails(model: model, section: .decisions)
                EndpointDetails(model: model, section: .workflow)
                Text(model.workflowContextStatus).font(.caption).textSelection(.enabled)
                Button("Export activity details…") { model.exportWorkflowContext() }
                Text("Exports may contain private activity details. Review them before sharing.")
                    .font(.caption).foregroundStyle(.secondary)
                Text("Clearing the workflow live view keeps saved activity, decisions, diagnostics and captures. Network history is unchanged.")
                    .font(.caption).foregroundStyle(.secondary)
                Button("Clear workflow live view", role: .destructive) { model.clearWorkflow() }
                    .disabled(model.workflow.events.isEmpty)
                Text(model.journalStatus).font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
            }
        case .policies:
            GroupBox("Code checks and review") {
                VStack(alignment: .leading, spacing: 8) {
                    Toggle("Warn about failed checks or stale code evidence", isOn: Binding(get: { model.codeVerificationEnabled }, set: model.setCodeVerificationEnabled))
                    Text("Show advisory warnings for instrumented Python or Node.js tests and pushes, plus explicit GitHub CLI merge requests with commit-bound CI results. Decisions run locally without AI; GitHub observations require the adapter’s --github-checks option and use your existing CLI credentials for bounded read-only API queries. The separate --github-reviews option observes explicit PR diff/approval commands and warns about changed versions within the same --run-id. Diff output is not proof of reading. Other tools and web actions remain unknown. Actions are never blocked.")
                        .font(.caption).foregroundStyle(.secondary)
                    Button("Open code checks") { model.selectedPage = .activity }
                }.frame(maxWidth: .infinity, alignment: .leading)
            }
            if model.showsHumanChecks {
            EmailReviewPolicyCard(model: model)
            GroupBox("PDF attachment review") {
                VStack(alignment: .leading, spacing: 8) {
                    Toggle("Review PDF attachments locally", isOn: Binding(get: { model.pdfReviewEnabled }, set: model.setPDFReviewEnabled))
                    Text("Compare Gmail attachments with PDF pages displayed in BoxCop. Enable PDF review in the browser extension too. BoxCop processes previews locally without an AI model. Previews in other apps remain unknown. Local previews also flag potentially blank pages for your inspection.")
                        .font(.caption).foregroundStyle(.secondary)
                    Button("Open PDF review") { model.selectedPage = .activity }.disabled(!model.pdfReviewEnabled)
                }.frame(maxWidth: .infinity, alignment: .leading)
            }
            DisclosureGroup("Reminders for every Gmail draft") {
                ReviewPolicyCard(model: model)
            }
            } else {
                HumanChecksOptIn(model: model)
            }
        case .settings:
            LocalPrivacyCard(isTeam: model.teamConnection.isTeam)
            ProductSupportSettings(support: model.productSupport)
            GroupBox("Background monitoring") {
                VStack(alignment: .leading, spacing: 12) {
                    HStack {
                        Text(model.menuStatus)
                        Spacer()
                        Button(model.running || model.starting ? "Pause" : "Resume") {
                            if model.running || model.starting { model.pause() } else { model.start() }
                        }.disabled(model.stopping || (!model.running && !model.starting && !model.canStart))
                    }
                    Text("Pausing stops activity monitoring and paste protection. Connected agent checks and system protection services stay active.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            HumanChecksSettings(model: model)
            if model.showsHumanChecks {
                DisclosureGroup("Paste protection") {
                    EndpointDetails(model: model, section: .guardSettings)
                }
            }
            EndpointDetails(model: model, section: .integration)
            TeamModeView(connection: model.teamConnection)
            DisclosureGroup("Monitoring permissions") {
                EndpointDetails(model: model, section: .consent)
                Button("Set up BoxCop…") { model.onboardingPresented = true }
            }
            DisclosureGroup("Protection limits") {
                EndpointDetails(model: model, section: .limits)
            }
            DisclosureGroup("Help & diagnostics") {
                EndpointDetails(model: model, section: .diagnostics)
                EndpointDetails(model: model, section: .liveStatus)
                Button("Privacy & removal guide") { model.revealBundledResource("BoxCop Guide.md") }
            }
        }
    }
}

/// Settings control for checks on the person's own actions. Turning it off also turns them off.
struct HumanChecksSettings: View {
    @ObservedObject var model: EndpointModel
    var body: some View {
        GroupBox("Checks on your own actions") {
            VStack(alignment: .leading, spacing: 8) {
                Toggle("Show paste, screen-sharing and email review checks", isOn: Binding(get: { model.showsHumanChecks }, set: model.setHumanChecksShown))
                    .disabled(model.teamConnection.isTeam)
                Text(model.teamConnection.isTeam
                     ? "Your team uses these checks. Their settings are in Connections and Policies."
                     : "These catch your own mistakes, such as pasting a malicious command or sharing a secret on screen. They’re mostly useful for teams and need extra macOS permissions. Turning this off also turns these checks off. Agent protection isn’t affected.")
                    .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }.frame(maxWidth: .infinity, alignment: .leading).padding(8)
        }
    }
}

#endif
