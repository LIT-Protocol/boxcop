#if os(macOS)
import SwiftUI
import BoxCopCore

/// Settings, About and Help. The limits that apply to every layer are written once, here.
struct SettingsView: View {
    @ObservedObject var model: AppModel
    @State private var confirmRemoval = false

    /// What BoxCop does not do. Short and honest.
    static let limits: [(String, String)] = [
        ("Agent checks are cooperative.", "They rely on hooks in Claude Code, Codex and Cursor. Other agents, cloud agents and anything an agent does outside its hooks are not checked."),
        ("Cached packages skip the install gate.", "A package already in the npm or pip cache, or installed before BoxCop was turned on, is not checked again."),
        ("The threat list matches exact hosts only.", "A host that is not on the list, a connection to a bare IP address and traffic inside a VPN or proxy are recorded but not blocked."),
        ("Encrypted traffic is not inspected.", "BoxCop sees which app connects to which host. It never reads what is sent."),
        ("The local model is advisory.", "Its explanations can be wrong. It can ask for a closer look but can never allow something a rule blocked."),
        ("Machine health reads versions.", "A finding means an installed version has a known issue. It is not proof of an attack, and no finding is not proof of safety.")
    ]

    var body: some View {
        PageScaffold(title: "Settings") {
            section("General") {
                toggleRow("Start BoxCop at login", model.loginMessage.isEmpty ? "Keeps protection on after a restart." : model.loginMessage,
                          Binding(get: { model.loginEnabled }, set: { model.setLoginEnabled($0) }))
                RowDivider()
                toggleRow("Notifications", model.notificationMessage.isEmpty ? "One notification when something is blocked, with a link to the event." : model.notificationMessage,
                          Binding(get: { model.notificationsEnabled }, set: { model.setNotifications($0) }))
                if let updater = model.updater, updater.enabled {
                    RowDivider()
                    UpdateRow(updater: updater)
                }
            }
            section("Protection") {
                actionRow(model.paused ? "Protection is paused" : "Pause protection",
                          model.paused ? "Package checks, containment, threat blocking and credential protection are off. Agent hooks stay connected."
                                       : "Turns off package checks, containment, threat blocking and credential protection until you resume. Agent hooks stay connected.") {
                    Button(model.paused ? "Resume" : "Pause") { if model.paused { model.resume() } else { model.pause() } }.buttonStyle(model.paused ? AnyButtonStyle(.primary) : AnyButtonStyle(.quiet))
                }
                RowDivider()
                actionRow("Remove BoxCop's integrations", model.removalMessage.isEmpty
                          ? "Removes the agent hooks, package routing, script routing, network filtering and credential protection. Do this before deleting the app." : model.removalMessage) {
                    Button("Remove") { confirmRemoval = true }.buttonStyle(QuietButtonStyle(tint: Palette.red))
                }
            }
            section("About") {
                infoRow("Version", model.capabilities.version)
                RowDivider()
                infoRow("App", Bundle.main.bundleIdentifier ?? "Development build")
                RowDivider()
                infoRow("Data on this Mac", EngineTools.dataDirectory.path.replacingOccurrences(of: NSHomeDirectory(), with: "~"))
                RowDivider()
                infoRow("Privacy", "No account. Protection decisions stay on this Mac. Updates and security feeds require downloads.")
            }
            VStack(alignment: .leading, spacing: 7) {
                SectionTitle("Help: what BoxCop does not do")
                RowGroup {
                    ForEach(Array(Self.limits.enumerated()), id: \.offset) { index, limit in
                        if index > 0 { RowDivider() }
                        VStack(alignment: .leading, spacing: 2) {
                            Text(limit.0).font(.system(size: 12.5, weight: .semibold))
                            Text(limit.1).font(.system(size: 12)).foregroundStyle(Palette.quiet).fixedSize(horizontal: false, vertical: true)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.horizontal, 12).padding(.vertical, 8)
                    }
                }
            }
        }
        .confirmationDialog("Remove BoxCop's integrations?", isPresented: $confirmRemoval, titleVisibility: .visible) {
            Button("Remove hooks, routing and system protection", role: .destructive) { model.removeIntegrations() }
        } message: {
            Text("Agents, npm and pip go back to how they were before BoxCop. Your event history and settings stay on this Mac.")
        }
    }

    private func section<Content: View>(_ title: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 7) {
            SectionTitle(title)
            RowGroup { content() }
        }
    }
    private func label(_ title: String, _ detail: String) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(title).font(.system(size: 12.5, weight: .medium))
            Text(detail).font(.system(size: 11.5)).foregroundStyle(Palette.quiet).fixedSize(horizontal: false, vertical: true)
        }
    }
    private func toggleRow(_ title: String, _ detail: String, _ value: Binding<Bool>) -> some View {
        HStack(spacing: 12) {
            label(title, detail)
            Spacer()
            Toggle("", isOn: value).toggleStyle(SwitchStyle()).labelsHidden().accessibilityLabel(title)
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
    }
    private func actionRow<Trailing: View>(_ title: String, _ detail: String, @ViewBuilder trailing: () -> Trailing) -> some View {
        HStack(spacing: 12) {
            label(title, detail)
            Spacer()
            trailing()
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
    }
    private func infoRow(_ title: String, _ value: String) -> some View {
        HStack(spacing: 12) {
            Text(title).font(.system(size: 12.5, weight: .medium)).frame(width: 130, alignment: .leading)
            Text(value).font(.system(size: 12)).foregroundStyle(Palette.quiet).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
            Spacer()
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
    }
}

private struct UpdateRow: View {
    @ObservedObject var updater: AppUpdater
    var body: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 1) {
                Text("Updates").font(.system(size: 12.5, weight: .medium))
                Toggle("Check automatically", isOn: $updater.automaticallyChecksForUpdates).toggleStyle(.checkbox).font(.system(size: 11.5))
            }
            Spacer()
            Button(updater.availableVersion.map { "Update to \($0)" } ?? "Check for updates") { updater.checkForUpdates() }
                .buttonStyle(.quiet).disabled(!updater.canCheckForUpdates && updater.availableVersion == nil)
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
    }
}

/// Lets one call site pick between two button styles.
struct AnyButtonStyle: ButtonStyle {
    private let body: (Configuration) -> AnyView
    init<Style: ButtonStyle>(_ style: Style) { body = { AnyView(style.makeBody(configuration: $0)) } }
    func makeBody(configuration: Configuration) -> some View { body(configuration) }
}
#endif
