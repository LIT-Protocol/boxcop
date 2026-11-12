#if os(macOS)
import SwiftUI
import BoxCopCore

/// Coverage claims use live guard state; registration and historical observations
/// are deliberately not promoted to a general "protected" indicator.
struct ProtectionSetupView: View {
    @ObservedObject var model: EndpointModel
    @State private var extensionID = ""
    @State private var confirmRemoval = false
    @State private var presentationWindow: UInt32 = 0
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            PackageProtectionView(model: model)
            InstallScriptProtectionView(model: model)
            ConnectionCard(title: "Agent actions", status: model.hostAgentStatus, symbol: "terminal") {
                VStack(alignment: .leading, spacing: 12) {
                ForEach(model.agentConnections) { connection in
                    VStack(alignment: .leading, spacing: 5) {
                        Text(connection.id.capitalized + " · " + connection.state).fontWeight(.medium)
                        Text("Checks: " + connection.coverage)
                        Text("Last activity check (UTC): " + connection.lastCallback)
                        Text(connection.nextStep)
                        ForEach(connection.actions) { action in
                            VStack(alignment: .leading, spacing: 2) {
                                Text(action.title + " · " + action.state)
                                Text("Last callback (UTC): " + action.lastCallback).foregroundStyle(.secondary)
                                Text(action.verification).foregroundStyle(.secondary)
                                if action.state != "callback observed" { Text(action.nextStep).foregroundStyle(.secondary) }
                            }.padding(.leading, 8)
                        }
                    }.font(.caption).textSelection(.enabled)
                }
                Text("Effect tests cover only the recorded CLI and named action. Recheck after updates; changed binaries or hook configuration invalidate matching evidence. MCP, remote agents and unregistered actions remain outside these hooks.").font(.caption).foregroundStyle(.secondary)
                Button("Recheck agent connections") { model.repairAgentHooks(recheck: true) }.disabled(model.agentRepairBusy)
                Button("Connect or repair agent checks") { model.repairAgentHooks() }.disabled(model.agentRepairBusy)
                Button("Remove BoxCop agent hooks…", role: .destructive) { confirmRemoval = true }
                    .disabled(model.agentRepairBusy)
                    .confirmationDialog("Remove BoxCop hooks and opt out of automatic registration? Restart agent sessions afterward. Other hooks are preserved.", isPresented: $confirmRemoval, titleVisibility: .visible) {
                        Button("Remove BoxCop hooks", role: .destructive) { model.repairAgentHooks(remove: true) }
                    }
                Text("Claude Code and Cursor pick up the check on their own. Codex asks you to approve it when it next opens. Run a command, then recheck the connection to confirm BoxCop receives activity. Pause and Quit do not remove hooks.").font(.caption)
                }
            }
            if model.releaseProfile.usesNetworkProtection {
                NetworkProtectionSetupView(model: model.networkConnections) { model.selectedPage = .activity }
            } else {
                ConnectionCard(title: "Outgoing connections", status: "Not included in this beta", symbol: "network") {
                    Text("This build does not include the network extension. Install a provisioned build to set up outgoing protection.").font(.caption)
                }
            }
            if model.showsHumanChecks {
                ConnectionCard(title: "Paste protection", status: model.running && model.guardActive ? "Checking Command-V pastes" : "Inactive", symbol: "doc.on.clipboard") {
                VStack(alignment: .leading, spacing: 12) {
                    Label(model.running && model.guardActive ? "Limited paste protection active" : "Paste protection is not active",
                          systemImage: model.running && model.guardActive ? "checkmark.shield" : "exclamationmark.triangle")
                        .font(.headline)
                    Text(model.releaseProfile == .limitedDevelopment ? "This limited development build checks supported pastes and agent actions. Network protection and native process and file blocking are unavailable." : "This preview does not cover all malware, exploits or data loss.").font(.caption)
                    Text("Menu Paste, drag and drop, uploads and apps that read the clipboard directly are not checked by paste protection.")
                    HStack {
                        Button("Set up Accessibility…") { model.requestAccessibility() }
                        Button("Recheck") { model.retry() }.disabled(model.starting || model.stopping || !model.choices.monitoring)
                        Button("Test paste protection…") { model.runPasteSelfTest() }.disabled(!model.running || !model.guardActive)
                    }
                    Text("The test replaces your clipboard and opens a test field in BoxCop.").font(.caption).foregroundStyle(.secondary)
                    Text(model.pasteTestStatus).font(.caption)
                }.frame(maxWidth: .infinity, alignment: .leading)
                }
                ConnectionCard(title: "Background screen warnings", status: model.backgroundScreenEnabled && model.running ? "Enabled · advisory only" : "Paused or off", symbol: "exclamationmark.bubble") {
                    Toggle("Check displays while screen capture is detected", isOn: Binding(get: { model.backgroundScreenEnabled }, set: { model.setBackgroundScreenMonitoring($0) }))
                        .disabled(model.teamConnection.state.settings["background_screen"] != nil)
                    Toggle("Cover all displays when sensitive content is detected", isOn: Binding(get: { model.backgroundScreenFullScreen }, set: { model.setBackgroundScreenFullScreen($0) }))
                        .disabled(model.teamConnection.state.settings["screen_cover"] != nil)
                    Text("The cover appears after detection. Earlier frames can escape, and a shared app window may bypass it.").font(.caption).foregroundStyle(.secondary)
                    Text(model.backgroundScreenStatus).font(.caption)
                    Text("Checks all displays only when macOS identifies another app capturing your screen, with five seconds between scans. Camera-only calls do not trigger checks. Unavailable or unrecognized sharing status pauses automatic covers. Local recordings can also trigger checks. Screenshots and recognized text are not saved. Warnings cannot prevent exposure.").font(.caption).foregroundStyle(.secondary)
                    Button("Set up Screen Recording…") { model.requestScreenRecording() }
                }
                ConnectionCard(title: "Protected presentation", status: model.presentationRunning ? "Checking selected window" : "Paused", symbol: "rectangle.on.rectangle") {
                    Text("Choose a source and start presenting. In your meeting, share only BoxCop Protected Presentation.")
                    Picker("Source window", selection: $presentationWindow) {
                        Text("Choose a window").tag(UInt32(0))
                        ForEach(model.presentationSources) { source in Text(source.name).tag(source.id) }
                    }
                    HStack {
                        Button("Refresh windows") { model.refreshPresentationSources() }.disabled(model.presentationLoading)
                        Button("Start presentation") { model.startPresentation(windowID: presentationWindow) }
                            .disabled(!model.running || !model.presentationSources.contains(where: { $0.id == presentationWindow }))
                        Button("Pause presentation") { model.stopPresentation() }.disabled(!model.presentationRunning)
                    }
                    Text(model.presentationStatus).font(.caption)
                    Text("BoxCop hides the presentation when it detects sensitive text or a QR code, or cannot read the image. Text recognition can miss secrets. Share only the BoxCop presentation window; direct screen sharing, audio and camera are not protected.").font(.caption).foregroundStyle(.secondary)
                }
                ConnectionCard(title: "Share checks", status: model.screenShareActive && model.running ? "Active" : "Inactive", symbol: "rectangle.on.rectangle") {
                    Toggle("Check visible displays before recognized share actions", isOn: Binding(get: { model.screenShareEnabled }, set: { model.setScreenSharePreflight($0) }))
                    Text(model.screenShareStatus).font(.caption)
                    Text("Recognized English share buttons in Zoom, Teams, Safari, Chrome and Edge. May block clean-window sharing when another display is sensitive. Does not guard ongoing shares, unrecognized controls, or programmatic capture.").font(.caption).foregroundStyle(.secondary)
                }
            } else {
                HumanChecksOptIn(model: model)
            }
            ConnectionCard(title: "Chrome / Chromium", status: model.browserSetupStatus, symbol: "globe") {
                VStack(alignment: .leading, spacing: 12) {
                Text("1. Show the bundled extension folder. In chrome://extensions (Chromium: chromium://extensions), enable Developer mode, choose Load unpacked and select that folder.\n2. Copy the extension ID below, connect the extension, then reload the extension and existing HTTP(S) tabs.").font(.caption)
                Text("Connected browser and agent observations are collected automatically while monitoring.").font(.caption)
                Button("Show browser extension folder") { model.revealBundledResource("browser-context") }
                HStack {
                    TextField("Extension ID", text: $extensionID)
                    Button("Connect extension") { model.installBrowserHost(extensionID: extensionID) }
                }
                TimelineView(.periodic(from: .now, by: 15)) { context in
                    Text(BrowserEvidence.description(running: model.running && model.collectAdapters,
                         lastEvent: model.lastBrowserEventAt, now: context.date)).font(.caption)
                }
                Text("Browser and agent observations may retain page excerpts, selected text, prompts, tool arguments and result summaries locally for linked workflow context. They can contain secrets. This does not enable universal upload blocking.").font(.caption).foregroundStyle(.secondary)
                }
            }
            ConnectionCard(title: "System services", status: model.endpointSecurityStatus, symbol: "desktopcomputer") {
                VStack(alignment: .leading, spacing: 12) {
                Text("Network logging and listed-threat domain blocking cover all apps and requires the provisioned build and macOS approval. File-access enforcement uses a separate Endpoint Security service. A running service alone does not verify coverage; check each connection above.").font(.caption)
                Text("Pausing stops activity monitoring and paste protection. Connected agent checks and system protection services stay active.").font(.caption)
                Button("Setup, privacy & removal guide") { model.revealBundledResource("BoxCop Guide.md") }
                }.frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }
}
/// Individuals opt in to checks on their own actions; until then the app shows agent protection only.
struct HumanChecksOptIn: View {
    @ObservedObject var model: EndpointModel
    var body: some View {
        GroupBox {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: "person.badge.shield.checkmark").font(.title3).foregroundStyle(AppPalette.quiet).frame(width: 24)
                VStack(alignment: .leading, spacing: 5) {
                    Text("Checks on your own actions").fontWeight(.medium)
                    Text("Paste, screen-sharing and email review checks catch your own mistakes. They’re mostly useful for teams and need extra macOS permissions.")
                        .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 8)
                Button("Show") { model.setHumanChecksShown(true) }
            }
        }
    }
}

private struct ConnectionCard<Content: View>: View {
    let title: String
    let status: String
    let symbol: String
    @ViewBuilder var content: () -> Content
    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 12) {
                HStack(alignment: .top, spacing: 12) {
                    Image(systemName: symbol).font(.title3).foregroundStyle(.tint).frame(width: 24)
                    VStack(alignment: .leading, spacing: 5) {
                        Text(title).fontWeight(.medium)
                        Text(status).font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                    }
                }
                DisclosureGroup("Setup & details") {
                    content().padding(.top, 12)
                }
            }
        }
    }
}
#endif
