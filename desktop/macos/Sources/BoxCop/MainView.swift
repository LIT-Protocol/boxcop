#if os(macOS)
import SwiftUI
import BoxCopCore

/// One window: a sidebar with four destinations and Settings, or the one-screen onboarding.
struct MainView: View {
    @ObservedObject var model: AppModel
    var body: some View {
        Group {
            if model.onboardingPresented {
                OnboardingView(model: model)
            } else {
                HStack(spacing: 0) {
                    Sidebar(model: model)
                    Rectangle().fill(Palette.border).frame(width: 1)
                    page.frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                }
            }
        }
        .frame(minWidth: 760, minHeight: 520)
        .background(Palette.canvas)
        .foregroundStyle(Palette.ink)
        .tint(Palette.accent)
        .ignoresSafeArea()
        .sheet(item: $model.testSheet) { LayerTestSheet(layer: $0, model: model) }
    }
    @ViewBuilder private var page: some View {
        switch model.page {
        case .overview: OverviewView(model: model)
        case .events: EventsView(model: model)
        case .protections: ProtectionsView(model: model)
        case .health: HealthView(model: model)
        case .settings: SettingsView(model: model)
        }
    }
}

private struct Sidebar: View {
    @ObservedObject var model: AppModel
    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: 8) {
                BoxCopMark().frame(width: 26, height: 26)
                Text("BoxCop").font(.system(size: 15, weight: .semibold))
            }
            .padding(.leading, 8).padding(.bottom, 14)
            item(.overview)
            item(.events, badge: model.pendingApprovalCount, badgeColor: Palette.amber)
            item(.protections)
            item(.health, badge: model.wants(.machineHealth) ? model.activeFindings.count : 0, badgeColor: Palette.accent)
            Spacer()
            item(.settings)
            Text("Version \(model.capabilities.version)").font(.system(size: 10.5)).foregroundStyle(Palette.quiet)
                .padding(.leading, 10).padding(.top, 6)
        }
        .padding(.horizontal, 10).padding(.top, 44).padding(.bottom, 14)
        .frame(width: 170)
        .frame(maxHeight: .infinity)
        .background(Palette.sidebar)
    }
    private func item(_ page: AppModel.Page, badge: Int = 0, badgeColor: Color = Palette.accent) -> some View {
        let selected = model.page == page
        return Button { model.page = page } label: {
            HStack(spacing: 8) {
                Image(systemName: page.icon).font(.system(size: 13)).frame(width: 18)
                Text(page.title).font(.system(size: 13, weight: selected ? .semibold : .regular))
                Spacer(minLength: 0)
                if badge > 0 {
                    Text(badge > 99 ? "99+" : String(badge)).font(.system(size: 10.5, weight: .semibold)).foregroundStyle(Palette.onAccent)
                        .padding(.horizontal, 6).padding(.vertical, 1).background(badgeColor, in: Capsule())
                }
            }
            .foregroundStyle(selected ? Palette.accent : Palette.ink)
            .padding(.horizontal, 10).frame(height: 30)
            .background(selected ? Palette.accent.opacity(0.12) : Color.clear, in: RoundedRectangle(cornerRadius: 6, style: .continuous))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel(badge > 0 ? "\(page.title), \(badge)" : page.title)
    }
}

/// A scrolling page with a title row.
struct PageScaffold<Trailing: View, Content: View>: View {
    let title: String
    var subtitle: String?
    @ViewBuilder var trailing: Trailing
    @ViewBuilder var content: Content
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                HStack(alignment: .firstTextBaseline) {
                    VStack(alignment: .leading, spacing: 3) {
                        Text(title).font(.system(size: 20, weight: .semibold))
                        if let subtitle { Text(subtitle).font(.system(size: 12.5)).foregroundStyle(Palette.quiet) }
                    }
                    Spacer()
                    trailing
                }
                content
            }
            .padding(.horizontal, 24).padding(.top, 22).padding(.bottom, 24)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

extension PageScaffold where Trailing == EmptyView {
    init(title: String, subtitle: String? = nil, @ViewBuilder content: () -> Content) {
        self.init(title: title, subtitle: subtitle, trailing: { EmptyView() }, content: content)
    }
}

struct OverviewView: View {
    @ObservedObject var model: AppModel
    var body: some View {
        let summary = model.summary
        let needs = model.needsYou
        let events = model.events
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                header(summary)
                if !needs.isEmpty {
                    VStack(alignment: .leading, spacing: 7) {
                        SectionTitle("Needs you")
                        RowGroup {
                            ForEach(Array(needs.enumerated()), id: \.element.id) { index, item in
                                if index > 0 { RowDivider() }
                                HStack(spacing: 10) {
                                    Image(systemName: item.icon).font(.system(size: 12)).foregroundStyle(Palette.amber).frame(width: 18)
                                    Text(item.text).font(.system(size: 12.5)).lineLimit(1).truncationMode(.middle)
                                    Spacer(minLength: 8)
                                    Button(item.button) { model.perform(item.action) }.buttonStyle(.primary)
                                }
                                .padding(.horizontal, 12).frame(height: 36)
                            }
                        }
                    }
                }
                VStack(alignment: .leading, spacing: 7) {
                    SectionTitle("Layers")
                    RowGroup {
                        ForEach(Array(summary.layers.enumerated()), id: \.element.id) { index, layer in
                            if index > 0 { RowDivider() }
                            layerRow(layer)
                        }
                    }
                }
                VStack(alignment: .leading, spacing: 7) {
                    HStack {
                        SectionTitle("Recent events")
                        Spacer()
                        if !events.isEmpty {
                            Button("View all") { model.page = .events }.buttonStyle(.plain).font(.system(size: 11.5, weight: .medium)).foregroundStyle(Palette.accent)
                        }
                    }
                    if events.isEmpty {
                        Text("Nothing has been blocked or held yet.").font(.system(size: 12.5)).foregroundStyle(Palette.quiet).padding(.vertical, 4)
                    } else {
                        RowGroup {
                            ForEach(Array(events.prefix(5).enumerated()), id: \.element.id) { index, event in
                                if index > 0 { RowDivider() }
                                Button { model.showEvent(event.id) } label: { EventLine(event: event).padding(.horizontal, 12).frame(height: 30).contentShape(Rectangle()) }
                                    .buttonStyle(.plain)
                            }
                        }
                    }
                }
            }
            .padding(.horizontal, 24).padding(.top, 22).padding(.bottom, 24)
        }
    }

    private func header(_ summary: ProtectionSummary) -> some View {
        let color = Palette.color(summary.overall)
        let symbol: String
        switch summary.overall {
        case .protected: symbol = "checkmark.shield.fill"
        case .partlyProtected: symbol = "exclamationmark.shield.fill"
        case .notProtected: symbol = "xmark.shield.fill"
        case .paused: symbol = "pause.circle.fill"
        }
        return HStack(spacing: 14) {
            Image(systemName: symbol).font(.system(size: 34)).foregroundStyle(color).frame(width: 44)
            VStack(alignment: .leading, spacing: 2) {
                Text(summary.overall.word).font(.system(size: 26, weight: .bold)).foregroundStyle(color)
                Text(summary.sentence).font(.system(size: 13)).foregroundStyle(Palette.ink)
            }
            Spacer()
            if summary.overall == .paused { Button("Resume") { model.resume() }.buttonStyle(.primary) }
        }
        .accessibilityElement(children: .combine)
    }

    private func layerRow(_ layer: LayerStatus) -> some View {
        let busy = model.busyLayers.contains(layer.id) || (layer.id == .outboundControl && model.network.busy)
        return HStack(spacing: 11) {
            Image(systemName: layer.id.icon).font(.system(size: 14)).foregroundStyle(layer.state == .on ? Palette.accent : Palette.quiet).frame(width: 22)
            VStack(alignment: .leading, spacing: 1) {
                Text(layer.id.name).font(.system(size: 13, weight: .semibold))
                Text(layer.state == .on || layer.state == .off ? layer.id.summary : layer.detail)
                    .font(.system(size: 11.5)).foregroundStyle(Palette.quiet).lineLimit(1)
            }
            Spacer(minLength: 8)
            StatePill(state: layer.state)
            Group {
                if model.paused && layer.id.enforces && layer.id != .agentChecks { EmptyView() }
                else if layer.state == .off { Button("Turn on") { model.setLayer(layer.id, on: true) }.buttonStyle(.quiet) }
                else if layer.state == .needsSetup, model.fixable(layer) { Button("Fix") { model.fixLayer(layer.id) }.buttonStyle(.quiet) }
            }
            .disabled(busy)
            .frame(width: 68, alignment: .trailing)
        }
        .padding(.horizontal, 12).frame(height: 44)
        .help(layer.detail)
    }
}

/// One event on one line: time, what, source, status.
struct EventLine: View {
    let event: FeedEvent
    var body: some View {
        HStack(spacing: 10) {
            Text(Format.time(event.time)).font(.system(size: 11.5).monospacedDigit()).foregroundStyle(Palette.quiet).frame(width: 66, alignment: .leading)
            Text(event.title).font(.system(size: 12.5)).lineLimit(1).frame(maxWidth: .infinity, alignment: .leading)
            Text(event.source).font(.system(size: 11.5)).foregroundStyle(Palette.quiet).lineLimit(1).frame(width: 104, alignment: .leading)
            StatusTag(status: event.status).frame(width: 72, alignment: .leading)
        }
    }
}
#endif
