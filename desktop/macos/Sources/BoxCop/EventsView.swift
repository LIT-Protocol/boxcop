#if os(macOS)
import SwiftUI
import BoxCopCore

/// One list for every layer. Waiting approvals stay on top; the selected row explains itself below.
struct EventsView: View {
    @ObservedObject var model: AppModel
    @State private var copied: String?

    var body: some View {
        let all = model.events
        let rows = EventFeed.filter(all, model.eventFilter)
        let selected = rows.first { $0.id == model.selectedEventID }
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 12) {
                Text("Events").font(.system(size: 20, weight: .semibold))
                controls
            }
            .padding(.horizontal, 24).padding(.top, 22).padding(.bottom, 12)
            if all.isEmpty {
                empty("Nothing has been blocked, held or flagged yet. Events appear here as soon as a layer steps in.")
            } else if rows.isEmpty {
                empty("No events match this search or filter.")
            } else {
                columnTitles
                RowDivider()
                ScrollView {
                    VStack(spacing: 0) {
                        ForEach(rows) { event in
                            row(event, selected: event.id == selected?.id)
                            RowDivider().opacity(0.6)
                        }
                    }
                }
                .frame(maxHeight: .infinity)
                if let selected {
                    RowDivider()
                    EventDetail(event: selected, model: model, copied: $copied)
                        .frame(height: 262)
                        .background(Palette.sidebar.opacity(0.55))
                }
            }
        }
    }

    private var controls: some View {
        HStack(spacing: 10) {
            HStack(spacing: 6) {
                Image(systemName: "magnifyingglass").font(.system(size: 11)).foregroundStyle(Palette.quiet)
                TextField("Search events", text: $model.eventFilter.search).textFieldStyle(.plain).font(.system(size: 12.5))
            }
            .padding(.horizontal, 8).frame(width: 200, height: 26)
            .background(Palette.canvas, in: RoundedRectangle(cornerRadius: 6, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 6, style: .continuous).strokeBorder(Palette.border))
            HStack(spacing: 0) {
                ForEach(EventFilter.Kind.allCases) { kind in
                    let on = model.eventFilter.kind == kind
                    Button { model.eventFilter.kind = kind } label: {
                        Text(kind.rawValue).font(.system(size: 12, weight: on ? .semibold : .regular))
                            .foregroundStyle(on ? Palette.onAccent : Palette.ink)
                            .padding(.horizontal, 11).frame(height: 24)
                            .background(on ? Palette.accent : Color.clear, in: RoundedRectangle(cornerRadius: 5, style: .continuous))
                            .contentShape(Rectangle())
                    }.buttonStyle(.plain)
                }
            }
            .padding(1)
            .background(Palette.sidebar, in: RoundedRectangle(cornerRadius: 6, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 6, style: .continuous).strokeBorder(Palette.border))
            Spacer()
            Menu {
                Button("All layers") { model.eventFilter.layer = nil }
                Divider()
                ForEach(LayerID.allCases.filter { $0 != .smartTriage }) { layer in
                    Button(layer.name) { model.eventFilter.layer = layer }
                }
            } label: {
                HStack(spacing: 5) {
                    Text(model.eventFilter.layer?.name ?? "All layers").font(.system(size: 12, weight: .medium))
                    Image(systemName: "chevron.down").font(.system(size: 9, weight: .semibold))
                }
                .foregroundStyle(Palette.ink).padding(.horizontal, 10).frame(height: 26)
                .background(Palette.sidebar.opacity(0.6), in: RoundedRectangle(cornerRadius: 6, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: 6, style: .continuous).strokeBorder(Palette.border))
            }
            .menuStyle(.button).buttonStyle(.plain).menuIndicator(.hidden).fixedSize()
        }
    }

    private var columnTitles: some View {
        HStack(spacing: 10) {
            SectionTitle("Time").frame(width: 66, alignment: .leading)
            SectionTitle("What").frame(maxWidth: .infinity, alignment: .leading)
            SectionTitle("Source").frame(width: 104, alignment: .leading)
            SectionTitle("Status").frame(width: 72, alignment: .leading)
        }
        .padding(.horizontal, 24).padding(.bottom, 6)
    }

    private func row(_ event: FeedEvent, selected: Bool) -> some View {
        Group {
                if let approval = event.approvalID {
                    HStack(spacing: 10) {
                        Image(systemName: "pin.fill").font(.system(size: 10)).foregroundStyle(Palette.amber).frame(width: 66, alignment: .leading)
                        VStack(alignment: .leading, spacing: 1) {
                            Text(event.title).font(.system(size: 12.5, weight: .semibold)).lineLimit(1)
                            if !event.subject.isEmpty {
                                Text(event.subject).font(.system(size: 11, design: .monospaced)).foregroundStyle(Palette.quiet).lineLimit(1).truncationMode(.middle)
                            }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        Button("Reject") { model.resolve(approvalID: approval, approve: false) }.buttonStyle(.quiet)
                        Button("Approve") { model.resolve(approvalID: approval, approve: true) }.buttonStyle(.primary)
                            .help("Asks you to authenticate on this Mac, then allows this exact command once.")
                    }
                    .padding(.horizontal, 24).frame(height: 44)
                    .disabled(model.reviewBusy)
                } else {
                    EventLine(event: event).padding(.horizontal, 24).frame(height: 30)
                }
            }
        .background(selected ? Palette.accent.opacity(0.12) : event.pinned ? Palette.amber.opacity(0.08) : Color.clear)
        .contentShape(Rectangle())
        .onTapGesture { model.selectedEventID = selected ? nil : event.id }
        .accessibilityAddTraits(.isButton)
    }

    private func empty(_ text: String) -> some View {
        VStack(spacing: 10) {
            Image(systemName: "checkmark.shield").font(.system(size: 30)).foregroundStyle(Palette.quiet)
            Text(text).font(.system(size: 13)).foregroundStyle(Palette.quiet).multilineTextAlignment(.center).frame(maxWidth: 380)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

/// What happened, why, what exactly, who started it, and what you can do next.
struct EventDetail: View {
    let event: FeedEvent
    @ObservedObject var model: AppModel
    @Binding var copied: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 9) {
                    HStack(alignment: .firstTextBaseline, spacing: 8) {
                        Text(event.title).font(.system(size: 15, weight: .semibold)).lineLimit(2)
                        StatusTag(status: event.status)
                        Spacer()
                        Text("\(event.layer.name) · \(Format.full(event.time))").font(.system(size: 11.5)).foregroundStyle(Palette.quiet).lineLimit(1)
                    }
                    if !event.reason.isEmpty { fact("Why") { Text(event.reason).font(.system(size: 12.5)) } }
                    if !event.subject.isEmpty {
                        fact("What exactly") { Text(event.subject).font(.system(size: 12, design: .monospaced)).textSelection(.enabled) }
                    }
                    if !event.chain.isEmpty {
                        fact("Started by") { Text(event.chain.joined(separator: "  →  ")).font(.system(size: 12, design: .monospaced)).textSelection(.enabled) }
                    }
                    if let signing = event.signing { fact("Signed by") { Text(signing).font(.system(size: 12, design: .monospaced)) } }
                    if model.triageEnabled {
                        fact("Local model") {
                            if let explanation = event.explanation {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(explanation).font(.system(size: 12.5))
                                    Text("Written by the local model. It is advisory and can be wrong.").font(.system(size: 11)).foregroundStyle(Palette.quiet)
                                }
                            } else {
                                Text("No explanation for this event yet.").font(.system(size: 12.5)).foregroundStyle(Palette.quiet)
                            }
                        }
                    }
                    if !event.policyIDs.isEmpty {
                        fact(event.status == .finding ? "Advisory" : "Rule") {
                            Text(event.policyIDs.joined(separator: ", ")).font(.system(size: 11.5, design: .monospaced)).foregroundStyle(Palette.quiet)
                        }
                    }
                }
                .padding(.horizontal, 24).padding(.top, 14).padding(.bottom, 8)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            HStack(spacing: 8) {
                ForEach(Array(event.actions.enumerated()), id: \.offset) { _, action in button(action) }
                if let message = model.reviewError, event.pinned { Text(message).font(.system(size: 11.5)).foregroundStyle(Palette.red).lineLimit(1) }
                else if case .allowForPackage = event.actions.first, let message = model.layerMessages[.containment] {
                    Text(message).font(.system(size: 11.5)).foregroundStyle(Palette.quiet).lineLimit(1)
                }
                Spacer()
            }
            .padding(.horizontal, 24).padding(.vertical, 10)
        }
    }

    private func fact<Value: View>(_ label: String, @ViewBuilder value: () -> Value) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            Text(label).font(.system(size: 11.5, weight: .medium)).foregroundStyle(Palette.quiet).frame(width: 84, alignment: .leading)
            value().frame(maxWidth: .infinity, alignment: .leading).fixedSize(horizontal: false, vertical: true)
        }
    }

    @ViewBuilder private func button(_ action: FeedEvent.Action) -> some View {
        switch action {
        case .approve:
            Button(action.title) { if let id = event.approvalID { model.resolve(approvalID: id, approve: true) } }.buttonStyle(.primary).disabled(model.reviewBusy)
        case .reject:
            Button(action.title) { if let id = event.approvalID { model.resolve(approvalID: id, approve: false) } }.buttonStyle(.quiet).disabled(model.reviewBusy)
        case let .allowForPackage(package, host):
            Button(action.title) { model.allowScriptDestination(package: package, host: host) }.buttonStyle(.primary)
                .help("Lets install scripts of \(package) reach \(host). Nothing else changes.")
        case .openHealth:
            Button(action.title) { model.page = .health }.buttonStyle(.primary)
        case .copyDetails:
            Button(copied == event.id ? "Copied" : action.title) { Format.copy(event.detailsText); copied = event.id }.buttonStyle(.quiet)
        }
    }
}
#endif
