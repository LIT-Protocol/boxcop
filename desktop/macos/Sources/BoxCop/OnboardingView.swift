#if os(macOS)
import SwiftUI
import BoxCopCore

/// First run: one screen, one button. macOS approvals follow on Overview under "Needs you".
struct OnboardingView: View {
    @ObservedObject var model: AppModel
    @State private var chosen: Set<LayerID>

    init(model: AppModel) {
        self.model = model
        var recommended: Set<LayerID> = [.installGate, .containment, .agentChecks, .machineHealth]
        // Outbound control is offered only in a build that includes the network extension.
        if model.capabilities.networkExtension { recommended.insert(.outboundControl) }
        if !model.capabilities.engine { recommended.subtract([.installGate, .containment, .agentChecks, .machineHealth]) }
        _chosen = State(initialValue: recommended)
    }

    private func available(_ layer: LayerID) -> Bool {
        switch layer {
        case .outboundControl: return model.capabilities.networkExtension
        case .smartTriage: return model.capabilities.engine && model.capabilities.triageRuntime
        default: return model.capabilities.engine
        }
    }
    private func note(_ layer: LayerID) -> String? {
        if !available(layer) { return layer == .outboundControl ? "Not included in this build." : layer == .smartTriage ? "The local model runtime is not in this build." : "The BoxCop engine is not in this build." }
        switch layer {
        case .outboundControl: return "macOS will ask you to approve a network extension."
        case .smartTriage: return "Optional. A 2.7 GB model download on first use."
        default: return nil
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            Spacer(minLength: 12)
            VStack(alignment: .leading, spacing: 18) {
                HStack(spacing: 12) {
                    BoxCopMark().frame(width: 52, height: 52)
                    VStack(alignment: .leading, spacing: 3) {
                        Text("Let your AI agents work.\nKeep your Mac protected.").font(.system(size: 22, weight: .bold)).fixedSize(horizontal: false, vertical: true)
                    }
                }
                Text("BoxCop checks what agents install, contains what they run and watches what leaves. Choose the layers to turn on. You can change them later.")
                    .font(.system(size: 13)).foregroundStyle(Palette.quiet).fixedSize(horizontal: false, vertical: true)
                RowGroup {
                    ForEach(Array(LayerID.allCases.enumerated()), id: \.element) { index, layer in
                        if index > 0 { RowDivider() }
                        row(layer)
                    }
                }
                HStack(spacing: 12) {
                    Image(systemName: "lock").font(.system(size: 12)).foregroundStyle(Palette.quiet)
                    Text("No account. Nothing is uploaded.").font(.system(size: 12.5)).foregroundStyle(Palette.quiet)
                    Spacer()
                    Button(chosen.isEmpty ? "Continue without protection" : "Turn on protection") { model.finishOnboarding(chosen) }
                        .buttonStyle(PrimaryButtonStyle(large: true)).keyboardShortcut(.defaultAction)
                }
            }
            .frame(width: 560)
            Spacer(minLength: 12)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Palette.canvas)
    }

    private func row(_ layer: LayerID) -> some View {
        let enabled = available(layer)
        return HStack(spacing: 11) {
            Toggle("", isOn: Binding(get: { chosen.contains(layer) }, set: { if $0 { chosen.insert(layer) } else { chosen.remove(layer) } }))
                .toggleStyle(CheckStyle()).labelsHidden().disabled(!enabled).accessibilityLabel(layer.name)
            Image(systemName: layer.icon).font(.system(size: 14)).foregroundStyle(enabled ? Palette.accent : Palette.quiet).frame(width: 22)
            VStack(alignment: .leading, spacing: 1) {
                Text(layer.name).font(.system(size: 13, weight: .semibold))
                Text(layer.summary).font(.system(size: 11.5)).foregroundStyle(Palette.quiet).lineLimit(1)
                if let note = note(layer) { Text(note).font(.system(size: 11.5)).foregroundStyle(enabled ? Palette.ink : Palette.quiet).lineLimit(1) }
            }
            Spacer()
            if !enabled { StatePill(state: .unavailable) }
        }
        .padding(.horizontal, 12).padding(.vertical, 7)
        .opacity(enabled ? 1 : 0.75)
        .contentShape(Rectangle())
    }
}
#endif
