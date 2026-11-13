#if os(macOS)
import SwiftUI
import AppKit
import BoxCopCore

/// The BoxCop palette, with light and dark values.
enum Palette {
    static func adaptive(_ light: UInt32, _ dark: UInt32) -> Color {
        Color(nsColor: NSColor(name: nil) { appearance in
            nsColor(appearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua ? dark : light)
        })
    }
    static func nsColor(_ value: UInt32) -> NSColor {
        NSColor(srgbRed: CGFloat((value >> 16) & 255) / 255, green: CGFloat((value >> 8) & 255) / 255, blue: CGFloat(value & 255) / 255, alpha: 1)
    }
    static let navyHex: UInt32 = 0x0A1730, amberHex: UInt32 = 0xC77700, redHex: UInt32 = 0xD1342F
    /// Text: ink navy on light, light text on dark.
    static let ink = adaptive(navyHex, 0xEEF2F8)
    static let quiet = adaptive(0x5F6B7A, 0xA3ADBB)
    static let accent = adaptive(0x2F6BFF, 0x5B8CFF)
    static let green = adaptive(0x1F9D55, 0x3CCB7F)
    static let amber = adaptive(amberHex, 0xF0A93B)
    static let red = adaptive(redHex, 0xFF6B63)
    static let canvas = adaptive(0xFCFDFE, 0x16181D)
    static let sidebar = adaptive(0xF2F5F9, 0x1D2026)
    static let border = adaptive(0xDDE3EC, 0x343A44)
    /// Brand mark only.
    static let navy = Color(nsColor: nsColor(navyHex))
    static let gold = Color(nsColor: nsColor(0xFFC53D))
    static let onAccent = Color.white

    static func color(_ overall: OverallStatus) -> Color {
        switch overall {
        case .protected: return green
        case .partlyProtected: return amber
        case .notProtected: return red
        case .paused: return quiet
        }
    }
    static func color(_ state: LayerState) -> Color {
        switch state {
        case .on: return green
        case .needsSetup: return amber
        case .off, .unavailable: return quiet
        }
    }
    static func color(_ status: FeedEvent.Status) -> Color {
        switch status {
        case .blocked: return red
        case .finding: return accent
        case .warned: return quiet
        }
    }
}

extension LayerID {
    var icon: String {
        switch self {
        case .installGate: return "shippingbox"
        case .containment: return "lock.square"
        case .outboundControl: return "network"
        case .agentChecks: return "terminal"
        case .machineHealth: return "stethoscope"
        case .smartTriage: return "sparkles"
        }
    }
}

/// Geometry of the mark, in the 512-unit box of `Resources/BoxCopMark.svg`.
enum BoxCopMarkGeometry {
    static func polygon(_ points: [(CGFloat, CGFloat)]) -> CGPath {
        let path = CGMutablePath()
        path.addLines(between: points.map { CGPoint(x: $0.0, y: $0.1) })
        path.closeSubpath()
        return path
    }
    static let top = polygon([(256, 60), (432, 150), (256, 240), (80, 150)])
    static let left = polygon([(80, 150), (256, 240), (256, 452), (80, 362)])
    static let right = polygon([(432, 150), (256, 240), (256, 452), (432, 362)])
    static let tape = polygon([(150, 114), (326, 204), (362, 186), (186, 96)])
    /// The badge is sheared so it sits on the left face.
    static let face = CGAffineTransform(a: 1.12, b: 0.573, c: 0, d: 1.12, tx: 168, ty: 232)
    static var shieldOutline: CGMutablePath {
        let path = CGMutablePath()
        path.move(to: CGPoint(x: 0, y: 14))
        path.addCurve(to: CGPoint(x: -54, y: 0), control1: CGPoint(x: -22, y: 14), control2: CGPoint(x: -40, y: 8))
        path.addLine(to: CGPoint(x: -54, y: 52))
        path.addCurve(to: CGPoint(x: 0, y: 126), control1: CGPoint(x: -54, y: 88), control2: CGPoint(x: -32, y: 112))
        path.addCurve(to: CGPoint(x: 54, y: 52), control1: CGPoint(x: 32, y: 112), control2: CGPoint(x: 54, y: 88))
        path.addLine(to: CGPoint(x: 54, y: 0))
        path.addCurve(to: CGPoint(x: 0, y: 14), control1: CGPoint(x: 40, y: 8), control2: CGPoint(x: 22, y: 14))
        path.closeSubpath()
        return path
    }
    static func shield(_ transform: CGAffineTransform = face) -> CGPath {
        var transform = transform
        return shieldOutline.copy(using: &transform) ?? shieldOutline
    }
    static var star: CGPath {
        var transform = face
        let path = polygon([(0, 34), (9.4, 55), (32, 57.6), (15, 73), (20, 95.5), (0, 84), (-20, 95.5), (-15, 73), (-32, 57.6), (-9.4, 55)])
        return path.copy(using: &transform) ?? path
    }
    static func fit(_ rect: CGRect) -> CGAffineTransform {
        let scale = min(rect.width, rect.height) / 512
        return CGAffineTransform(translationX: rect.midX - 256 * scale, y: rect.midY - 256 * scale).scaledBy(x: scale, y: scale)
    }
}

/// The full-color mark: an isometric box with a shield-and-star badge on its left face.
struct BoxCopMark: View {
    var body: some View {
        GeometryReader { proxy in layers(proxy.size) }
            .aspectRatio(1, contentMode: .fit)
            .accessibilityHidden(true)
    }
    private func layers(_ size: CGSize) -> some View {
        let fit = BoxCopMarkGeometry.fit(CGRect(origin: .zero, size: size))
        let unit = min(size.width, size.height) / 512
        let line = StrokeStyle(lineWidth: 20 * unit, lineJoin: .round)
        let badgeLine = StrokeStyle(lineWidth: 14 * 1.12 * unit, lineJoin: .round)
        func path(_ source: CGPath) -> Path { Path(source).applying(fit) }
        return ZStack {
            path(BoxCopMarkGeometry.top).fill(Color(nsColor: Palette.nsColor(0x7FB0FF)))
            path(BoxCopMarkGeometry.left).fill(Color(nsColor: Palette.nsColor(0x2F6BFF)))
            path(BoxCopMarkGeometry.right).fill(Color(nsColor: Palette.nsColor(0x1B47C9)))
            path(BoxCopMarkGeometry.top).stroke(Palette.navy, style: line)
            path(BoxCopMarkGeometry.left).stroke(Palette.navy, style: line)
            path(BoxCopMarkGeometry.right).stroke(Palette.navy, style: line)
            path(BoxCopMarkGeometry.tape).fill(Palette.navy)
            path(BoxCopMarkGeometry.shield()).fill(Palette.gold)
            path(BoxCopMarkGeometry.shield()).stroke(Palette.navy, style: badgeLine)
            path(BoxCopMarkGeometry.star).fill(Palette.navy)
        }
    }
}

/// The single-color version for the menu bar: the box outline with a solid shield. Reads at 18 pt.
enum BoxCopGlyph {
    /// Lines to stroke and the shield to fill, in the 512-unit box.
    static var outline: CGPath {
        let path = CGMutablePath()
        path.addPath(BoxCopMarkGeometry.polygon([(256, 52), (440, 146), (440, 366), (256, 460), (72, 366), (72, 146)]))
        path.move(to: CGPoint(x: 72, y: 146)); path.addLine(to: CGPoint(x: 256, y: 240)); path.addLine(to: CGPoint(x: 440, y: 146))
        path.move(to: CGPoint(x: 256, y: 240)); path.addLine(to: CGPoint(x: 256, y: 460))
        return path
    }
    /// Larger than in the full mark so it survives at small sizes.
    static var shield: CGPath {
        BoxCopMarkGeometry.shield(CGAffineTransform(a: 1.25, b: 0.64, c: 0, d: 1.25, tx: 164, ty: 232))
    }
    static func draw(in context: CGContext, rect: CGRect, color: CGColor) {
        var fit = BoxCopMarkGeometry.fit(rect)
        context.saveGState()
        context.setStrokeColor(color); context.setFillColor(color)
        context.setLineWidth(max(1.2, rect.width / 13)); context.setLineJoin(.round); context.setLineCap(.round)
        if let lines = outline.copy(using: &fit) { context.addPath(lines); context.strokePath() }
        if let badge = shield.copy(using: &fit) { context.addPath(badge); context.fillPath() }
        context.restoreGState()
    }
}
struct BoxCopGlyphView: View {
    var body: some View {
        GeometryReader { proxy in glyph(proxy.size) }.aspectRatio(1, contentMode: .fit)
    }
    private func glyph(_ size: CGSize) -> some View {
        let fit = BoxCopMarkGeometry.fit(CGRect(origin: .zero, size: size))
        return ZStack {
            Path(BoxCopGlyph.outline).applying(fit)
                .stroke(style: StrokeStyle(lineWidth: max(1.2, size.width / 13), lineCap: .round, lineJoin: .round))
            Path(BoxCopGlyph.shield).applying(fit).fill()
        }
    }
}

// MARK: Small shared pieces

struct Pill: View {
    let text: String
    let color: Color
    var body: some View {
        Text(text).font(.system(size: 11, weight: .medium)).foregroundStyle(color).lineLimit(1).fixedSize()
            .padding(.horizontal, 8).padding(.vertical, 2)
            .background(color.opacity(0.14), in: Capsule())
    }
}
struct StatePill: View {
    let state: LayerState
    var body: some View { Pill(text: state.label, color: Palette.color(state)) }
}
struct StatusTag: View {
    let status: FeedEvent.Status
    var body: some View { Pill(text: status.label, color: Palette.color(status)) }
}

struct SectionTitle: View {
    let text: String
    init(_ text: String) { self.text = text }
    var body: some View {
        Text(text.uppercased()).font(.system(size: 10.5, weight: .semibold)).tracking(0.6).foregroundStyle(Palette.quiet)
    }
}

/// A bordered group of rows. Calm and dense; no shadows.
struct RowGroup<Content: View>: View {
    @ViewBuilder var content: Content
    var body: some View {
        VStack(spacing: 0) { content }
            .background(Palette.canvas)
            .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(Palette.border))
    }
}
struct RowDivider: View {
    var body: some View { Rectangle().fill(Palette.border).frame(height: 1) }
}

struct PrimaryButtonStyle: ButtonStyle {
    @Environment(\.isEnabled) private var enabled
    var large = false
    func makeBody(configuration: Configuration) -> some View {
        configuration.label.font(.system(size: large ? 14 : 12, weight: .semibold)).foregroundStyle(Palette.onAccent).lineLimit(1)
            .padding(.horizontal, large ? 18 : 11).padding(.vertical, large ? 9 : 4.5)
            .background(Palette.accent.opacity(enabled ? (configuration.isPressed ? 0.8 : 1) : 0.4), in: RoundedRectangle(cornerRadius: 6, style: .continuous))
    }
}
struct QuietButtonStyle: ButtonStyle {
    @Environment(\.isEnabled) private var enabled
    var tint: Color = Palette.ink
    func makeBody(configuration: Configuration) -> some View {
        configuration.label.font(.system(size: 12, weight: .medium)).foregroundStyle(tint.opacity(enabled ? 1 : 0.4)).lineLimit(1)
            .padding(.horizontal, 10).padding(.vertical, 3.5)
            .background(Palette.sidebar.opacity(configuration.isPressed ? 1 : 0.6), in: RoundedRectangle(cornerRadius: 6, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 6, style: .continuous).strokeBorder(Palette.border))
    }
}
extension ButtonStyle where Self == PrimaryButtonStyle { static var primary: PrimaryButtonStyle { PrimaryButtonStyle() } }
extension ButtonStyle where Self == QuietButtonStyle { static var quiet: QuietButtonStyle { QuietButtonStyle() } }

/// Drawn switches and checkboxes keep their color in an inactive window and in rendered previews.
struct SwitchStyle: ToggleStyle {
    @Environment(\.isEnabled) private var enabled
    func makeBody(configuration: Configuration) -> some View {
        Button { configuration.isOn.toggle() } label: {
            Capsule().fill(configuration.isOn ? Palette.accent : Palette.border)
                .frame(width: 32, height: 18)
                .overlay(alignment: configuration.isOn ? .trailing : .leading) {
                    Circle().fill(Color.white).frame(width: 14, height: 14).padding(2).shadow(color: .black.opacity(0.2), radius: 0.5, y: 0.5)
                }
                .opacity(enabled ? 1 : 0.45)
                .contentShape(Capsule())
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(.isToggle)
        .accessibilityValue(configuration.isOn ? "On" : "Off")
    }
}
struct CheckStyle: ToggleStyle {
    @Environment(\.isEnabled) private var enabled
    func makeBody(configuration: Configuration) -> some View {
        Button { configuration.isOn.toggle() } label: {
            RoundedRectangle(cornerRadius: 4, style: .continuous)
                .fill(configuration.isOn ? Palette.accent : Palette.canvas)
                .frame(width: 15, height: 15)
                .overlay(RoundedRectangle(cornerRadius: 4, style: .continuous).strokeBorder(configuration.isOn ? Palette.accent : Palette.quiet.opacity(0.6)))
                .overlay { if configuration.isOn { Image(systemName: "checkmark").font(.system(size: 9, weight: .bold)).foregroundStyle(Color.white) } }
                .opacity(enabled ? 1 : 0.45)
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(.isToggle)
        .accessibilityValue(configuration.isOn ? "On" : "Off")
    }
}

enum Format {
    static func time(_ date: Date, now: Date = Date()) -> String {
        let calendar = Calendar.current
        if calendar.isDate(date, inSameDayAs: now) { return date.formatted(date: .omitted, time: .shortened) }
        if let yesterday = calendar.date(byAdding: .day, value: -1, to: now), calendar.isDate(date, inSameDayAs: yesterday) { return "Yesterday" }
        return date.formatted(.dateTime.month(.abbreviated).day())
    }
    static func full(_ date: Date) -> String { date.formatted(date: .abbreviated, time: .standard) }
    static func stamp(_ text: String) -> String {
        guard let date = SecurityEvent.date(text) else { return text.isEmpty ? "never" : text }
        return date.formatted(date: .abbreviated, time: .shortened)
    }
    static func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }
}
#endif
