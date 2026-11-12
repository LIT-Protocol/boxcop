#if os(macOS)
import SwiftUI
import AppKit

/// Colors from the product study, with native dark appearance counterparts.
enum AppPalette {
    static let accent = Color(red: 0.031, green: 0.486, blue: 0.941)
    static func adaptive(_ light: UInt32, _ dark: UInt32) -> Color {
        Color(nsColor: NSColor(name: nil) { appearance in
            let value = appearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua ? dark : light
            return NSColor(srgbRed: CGFloat((value >> 16) & 255) / 255,
                           green: CGFloat((value >> 8) & 255) / 255,
                           blue: CGFloat(value & 255) / 255, alpha: 1)
        })
    }
    static let canvas = adaptive(0xfcfdfd, 0x202226)
    static let sidebar = adaptive(0xf3f6f7, 0x292c30)
    static let border = adaptive(0xdfe6ea, 0x444950)
    static let selection = adaptive(0xe1ebf1, 0x334553)
    static let ink = adaptive(0x292e34, 0xf0f2f4)
    static let quiet = adaptive(0x68737b, 0xaab4bc)
    static let icon = adaptive(0xedf2f6, 0x303b44)
    static let raised = adaptive(0xf3f6f7, 0x2b2e33)
    /// The blue light only ever means a protection is on.
    static let light = adaptive(0x087cf0, 0x46a2ff)
}

/// Exact paths from https://getallay.ai/mark.svg (vendored in Resources/BoxCopMark.svg).
struct BoxCopMark: Shape {
    func path(in rect: CGRect) -> Path {
        var p = Path()
        p.move(to: CGPoint(x: 3, y: 10.2))
        p.addCurve(to: CGPoint(x: 11.9, y: 3), control1: CGPoint(x: 3.5, y: 5.7), control2: CGPoint(x: 6.9, y: 3))
        p.addLine(to: CGPoint(x: 12.7, y: 3))
        p.addCurve(to: CGPoint(x: 21, y: 11.3), control1: CGPoint(x: 17.8, y: 3), control2: CGPoint(x: 21, y: 6.3))
        p.addLine(to: CGPoint(x: 21, y: 19.5))
        p.addQuadCurve(to: CGPoint(x: 20.5, y: 20), control: CGPoint(x: 21, y: 20))
        p.addLine(to: CGPoint(x: 17.2, y: 20))
        p.addQuadCurve(to: CGPoint(x: 16.7, y: 19.5), control: CGPoint(x: 16.7, y: 20))
        p.addLine(to: CGPoint(x: 16.7, y: 11.4))
        p.addCurve(to: CGPoint(x: 12.7, y: 7.5), control1: CGPoint(x: 16.7, y: 9), control2: CGPoint(x: 15.2, y: 7.5))
        p.addLine(to: CGPoint(x: 8, y: 7.5))
        p.addCurve(to: CGPoint(x: 3, y: 10.2), control1: CGPoint(x: 5.8, y: 7.5), control2: CGPoint(x: 4.2, y: 8.6))
        p.closeSubpath()
        p.move(to: CGPoint(x: 3, y: 12.7))
        p.addCurve(to: CGPoint(x: 7.2, y: 10.7), control1: CGPoint(x: 4, y: 11.4), control2: CGPoint(x: 5.4, y: 10.7))
        p.addLine(to: CGPoint(x: 7.2, y: 13.7))
        p.addCurve(to: CGPoint(x: 10.2, y: 16.5), control1: CGPoint(x: 7.2, y: 15.5), control2: CGPoint(x: 8.3, y: 16.5))
        p.addLine(to: CGPoint(x: 13.7, y: 16.5))
        p.addQuadCurve(to: CGPoint(x: 14.2, y: 17), control: CGPoint(x: 14.2, y: 16.5))
        p.addLine(to: CGPoint(x: 14.2, y: 19.5))
        p.addQuadCurve(to: CGPoint(x: 13.7, y: 20), control: CGPoint(x: 14.2, y: 20))
        p.addLine(to: CGPoint(x: 9.6, y: 20))
        p.addCurve(to: CGPoint(x: 3, y: 13.6), control1: CGPoint(x: 5.5, y: 20), control2: CGPoint(x: 3, y: 17.5))
        p.closeSubpath()
        return p.applying(CGAffineTransform(translationX: -1, y: -1))
            .applying(CGAffineTransform(scaleX: rect.width / 22, y: rect.height / 22))
            .applying(CGAffineTransform(translationX: rect.minX, y: rect.minY))
    }
}

struct BoxCopBrand: View {
    var body: some View {
        HStack(spacing: 7) {
            BoxCopMark().frame(width: 19, height: 19).accessibilityHidden(true)
            Text("BoxCop").font(.system(size: 11, weight: .medium))
        }.foregroundStyle(AppPalette.ink)
    }
}

struct AppCardStyle: GroupBoxStyle {
    func makeBody(configuration: Configuration) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            configuration.label.font(.system(size: 13, weight: .semibold))
            configuration.content.frame(maxWidth: .infinity, alignment: .leading)
        }.padding(14)
            .background(AppPalette.canvas, in: RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(AppPalette.border))
    }
}
#endif
