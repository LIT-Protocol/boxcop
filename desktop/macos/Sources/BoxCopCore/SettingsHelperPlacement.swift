import Foundation
import CoreGraphics

public enum SettingsHelperPlacement {
    /// AppKit coordinates. Dialogs may precede the main window in front-to-back order.
    public static func frame(windows: [CGRect], panelSize: CGSize, visibleFrames: [CGRect]) -> CGRect? {
        guard let anchor = windows.max(by: { $0.width * $0.height < $1.width * $1.height }),
              let visible = visibleFrames.max(by: {
                  area($0.intersection(anchor)) < area($1.intersection(anchor))
              }), visible.intersects(anchor),
              panelSize.width <= visible.width - 16 else { return nil }
        let x = min(max(anchor.midX - panelSize.width / 2, visible.minX + 8),
                    visible.maxX - panelSize.width - 8)
        let frame = CGRect(x: x, y: anchor.minY - panelSize.height - 8,
                           width: panelSize.width, height: panelSize.height)
        // Never clamp upward into a window or a system approval dialog.
        guard visible.contains(frame), !windows.contains(where: { $0.intersects(frame) }) else { return nil }
        return frame
    }

    private static func area(_ rect: CGRect) -> CGFloat {
        rect.isNull ? 0 : rect.width * rect.height
    }
}
