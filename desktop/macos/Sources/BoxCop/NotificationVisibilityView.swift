#if os(macOS)
import SwiftUI

/// Notification permission alone does not establish that an alert was visible.
struct NotificationVisibilityView: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Focus can hide macOS notification banners while BoxCop continues monitoring. Pending reviews remain in Activity and the menu bar. To allow macOS banners through, add BoxCop in System Settings → Focus.")
                .font(.caption).foregroundStyle(.secondary)
            HStack {
                Link("Notification Settings", destination: URL(string: "x-apple.systempreferences:com.apple.Notifications-Settings.extension")!)
            }
        }
    }
}
#endif
