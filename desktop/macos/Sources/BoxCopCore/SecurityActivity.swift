import Foundation

/// Deliberately excludes routine observations and prospective policy decisions.
public struct SecurityActivityItem: Identifiable, Sendable {
    public let id: UUID
    public let date: Date
    public let title: String
    public let summary: String
    public let detail: String
    public let feedbackCategory: AlertFeedbackCategory?

    public static func make(records: [SafeRecord], events: [WorkflowEvent]) -> [Self] {
        var items = records.filter { $0.kind == .pasteAttempt && ($0.action == .block || $0.action == .warn) }.map { record in
            Self(id: record.id, date: record.createdAt,
                 title: record.action == .block ? "Paste policy: block" : "Paste policy: warning",
                 summary: record.reasons.joined(separator: " "),
                 detail: "App: \(record.bundleID ?? "Unknown")\n\(record.reasons.joined(separator: "\n"))\nPolicy result for a paste attempt; not confirmation of transfer.\nReference: \(record.id)", feedbackCategory: .paste)
        }
        for event in events {
            let title: String
            let reason: String
            switch event.kind {
            case "network_connection" where event.fields["decision"]?.value == "blocked_threat_domain":
                title = "Connection blocked"
                reason = event.fields["threat_reason"]?.value ?? "Destination matched the threat domain list."
            case "screen_share_preflight" where event.availability == "share_blocked_sensitive":
                title = "Screen share stopped"
                reason = "Sensitive content was visible during the share check."
            case "screen_share_preflight" where event.availability == "share_held_unavailable":
                title = "Screen share held"
                reason = "Screen evidence was unavailable or incomplete."
            case "screen_assessment" where event.fields["assessment"]?.value == "possible_sensitive_content":
                title = "Sensitive content warning"
                reason = "Possible sensitive content detected during screen capture. This warning does not confirm exposure was prevented."
            case "paste_override_granted":
                title = "Paste override granted"
                reason = "You authorized a one-time paste override."
            case "paste_override_passed":
                title = "Paste override used"
                reason = "The shortcut passed with an override. Actual insertion was not observed."
            default: continue
            }
            let context = [event.bundleID, event.fields["hostname"]?.value, event.fields["threat_source"]?.value].compactMap { $0 }.joined(separator: " · ")
            items.append(Self(id: event.id, date: event.observedAt, title: title, summary: reason,
                              detail: [reason, context, "Source: \(event.collector)", "Reference: \(event.id)"].filter { !$0.isEmpty }.joined(separator: "\n"),
                              feedbackCategory: event.kind == "network_connection" ? .network : event.kind.hasPrefix("screen_") ? .screenSharing : nil))
        }
        return items.sorted { $0.date > $1.date }
    }
}
