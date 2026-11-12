#if os(macOS)
import SwiftUI
import BoxCopCore

struct WorkflowJudgmentView: View {
    let status: WorkflowJudgmentStatus?
    var body: some View {
        GroupBox("AI workflow review") {
            VStack(alignment: .leading, spacing: 10) {
                if status?.result == nil, let setup = status?.setup, ["downloading", "verifying", "loading", "waiting_for_download"].contains(setup.state) {
                    Text(setup.state == "downloading" ? "Downloading the local safety model…" :
                         setup.state == "verifying" ? "Verifying the local safety model…" :
                         setup.state == "loading" ? "Starting local AI review…" : "Waiting for the model download…")
                    if setup.state == "downloading" {
                        ProgressView(value: Double(setup.downloadedBytes), total: Double(setup.totalBytes))
                        Text("\(ByteCountFormatter.string(fromByteCount: Int64(setup.downloadedBytes), countStyle: .file)) of \(ByteCountFormatter.string(fromByteCount: Int64(setup.totalBytes), countStyle: .file))")
                            .font(.caption)
                    } else { ProgressView().controlSize(.small) }
                    Text("One-time model setup. Reviews run on your Mac; your workflow is never sent to the download service. Turn off Local AI workflow review in Policies to cancel setup.")
                        .font(.caption).foregroundStyle(.secondary)
                } else if let review = status?.result {
                    Text((review.emailReviews ?? []).contains(where: { $0.outcome == "high_risk" }) ? "Email work needs review" : title(review.risk)).font(.headline)
                    Text(review.intent)
                    ForEach(Array((review.emailReviews ?? []).enumerated()), id: \.offset) { _, email in
                        VStack(alignment: .leading, spacing: 4) {
                            Text(email.probability.map { "Review-risk score: \(Int(($0 * 100).rounded()))/100" } ?? "Email review: insufficient evidence").font(.headline)
                            if email.outcome == "high_risk" { Text("Please review this message. Sending was not blocked.").foregroundStyle(.orange) }
                            if email.outcome == "high_risk" { AlertFeedbackButton(category: .emailReview) }
                            Text(email.reason)
                            Text("Draft version \(email.draftVersion) · \(email.phase == "send_attempted" ? "Send attempt, delivery unconfirmed" : "Draft assessment") · uncalibrated score, not proof of quality or review").font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    Text("Reviewed activity as of \(review.observedAt)" +
                         (status?.superseded == true ? " · newer activity has not been reviewed yet" : ""))
                        .font(.caption).foregroundStyle(.secondary)
                    ForEach(Array(review.findings.enumerated()), id: \.offset) { _, finding in
                        VStack(alignment: .leading, spacing: 4) {
                            Text(finding.summary)
                            Text(finding.recommendation).foregroundStyle(.secondary)
                            AlertFeedbackButton(category: .workflow)
                        }
                    }
                    ForEach(Array(review.uncertainties.enumerated()), id: \.offset) { _, uncertainty in
                        Text("Uncertainty: " + uncertainty).font(.caption)
                    }
                    if review.incomplete { Text("This review includes only part of your activity.").font(.caption) }
                } else if status?.state == "unavailable" {
                    Text("Local AI review unavailable")
                    Text("BoxCop will retry automatically. Check your internet connection and allow 3 GB of free disk space for initial setup. To retry now, turn Local AI workflow review off and on in Policies. Reviews run locally with the engine included in BoxCop; no separate app is required.")
                        .font(.caption).foregroundStyle(.secondary)
                } else {
                    Text(status?.state == "reviewing" ? "Reviewing recent activity…" : "Waiting for activity to review. BoxCop downloads its 2.7 GB safety model when first needed, then reviews locally.")
                }
                Text("AI reviews can miss risks or make mistakes. They offer advice and do not block actions.")
                    .font(.caption).foregroundStyle(.secondary)
            }.frame(maxWidth: .infinity, alignment: .leading).padding(8)
        }
    }
    private func title(_ risk: String) -> String {
        switch risk {
        case "high_risk": return "Potential high-risk activity"
        case "needs_review": return "This workflow needs review"
        case "no_concern_observed": return "No concern identified in the reviewed context"
        default: return "Insufficient evidence for a judgment"
        }
    }
}
#endif
