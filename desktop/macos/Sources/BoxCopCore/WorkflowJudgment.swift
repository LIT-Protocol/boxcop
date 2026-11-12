import Foundation

public struct WorkflowJudgmentStatus: Decodable, Sendable {
    public struct Finding: Decodable, Sendable {
        public let summary: String
        public let recommendation: String
        public let eventIDs: [UUID]
    }
    public struct EmailReviewSignals: Decodable, Sendable {
        public let linkedOutputs: Int
        public let revisionPairs: Int
        public let interactionSeconds: Int
        public let pasteToActionSeconds: Double?
        public var isValid: Bool {
            [linkedOutputs, revisionPairs, interactionSeconds].allSatisfy { (0...3840).contains($0) } &&
                (pasteToActionSeconds == nil || (pasteToActionSeconds!.isFinite && (0...86400).contains(pasteToActionSeconds!)))
        }
    }
    public struct EmailReview: Decodable, Sendable {
        public let scoreVersion: String?
        public let signals: EmailReviewSignals?
        public let targetEventID: UUID
        public let compositionID: String
        public let draftVersion: String
        public let phase: String
        public let probability: Double?
        public let threshold: Double
        public let reason: String
        public let eventIDs: [UUID]
        public let outcome: String
    }
    public struct EmailReviewAnnotation: Decodable, Sendable {
        public let key: String
        public let label: String
        public let annotationVersion: String
        public let eventIDs: [UUID]
    }
    public struct Review: Decodable, Sendable {
        public let emailReviewAnnotations: [EmailReviewAnnotation]?
        public let emailReviews: [EmailReview]?
        public let snapshotID: String
        public let contextID: UUID
        public let revision: Int
        public let observedAt: String
        public let evidenceEventIDs: [UUID]
        public let intent: String
        public let risk: String
        public let findings: [Finding]
        public let uncertainties: [String]
        public let incomplete: Bool
    }
    public struct Setup: Decodable, Sendable {
        public let state: String
        public let downloadedBytes: Int
        public let totalBytes: Int
        public var isValid: Bool {
            ["waiting", "waiting_for_download", "downloading", "verifying", "loading", "ready", "error"].contains(state) &&
                totalBytes > 0 && totalBytes <= 10_000_000_000 && downloadedBytes >= 0 && downloadedBytes <= totalBytes
        }
    }
    public let modelUsage: ModelUsageStatus?
    public let setup: Setup?
    public let state: String
    public let model: String
    public let promptVersion: String
    public let advisoryOnly: Bool
    public let superseded: Bool?
    public let result: Review?

    public var isValid: Bool {
        guard setup?.isValid != false, advisoryOnly, ["waiting", "reviewing", "ready", "unavailable", "insufficient_evidence"].contains(state),
              model.count <= 128, promptVersion.count <= 128 else { return false }
        guard let result else { return state != "ready" }
        let ids = Set(result.evidenceEventIDs)
        let valid = state == "ready" && superseded != nil && result.snapshotID.count == 64 && result.revision >= 0 &&
            result.observedAt.count <= 64 && result.intent.count <= 240 && ids.count <= 64 &&
            ["no_concern_observed", "needs_review", "high_risk", "insufficient_evidence"].contains(result.risk) &&
            (result.emailReviewAnnotations ?? []).count <= 8 && (result.emailReviewAnnotations ?? []).allSatisfy { a in
                a.key.count == 64 && a.annotationVersion == "email-engagement-v1" &&
                ["specific_correction", "final_check", "superficial", "unknown"].contains(a.label) &&
                a.eventIDs.count == 3 && Set(a.eventIDs).isSubset(of: ids)
            } && (result.emailReviews ?? []).count <= 4 && (result.emailReviews ?? []).allSatisfy { e in
                ids.contains(e.targetEventID) && (e.scoreVersion == nil || ["email-review-rules-v1", "email-review-rules-v2"].contains(e.scoreVersion ?? "")) && e.signals?.isValid != false && e.reason.count <= 400 && e.threshold == 0.75 &&
                (e.probability == nil || (e.probability!.isFinite && (0...1).contains(e.probability!))) &&
                e.eventIDs.contains(e.targetEventID) && e.eventIDs.count <= 8 && Set(e.eventIDs).isSubset(of: ids)
            } && result.findings.count <= 3 && result.uncertainties.count <= 5 && result.uncertainties.allSatisfy { $0.count <= 240 } &&
            result.findings.allSatisfy { $0.summary.count <= 400 && $0.recommendation.count <= 240 &&
                !$0.eventIDs.isEmpty && $0.eventIDs.count <= 6 && Set($0.eventIDs).isSubset(of: ids) }
        return valid
    }
}
