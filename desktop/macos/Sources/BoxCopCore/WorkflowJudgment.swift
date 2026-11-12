import Foundation

/// What the local model reported about recent linked activity. Advisory only: it may tighten review, never loosen protection.
public struct WorkflowJudgmentStatus: Decodable, Sendable {
    public struct Finding: Decodable, Sendable {
        public let summary: String
        public let recommendation: String
        public let eventIDs: [UUID]
    }
    public struct Review: Decodable, Sendable {
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
        public var fraction: Double { Double(downloadedBytes) / Double(max(totalBytes, 1)) }
    }
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
        return state == "ready" && superseded != nil && result.snapshotID.count == 64 && result.revision >= 0 &&
            result.observedAt.count <= 64 && result.intent.count <= 240 && ids.count <= 64 &&
            ["no_concern_observed", "needs_review", "high_risk", "insufficient_evidence"].contains(result.risk) &&
            result.findings.count <= 3 && result.uncertainties.count <= 5 && result.uncertainties.allSatisfy { $0.count <= 240 } &&
            result.findings.allSatisfy { $0.summary.count <= 400 && $0.recommendation.count <= 240 &&
                !$0.eventIDs.isEmpty && $0.eventIDs.count <= 6 && Set($0.eventIDs).isSubset(of: ids) }
    }
}
