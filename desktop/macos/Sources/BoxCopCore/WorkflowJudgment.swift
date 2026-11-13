import Foundation

/// What the local model reported about recent linked activity. Advisory only: it may tighten review, never loosen protection.
public struct WorkflowJudgmentStatus: Decodable, Sendable {
    public struct Finding: Decodable, Sendable {
        public let summary: String
        public let recommendation: String
        /// Timeline ids: a UUID string, or `engine:<event id>` for an engine decision.
        public let eventIDs: [String]
        public init(summary: String, recommendation: String, eventIDs: [String]) {
            self.summary = summary; self.recommendation = recommendation; self.eventIDs = eventIDs
        }
    }
    public struct Review: Decodable, Sendable {
        public let snapshotID: String
        public let contextID: UUID
        public let revision: Int
        public let observedAt: String
        public let evidenceEventIDs: [String]
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
        /// The engine's own sentence for a failed setup, shown as written. Nil unless `state` is `error`.
        public let message: String?
        enum CodingKeys: String, CodingKey { case state, downloadedBytes, totalBytes, message }
        public init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            state = try c.decode(String.self, forKey: .state)
            downloadedBytes = try c.decode(Int.self, forKey: .downloadedBytes)
            totalBytes = try c.decode(Int.self, forKey: .totalBytes)
            let text = ((try? c.decodeIfPresent(String.self, forKey: .message)) ?? nil)?.trimmingCharacters(in: .whitespacesAndNewlines)
            message = text.flatMap { $0.isEmpty ? nil : String($0.prefix(400)) }
        }
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
            result.observedAt.count <= 64 && result.intent.count <= 240 && ids.count <= 64 && ids.allSatisfy(EngineObservation.citable) &&
            ["no_concern_observed", "needs_review", "high_risk", "insufficient_evidence"].contains(result.risk) &&
            result.findings.count <= 3 && result.uncertainties.count <= 5 && result.uncertainties.allSatisfy { $0.count <= 240 } &&
            result.findings.allSatisfy { $0.summary.count <= 400 && $0.recommendation.count <= 240 &&
                !$0.eventIDs.isEmpty && $0.eventIDs.count <= 6 && Set($0.eventIDs).isSubset(of: ids) }
    }
}
