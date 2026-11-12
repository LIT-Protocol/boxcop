import XCTest
@testable import BoxCopCore

final class WorkflowJudgmentTests: XCTestCase {
    func testWorkflowUsageIsDecodedAndValidated() throws {
        let counters: [String: Int] = ["attempts": 2, "ready": 1, "uncertain": 1, "unsupported": 0, "unavailable": 0, "error": 0]
        var usage: [String: Any] = ["persistence_ok": true, "backends": ["minilm-head-v1": counters, "qwen3.5-4b-workflow-v2": counters]]
        func decode() throws -> WorkflowJudgmentStatus {
            let value: [String: Any] = ["state": "waiting", "model": "Qwen", "promptVersion": "workflow-judgment-v2", "advisoryOnly": true, "modelUsage": usage]
            return try JSONDecoder().decode(WorkflowJudgmentStatus.self, from: JSONSerialization.data(withJSONObject: value))
        }
        XCTAssertEqual(try decode().modelUsage?.qwen.attempts, 2)
        XCTAssertTrue(try decode().isValid)
        var invalid = counters; invalid["ready"] = 3
        usage["backends"] = ["minilm-head-v1": counters, "qwen3.5-4b-workflow-v2": invalid]
        XCTAssertThrowsError(try decode())
    }

    func testSetupProgressIsBounded() throws {
        var status: [String: Any] = ["state": "reviewing", "model": "Qwen3.5-4B-Q4_K_M",
            "promptVersion": "workflow-judgment-v1", "advisoryOnly": true,
            "setup": ["state": "downloading", "downloadedBytes": 100, "totalBytes": 2740937888]]
        func valid() throws -> Bool {
            try JSONDecoder().decode(WorkflowJudgmentStatus.self, from: JSONSerialization.data(withJSONObject: status)).isValid
        }
        XCTAssertTrue(try valid())
        status["setup"] = ["state": "downloading", "downloadedBytes": -1, "totalBytes": 2740937888]
        XCTAssertFalse(try valid())
        status["setup"] = ["state": "unexpected", "downloadedBytes": 0, "totalBytes": 2740937888]
        XCTAssertFalse(try valid())
    }

    func testReviewRequiresAdvisoryModeAndBoundEvidence() throws {
        let id = UUID().uuidString
        var review: [String: Any] = ["state": "ready", "model": "qwen3.5:4b", "promptVersion": "workflow-judgment-v1", "advisoryOnly": true, "superseded": true,
            "result": ["snapshotID": String(repeating: "a", count: 64), "contextID": id, "revision": 2,
                "observedAt": "2026-11-03T20:00:00Z", "evidenceEventIDs": [id], "intent": "Summarize a report",
                "risk": "needs_review", "incomplete": true, "uncertainties": ["Tool execution is unconfirmed"],
                "findings": [["summary": "Requested action differs from the task", "recommendation": "Review the request", "eventIDs": [id]]]]]
        func decode(_ value: [String: Any]) throws -> WorkflowJudgmentStatus {
            try JSONDecoder().decode(WorkflowJudgmentStatus.self, from: JSONSerialization.data(withJSONObject: value))
        }
        XCTAssertTrue(try decode(review).isValid)
        review["advisoryOnly"] = false
        XCTAssertFalse(try decode(review).isValid)
        review["advisoryOnly"] = true
        var result = review["result"] as! [String: Any]
        result["evidenceEventIDs"] = [UUID().uuidString]; review["result"] = result
        XCTAssertFalse(try decode(review).isValid)
        review.removeValue(forKey: "result")
        XCTAssertFalse(try decode(review).isValid)
        review["state"] = "unavailable"
        XCTAssertTrue(try decode(review).isValid)
    }
}
