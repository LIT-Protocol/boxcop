import XCTest
@testable import BoxCopCore

final class WorkflowJudgmentTests: XCTestCase {
    func testSetupProgressIsBounded() throws {
        var status: [String: Any] = ["state": "reviewing", "model": "Qwen3.5-4B-Q4_K_M",
            "promptVersion": "workflow-judgment-v1", "advisoryOnly": true,
            "setup": ["state": "downloading", "downloadedBytes": 100, "totalBytes": 2740937888]]
        func valid() throws -> Bool {
            try JSONDecoder().decode(WorkflowJudgmentStatus.self, from: JSONSerialization.data(withJSONObject: status)).isValid
        }
        XCTAssertTrue(try valid())
        XCTAssertNil(try JSONDecoder().decode(WorkflowJudgmentStatus.self, from: JSONSerialization.data(withJSONObject: status)).setup?.message)
        let disk = "Not enough free disk space to download the triage model. It needs 6.8 GB free (a 2.7 GB download plus 4 GB left over) and 3.1 GB is available."
        status["setup"] = ["state": "error", "downloadedBytes": 0, "totalBytes": 2740937888, "message": disk]
        XCTAssertTrue(try valid())
        XCTAssertEqual(try JSONDecoder().decode(WorkflowJudgmentStatus.self, from: JSONSerialization.data(withJSONObject: status)).setup?.message, disk)
        status["setup"] = ["state": "ready", "downloadedBytes": 2740937888, "totalBytes": 2740937888, "message": NSNull()]
        XCTAssertTrue(try valid())
        XCTAssertNil(try JSONDecoder().decode(WorkflowJudgmentStatus.self, from: JSONSerialization.data(withJSONObject: status)).setup?.message)
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
        // An engine decision is cited by `engine:<event id>`; nothing else that is not a UUID is accepted.
        var cited = review["result"] as! [String: Any]
        cited["evidenceEventIDs"] = [id, "engine:3f2a9c0d1b7e4a55"]
        cited["findings"] = [["summary": "Blocked release", "recommendation": "Leave it blocked", "eventIDs": ["engine:3f2a9c0d1b7e4a55"]]]
        var engine = review; engine["result"] = cited
        let decoded = try decode(engine)
        XCTAssertTrue(decoded.isValid)
        XCTAssertEqual(decoded.result?.findings.first?.eventIDs, ["engine:3f2a9c0d1b7e4a55"])
        cited["evidenceEventIDs"] = [id, "engine:not valid"]; cited["findings"] = []; engine["result"] = cited
        XCTAssertFalse(try decode(engine).isValid)
        cited["evidenceEventIDs"] = ["approval:rq-1"]; engine["result"] = cited
        XCTAssertFalse(try decode(engine).isValid)
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
