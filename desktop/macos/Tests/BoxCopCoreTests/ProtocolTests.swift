import XCTest
@testable import BoxCopCore

final class ProtocolTests: XCTestCase {
    let status = #"{"version":1,"id":"r1","ok":true,"result":{"ready":true,"protocol":1,"engine":"rules+sequence","monitoring":false,"network_listener":false}}"#
    func testStrictStatusAndReadiness() throws {
        let response = try WireCodec.decode(Data(status.utf8))
        XCTAssertEqual(response.id, "r1")
        guard case .status = response.result else { return XCTFail("Not a status result") }
        for bad in [status.replacingOccurrences(of: "\"ready\":true", with: "\"ready\":false"), status.replacingOccurrences(of: "\"monitoring\":false", with: "\"monitoring\":true"), status.replacingOccurrences(of: "\"network_listener\":false", with: "\"network_listener\":true")] {
            XCTAssertThrowsError(try WireCodec.decode(Data(bad.utf8)))
        }
    }
    private func classificationEnvelope(_ usage: [String: Any]? = nil) throws -> Data {
        var envelope = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(status.utf8)) as? [String: Any])
        var result = try XCTUnwrap(envelope["result"] as? [String: Any])
        var classification: [String: Any] = ["hits": 4, "misses": 3, "coalesced": 0, "dropped": 0,
            "completed": 3, "failures": 0, "queued": 0, "cached": 3, "active": false,
            "shadow_only": true, "ready": 2, "uncertain": 1, "unavailable": 0]
        if let usage { classification["model_usage"] = usage }
        result["classification"] = classification; envelope["result"] = result
        return try JSONSerialization.data(withJSONObject: envelope)
    }
    private var usage: [String: Any] {
        ["persistence_ok": true, "backends": [
            "minilm-head-v1": ["attempts": 3, "ready": 2, "uncertain": 1, "unsupported": 0, "unavailable": 0, "error": 0],
            "qwen3.5-4b-workflow-v2": ["attempts": 1, "ready": 0, "uncertain": 1, "unsupported": 0, "unavailable": 0, "error": 0]]]
    }
    func testModelUsageAndLegacyCacheStatus() throws {
        let response = try WireCodec.decode(classificationEnvelope(usage))
        guard case let .status(classification?) = response.result else { return XCTFail("Missing classification") }
        XCTAssertEqual(classification.hits, 4)
        XCTAssertEqual(classification.modelUsage?.minilm.attempts, 3)
        XCTAssertEqual(classification.modelUsage?.qwen.uncertain, 1)
        XCTAssertEqual(classification.summary, "Local checks are ready.")
        let legacy = try WireCodec.decode(classificationEnvelope())
        guard case let .status(old?) = legacy.result else { return XCTFail("Missing legacy classification") }
        XCTAssertNil(old.modelUsage)
        XCTAssertEqual(old.summary, "Local checks are ready.")
    }
    func testModelUsageRetainsPersistenceFailureAndUnfinishedAttempts() throws {
        var value = usage
        value["persistence_ok"] = false
        var backends = try XCTUnwrap(value["backends"] as? [String: [String: Int]])
        backends["minilm-head-v1"]?["attempts"] = 4
        value["backends"] = backends
        let response = try WireCodec.decode(classificationEnvelope(value))
        guard case let .status(classification?) = response.result else { return XCTFail("Missing classification") }
        XCTAssertEqual(classification.summary, "Local checks are ready.")
        XCTAssertEqual(classification.modelUsage?.persistenceOK, false)
        XCTAssertEqual(classification.modelUsage?.minilm.attempts, 4)
    }
    func testModelUsageRejectsUntrustedFieldsAndInvalidCounts() throws {
        for (key, value) in [("attempts", -1 as Any), ("ready", 4 as Any), ("error", true as Any), ("text", "PRIVATE" as Any)] {
            var changed = usage
            var backends = try XCTUnwrap(changed["backends"] as? [String: [String: Any]])
            backends["minilm-head-v1"]?[key] = value
            changed["backends"] = backends
            XCTAssertThrowsError(try WireCodec.decode(classificationEnvelope(changed)))
        }
        var changed = usage
        changed["text"] = "PRIVATE"
        XCTAssertThrowsError(try WireCodec.decode(classificationEnvelope(changed)))
        changed = usage
        changed["backends"] = ["unrecognized-model": ["attempts": 0]]
        XCTAssertThrowsError(try WireCodec.decode(classificationEnvelope(changed)))
    }
    func testExtraKeysDuplicateKeysAndWrongScalarTypesRejected() {
        let malformed = [
            status.replacingOccurrences(of: "\"version\":1", with: "\"version\":1,\"extra\":true"),
            status.replacingOccurrences(of: "\"version\":1", with: "\"version\":1,\"version\":1"),
            status.replacingOccurrences(of: "\"version\":1", with: "\"version\":1,\"ver\\u0073ion\":1"),
            status.replacingOccurrences(of: "\"ready\":true", with: "\"ready\":true,\"ignored\":0"),
            status.replacingOccurrences(of: "\"version\":1", with: "\"version\":true"),
            status.replacingOccurrences(of: "\"version\":1", with: "\"version\":1.0"),
            status.replacingOccurrences(of: "\"version\":1", with: "\"version\":NaN"),
            status.replacingOccurrences(of: "\"r1\"", with: "\"not a valid id\""),
            status + status
        ]
        for bad in malformed { XCTAssertThrowsError(try WireCodec.decode(Data(bad.utf8))) }
        XCTAssertThrowsError(try WireCodec.decode(Data([0xff])))
    }
    func testRequestShapeAndBounds() throws {
        let event = try DesktopEvent(kind: .pasteAttempt, content: "hello", bundleID: "com.apple.TextEdit", pid: 42, role: .engineering)
        let data = try WireCodec.encode(id: "r1", command: .evaluate(event))
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(Set(object.keys), ["version", "id", "op", "event"])
        let wireEvent = try XCTUnwrap(object["event"] as? [String: Any])
        XCTAssertEqual(Set(wireEvent.keys), ["kind", "content", "app_bundle_id", "app_pid", "role"])
        XCTAssertEqual(wireEvent["kind"] as? String, "paste_attempt")
        XCTAssertFalse(String(describing: event).contains("hello"))
        XCTAssertThrowsError(try DesktopEvent(kind: .clipboardCopy, content: String(repeating: "x", count: 4097), bundleID: "com.apple.TextEdit", pid: 42, role: .engineering))
        XCTAssertThrowsError(try DesktopEvent(kind: .clipboardCopy, content: "x", bundleID: "bad/id", pid: 42, role: .engineering))
        XCTAssertThrowsError(try DesktopEvent(kind: .clipboardCopy, content: "x", bundleID: "com.apple.TextEdit", pid: 0, role: .engineering))
        XCTAssertThrowsError(try WireCodec.encode(id: "bad id", command: .status))
        XCTAssertThrowsError(try WireCodec.encode(id: "r1", command: .recent(0)))
    }
    func testJSONLHandlesChunksAndMultipleFramesWithoutUnboundedBuffering() throws {
        var framer = JSONLFramer(maximumLineBytes: 8)
        XCTAssertEqual(try framer.feed(Data("abc".utf8)), [])
        XCTAssertEqual(try framer.feed(Data("\ndef\n".utf8)), [Data("abc".utf8), Data("def".utf8)])
        XCTAssertNoThrow(try framer.finish())
        XCTAssertThrowsError(try framer.feed(Data("123456789".utf8)))
        var partial = JSONLFramer()
        _ = try partial.feed(Data("{".utf8))
        XCTAssertThrowsError(try partial.finish())
    }
    func testErrorsNeverExposePeerMessage() throws {
        let response = try WireCodec.decode(Data(#"{"version":1,"id":null,"ok":false,"error":{"code":"invalid_request","message":"PRIVATE_MARKER"}}"#.utf8))
        XCTAssertEqual(response.failure, .invalidRequest)
        XCTAssertFalse(String(describing: response).contains("PRIVATE_MARKER"))
    }
    func testSanitizerMayRemoveClipboardSubstringFromBundleIdentity() throws {
        let wire = Self.recordEnvelope.replacingOccurrences(of: "com.apple.TextEdit", with: "com.[not retained].TextEdit")
        let response = try WireCodec.decode(Data(wire.utf8))
        guard case let .record(record) = response.result else { return XCTFail("Not record") }
        XCTAssertNil(record.bundleID)
    }
    func testRecordKeepsOnlySanitizedStructuredValues() throws {
        let response = try WireCodec.decode(Data(Self.recordEnvelope.utf8))
        guard case let .record(record) = response.result else { return XCTFail("Not record") }
        XCTAssertEqual(record.action, .allow)
        XCTAssertEqual(record.bundleID, "com.apple.TextEdit")
        XCTAssertFalse(String(describing: record).contains("PRIVATE_MARKER"))
        XCTAssertFalse(record.reasons.joined().contains("PRIVATE_MARKER"))
        XCTAssertThrowsError(try WireCodec.decode(Data(Self.recordEnvelope.replacingOccurrences(of: "[not retained]", with: "RAW_CLIPBOARD").utf8)))
    }
    static let recordEnvelope = #"{"version":1,"id":"r1","ok":true,"result":{"record":{"id":"e4f4041e-9a0f-44fe-aa39-7c64d1dd9dd4","created_at":"2026-10-23T12:00:00.000000+00:00","synthetic":false,"event":{"session_id":"10cb2a87-1948-4bba-bb29-e7208ec67db7","actor":"human","role":"engineering","action":"paste","app":"com.apple.TextEdit","source":"","destination":"app://com.apple.TextEdit","content":"[not retained]","declared_intent":"PRIVATE_MARKER","synthetic":false},"decision":{"action":"allow","risk_score":0.0,"summary":"PRIVATE_MARKER","reasons":["PRIVATE_MARKER"],"policy_ids":[],"labels":[],"redacted_content":"[not retained]","latency_ms":0.1,"context_event_ids":[],"engine":"rules+sequence"}}}}"#
}
