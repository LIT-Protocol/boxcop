import XCTest
@testable import BoxCopCore

final class ProtocolTests: XCTestCase {
    let status = #"{"version":1,"id":"r1","ok":true,"result":{"ready":true,"protocol":1,"engine":"rules","network_listener":false}}"#
    func testStatusHandshakeRequiresRulesEngineAndReadiness() throws {
        let response = try WireCodec.decode(Data(status.utf8))
        XCTAssertEqual(response.id, "r1")
        guard case let .status(listeners) = response.result else { return XCTFail("Not a status result") }
        XCTAssertEqual(listeners, EngineStatus(packageRegistryListener: false, installScriptListener: false))
        for bad in [status.replacingOccurrences(of: "\"ready\":true", with: "\"ready\":false"),
                    status.replacingOccurrences(of: "\"engine\":\"rules\"", with: "\"engine\":\"rules+sequence\""),
                    status.replacingOccurrences(of: "\"protocol\":1", with: "\"protocol\":2"),
                    status.replacingOccurrences(of: "\"network_listener\":false", with: "\"network_listener\":true"),
                    status.replacingOccurrences(of: "\"network_listener\":false", with: "\"monitoring\":true")] {
            XCTAssertThrowsError(try WireCodec.decode(Data(bad.utf8)), bad)
        }
    }
    func testStatusListenerFlagsAreOptionalAndReported() throws {
        let minimal = #"{"version":1,"id":"r1","ok":true,"result":{"ready":true,"protocol":1,"engine":"rules"}}"#
        guard case .status = try WireCodec.decode(Data(minimal.utf8)).result else { return XCTFail("Minimal status rejected") }
        let both = #"{"version":1,"id":"r1","ok":true,"result":{"ready":true,"protocol":1,"engine":"rules","monitoring":false,"network_listener":true,"package_registry_listener":true,"install_script_listener":true}}"#
        guard case let .status(listeners) = try WireCodec.decode(Data(both.utf8)).result else { return XCTFail("Listener status rejected") }
        XCTAssertTrue(listeners.packageRegistryListener && listeners.installScriptListener)
        let paste = status.replacingOccurrences(of: "\"network_listener\":false", with: "\"classification\":{}")
        XCTAssertThrowsError(try WireCodec.decode(Data(paste.utf8)), "Removed classifier fields are not accepted")
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
        let data = try WireCodec.encode(id: "r1", command: .securityEvents(50))
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(Set(object.keys), ["version", "id", "op", "limit"])
        XCTAssertEqual(object["op"] as? String, "security_events")
        XCTAssertEqual(object["limit"] as? Int, 50)
        XCTAssertEqual(object["version"] as? Int, 1)
        XCTAssertThrowsError(try WireCodec.encode(id: "bad id", command: .status))
        XCTAssertThrowsError(try WireCodec.encode(id: "r1", command: .securityEvents(0)))
        XCTAssertThrowsError(try WireCodec.encode(id: "r1", command: .securityEvents(201)))
        XCTAssertEqual(Set([EngineCommand.status, .shutdown, .workflowClear(), .securityEvents(1), .packageProtection(.status), .scriptProtection(.status)].map(\.operation)),
                       ["status", "shutdown", "workflow_clear", "security_events", "package_protection", "script_protection"])
    }
    func testWorkflowClearCanAskForTheModelToBeRemoved() throws {
        func request(_ command: EngineCommand) throws -> [String: Any] {
            try XCTUnwrap(JSONSerialization.jsonObject(with: WireCodec.encode(id: "w1", command: command)) as? [String: Any])
        }
        XCTAssertEqual(Set(try request(.workflowClear()).keys), ["version", "id", "op"])
        let remove = try request(.workflowClear(removeModel: true))
        XCTAssertEqual(Set(remove.keys), ["version", "id", "op", "remove_model"])
        XCTAssertEqual(remove["remove_model"] as? Bool, true)
        func reply(_ result: String) throws -> EngineResult? { try WireCodec.decode(Data(#"{"version":1,"id":"w1","ok":true,"result":\#(result)}"#.utf8)).result }
        guard case let .workflowCleared(plain)? = try reply(#"{"workflowCleared":true}"#) else { return XCTFail("Not cleared") }
        XCTAssertNil(plain)
        guard case let .workflowCleared(removed)? = try reply(#"{"workflowCleared":true,"modelRemoved":true,"freedBytes":2740937888}"#) else { return XCTFail("Not cleared") }
        XCTAssertEqual(removed, ModelRemoval(removed: true, freedBytes: 2_740_937_888))
        guard case let .workflowCleared(held)? = try reply(#"{"workflowCleared":true,"modelRemoved":false,"freedBytes":0}"#) else { return XCTFail("Not cleared") }
        XCTAssertEqual(held, ModelRemoval(removed: false, freedBytes: 0))
        for bad in [#"{"workflowCleared":false}"#, #"{"workflowCleared":true,"freedBytes":-1}"#, #"{"workflowCleared":true,"freedBytes":1.5}"#,
                    #"{"workflowCleared":true,"modelRemoved":"yes"}"#, #"{"workflowCleared":true,"path":"/tmp"}"#] {
            XCTAssertThrowsError(try reply(bad), bad)
        }
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
}

final class SecurityEventsProtocolTests: XCTestCase {
    static let blocked = #"{"id":"evt-1","time":"2026-11-12T20:15:03Z","layer":"install_gate","outcome":"blocked","title":"Blocked install of evil-pkg 1.2.3","reason":"This exact release is on the known-malware feed.","subject":"evil-pkg@1.2.3","agent":"claude","command":"npm install evil-pkg","package":"evil-pkg","host":null,"policy_ids":["known-malicious-package"]}"#
    static let warned = #"{"id":"evt-2","time":"2026-11-12T20:16:00.250Z","layer":"agent_actions","outcome":"warned","title":"Warned about reading a credential file","reason":"The command reads a credential file locally.","subject":"cat ~/.netrc","agent":null,"command":null,"package":null,"host":null,"policy_ids":[],"ecosystem":null,"version":null,"allowable":false}"#
    static let reported = #"{"id":"9f0c1a","time":"2026-11-12T10:00:00Z","layer":"install_gate","outcome":"blocked","title":"Blocked install of left-pad 1.0.1 (reported as malware)","reason":"This release is reported as malware by ghsa, but not yet confirmed.","subject":"left-pad@1.0.1","agent":null,"command":null,"package":"left-pad","host":null,"policy_ids":["known-malicious-package"],"ecosystem":"npm","version":"1.0.1","allowable":true}"#

    func testEventsDecodeFromResultEnvelope() throws {
        let wire = #"{"version":1,"id":"e1","ok":true,"result":{"events":[\#(Self.blocked),\#(Self.warned)]}}"#
        guard case let .securityEvents(events) = try WireCodec.decode(Data(wire.utf8)).result else { return XCTFail("Not events") }
        XCTAssertEqual(events.map(\.id), ["evt-1", "evt-2"])
        let first = events[0]
        XCTAssertEqual(first.layer, .installGate); XCTAssertEqual(first.outcome, .blocked)
        XCTAssertEqual(first.title, "Blocked install of evil-pkg 1.2.3")
        XCTAssertEqual(first.subject, "evil-pkg@1.2.3"); XCTAssertEqual(first.agent, "claude")
        XCTAssertEqual(first.command, "npm install evil-pkg"); XCTAssertEqual(first.package, "evil-pkg")
        XCTAssertNil(first.host); XCTAssertEqual(first.policyIDs, ["known-malicious-package"])
        XCTAssertEqual(first.time, ISO8601DateFormatter().date(from: "2026-11-12T20:15:03Z"))
        XCTAssertEqual(events[1].layer, .agentActions); XCTAssertEqual(events[1].outcome, .warned)
        XCTAssertNil(events[1].agent); XCTAssertNil(events[1].command)
        XCTAssertEqual(events[1].time.timeIntervalSince(first.time), 57.25, accuracy: 0.001)
    }
    func testInstallGateRowsCarryTheExactReleaseAndWhetherItMayBeAllowed() throws {
        let wire = #"{"version":1,"id":"e1","ok":true,"result":{"events":[\#(Self.reported),\#(Self.blocked),\#(Self.warned)]}}"#
        guard case let .securityEvents(events) = try WireCodec.decode(Data(wire.utf8)).result else { return XCTFail("Not events") }
        XCTAssertEqual(events[0].release, PackageRelease(ecosystem: "npm", package: "left-pad", version: "1.0.1"))
        XCTAssertTrue(events[0].allowable); XCTAssertTrue(events[0].reportedOnly)
        // An engine that predates exceptions omits the three keys: nothing is allowable and no release is named.
        XCTAssertNil(events[1].ecosystem); XCTAssertNil(events[1].version); XCTAssertNil(events[1].release)
        XCTAssertFalse(events[1].allowable); XCTAssertFalse(events[1].reportedOnly)
        XCTAssertFalse(events[2].allowable); XCTAssertNil(events[2].release)
        // Wrongly typed additions are ignored, not fatal to the row.
        let odd = Self.reported.replacingOccurrences(of: "\"allowable\":true", with: "\"allowable\":\"yes\"").replacingOccurrences(of: "\"ecosystem\":\"npm\"", with: "\"ecosystem\":7")
        guard case let .securityEvents(rows) = try WireCodec.decode(Data(#"{"version":1,"id":"e1","ok":true,"result":{"events":[\#(odd)]}}"#.utf8)).result else { return XCTFail("Not events") }
        XCTAssertEqual(rows.map(\.id), ["9f0c1a"]); XCTAssertFalse(rows[0].allowable); XCTAssertNil(rows[0].release)
    }
    func testOutcomesThatNoLongerExistAreSkipped() throws {
        let rows = ["held", "approved", "rejected"].map { Self.warned.replacingOccurrences(of: "\"warned\"", with: "\"\($0)\"") }.joined(separator: ",")
        let wire = #"{"version":1,"id":"e1","ok":true,"result":{"events":[\#(rows),\#(Self.blocked)]}}"#
        guard case let .securityEvents(events) = try WireCodec.decode(Data(wire.utf8)).result else { return XCTFail("Not events") }
        XCTAssertEqual(events.map(\.id), ["evt-1"])
    }
    func testEventsDecodeFromTopLevelListAsWrittenInTheContract() throws {
        for wire in [#"{"ok":true,"id":"e1","events":[\#(Self.blocked)]}"#, #"{"version":1,"ok":true,"id":"e1","events":[]}"#] {
            let response = try WireCodec.decode(Data(wire.utf8))
            XCTAssertEqual(response.id, "e1")
            guard case .securityEvents = response.result else { return XCTFail("Not events") }
        }
    }
    func testUnknownLayerOrOutcomeSkipsOnlyThatRowAndMissingFieldsAreTolerated() throws {
        let future = Self.blocked.replacingOccurrences(of: "install_gate", with: "future_layer")
        let odd = Self.blocked.replacingOccurrences(of: "\"blocked\"", with: "\"observed\"")
        let sparse = #"{"id":"evt-3","time":"2026-11-12T20:17:00Z","layer":"containment","outcome":"warned","title":"Warned"}"#
        let wire = #"{"version":1,"id":"e1","ok":true,"result":{"events":[\#(future),\#(odd),\#(sparse),{"id":"x"}]}}"#
        guard case let .securityEvents(events) = try WireCodec.decode(Data(wire.utf8)).result else { return XCTFail("Not events") }
        XCTAssertEqual(events.map(\.id), ["evt-3"])
        XCTAssertEqual(events[0].reason, ""); XCTAssertEqual(events[0].policyIDs, [])
    }
    func testOversizedListAndWrongShapeAreRejected() {
        let many = Array(repeating: Self.warned, count: 201).joined(separator: ",")
        XCTAssertThrowsError(try WireCodec.decode(Data(#"{"version":1,"id":"e1","ok":true,"result":{"events":[\#(many)]}}"#.utf8)))
        XCTAssertThrowsError(try WireCodec.decode(Data(#"{"version":1,"id":"e1","ok":true,"result":{"events":{}}}"#.utf8)))
        XCTAssertThrowsError(try WireCodec.decode(Data(#"{"version":1,"id":"e1","ok":true,"result":{"events":[],"total":0}}"#.utf8)))
    }
}
