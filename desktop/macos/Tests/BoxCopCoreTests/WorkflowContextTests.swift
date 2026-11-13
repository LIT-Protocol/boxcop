import XCTest
@testable import BoxCopCore

final class WorkflowContextTests: XCTestCase {
    let now = Date(timeIntervalSince1970: 1_800_000_000)
    func event(_ index: Int, pid: UInt32 = 42, version: UInt32 = 3) -> NetworkActivityEvent {
        var event = NetworkActivityEvent(timestamp: now.addingTimeInterval(Double(index)), remoteAddress: "192.0.2.1", remotePort: "443",
            localAddress: nil, localPort: nil, hostname: "example.com", hostnameSource: "flow_remote_hostname",
            url: "https://user:password@example.com/file?secret=hidden#private", transport: "tcp", socketFamily: 2, socketType: 1,
            socketProtocol: 6, flowType: "socket", bootSessionID: "synthetic-boot")
        event.process.pid = pid; event.process.uid = 501; event.process.incarnation = version
        return event
    }
    func security(_ id: String, layer: SecurityEvent.Layer = .installGate, agent: String? = "claude", subject: String = "evil-pkg@1.2.3",
                  reason: String = "This exact release is confirmed malware.", at offset: TimeInterval) -> SecurityEvent {
        SecurityEvent(id: id, time: now.addingTimeInterval(offset), layer: layer, outcome: .blocked, title: "Blocked install of evil-pkg 1.2.3",
                      reason: reason, subject: subject, agent: agent, command: "npm install evil-pkg", package: "evil-pkg", host: "collector.example",
                      policyIDs: ["known-malicious-package"], ecosystem: "npm", version: "1.2.3")
    }
    func page(_ events: [NetworkActivityEvent], after: UUID? = nil) -> NetworkWorkflowPage {
        .init(retained: events, after: after, loggingDropped: 0, writeFailures: 0, providerStartedAt: now)
    }
    func testNetworkPagingDedupAndExpiredCursorExposeLoss() {
        let events = (0..<150).map { event($0) }
        var importer = NetworkWorkflowImporter(), timeline = WorkflowTimeline()
        importer.ingest(page(events), into: &timeline)
        importer.ingest(page(events), into: &timeline) // transport retry must not duplicate network events
        XCTAssertEqual(timeline.events.filter { $0.kind == "network_connection" }.count, 64)
        importer.ingest(page(events, after: importer.cursor), into: &timeline)
        importer.ingest(page(events, after: importer.cursor), into: &timeline)
        XCTAssertEqual(timeline.events.filter { $0.kind == "network_connection" }.count, 150)
        XCTAssertEqual(importer.cursor, events.last?.id)
        importer.ingest(page(Array(events.suffix(3)), after: UUID()), into: &timeline)
        XCTAssertTrue(timeline.events.contains { $0.kind == "collector_health" && $0.availability == "incomplete" })
        let connection = timeline.events.first { $0.kind == "network_connection" }!
        XCTAssertEqual(connection.fields["network_event_id"]?.value, events[0].id.uuidString)
        XCTAssertEqual(connection.observedAt, events[0].timestamp)
        XCTAssertEqual(connection.fields["url"]?.value, "https://example.com/file")
    }
    func testClearCannotReimportOldNetworkHistory() {
        var importer = NetworkWorkflowImporter(), timeline = WorkflowTimeline()
        importer.clear(at: now.addingTimeInterval(10))
        importer.ingest(page([event(1), event(11)]), into: &timeline)
        XCTAssertEqual(timeline.events.filter { $0.kind == "network_connection" }.count, 1)
    }
    func testExactProcessInstanceAndReportedAgentScopesRemainDistinct() {
        var importer = NetworkWorkflowImporter(), timeline = WorkflowTimeline()
        importer.ingest(page([event(0), event(1), event(2, version: 4)]), into: &timeline)
        func decision(_ id: String, _ agent: String, at offset: TimeInterval) -> String {
            EngineObservation.append(security(id, agent: agent, at: offset), to: &timeline)!
        }
        let first = decision("d1", "claude", at: 0), second = decision("d2", "claude", at: 3), other = decision("d3", "cursor", at: 4)
        let context = WorkflowContext.build(from: timeline, sources: [], now: now.addingTimeInterval(5))
        XCTAssertEqual(context.links.filter { $0.relation == "same_kernel_process_instance" }.count, 1)
        XCTAssertTrue(context.links.contains { $0.sourceEventID == first && $0.targetEventID == second && $0.relation == "same_agent_reported" })
        XCTAssertFalse(context.links.contains { $0.targetEventID == other })
        XCTAssertTrue(context.links.contains { $0.strength == "candidate" }) // bare PID/reused PID is only a candidate
    }
    func testNetworkBurstDoesNotCrowdOutProtectionDecisions() throws {
        var timeline = WorkflowTimeline()
        let blocked = try XCTUnwrap(EngineObservation.append(security("blocked-1", at: 0), to: &timeline))
        var importer = NetworkWorkflowImporter()
        let events = (1...90).map { event($0) }
        importer.ingest(page(events), into: &timeline)
        importer.ingest(page(events, after: importer.cursor), into: &timeline)
        let context = WorkflowContext.build(from: timeline, sources: [.init("network", "active", "extension")], now: now.addingTimeInterval(100))
        XCTAssertLessThanOrEqual(context.events.count, 64)
        XCTAssertTrue(context.events.contains { $0.id == blocked })
        XCTAssertTrue(context.artifacts.isEmpty)
        XCTAssertGreaterThan(context.omittedEvents, 0)
        XCTAssertLessThanOrEqual(try context.exportData().count, 96 * 1024)
    }
    func testBudgetsMissingReferencesAndNetworkOnlyPrivacy() throws {
        var timeline = WorkflowTimeline()
        for _ in 0..<30 {
            timeline.append(kind: "app_context", collector: "synthetic", at: now,
                fields: Dictionary(uniqueKeysWithValues: (0..<20).map { ("field\($0)", WorkflowField(String(repeating: "a", count: 4097))) }), relatedEventIDs: [UUID().uuidString])
        }
        var importer = NetworkWorkflowImporter(); importer.ingest(page([event(0)]), into: &timeline)
        let context = WorkflowContext.build(from: timeline, sources: [.init("network", "disabled_or_unavailable", "not available")], now: now)
        XCTAssertLessThanOrEqual(try context.exportData().count, 96 * 1024)
        XCTAssertTrue(context.issues.contains("context_window_or_budget_omissions"))
        XCTAssertTrue(context.issues.contains("collector_coverage_incomplete"))
        let privateContext = WorkflowContext.build(from: timeline, sources: [], now: now, networkOnly: true)
        XCTAssertTrue(privateContext.events.allSatisfy { $0.collector == "NetworkExtension" })
        XCTAssertFalse(String(decoding: try privateContext.exportData(), as: UTF8.self).contains("field0"))
    }
    func testWireUsesISO8601AndReportsUpstreamTruncation() throws {
        var timeline = WorkflowTimeline()
        timeline.append(kind: "app_context", collector: "synthetic", at: now, provenance: "reported",
                        fields: ["command": WorkflowField("short clipped text", provenance: "reported", truncated: true)])
        let context = WorkflowContext.build(from: timeline, sources: [], now: now)
        let wire = try WireCodec.encode(id: "workflow", command: .workflowContext(context))
        let object = try JSONSerialization.jsonObject(with: wire) as! [String: Any]
        let payload = object["context"] as! [String: Any]
        XCTAssertNotNil(payload["generatedAt"] as? String)
        XCTAssertEqual(payload["enforcement"] as? String, "context_only_not_authorization")
        XCTAssertTrue(context.issues.contains("truncated_fields"))
    }
    func testDecisionNetworkHostMatchIsOnlyCandidateAndTimeBounded() {
        var timeline = WorkflowTimeline(), importer = NetworkWorkflowImporter()
        let decision = EngineObservation.append(security("script-1", subject: "left-pad@1.0.0 → example.com:443", at: 0), to: &timeline)!
        // A host that merely ends with the same text is a different host.
        let other = EngineObservation.append(security("script-2", agent: nil, subject: "left-pad@1.0.0 → notexample.com:443", at: 0), to: &timeline)!
        importer.ingest(page([event(2), event(20)]), into: &timeline)
        let context = WorkflowContext.build(from: timeline, sources: [], now: now.addingTimeInterval(21))
        let candidates = context.links.filter { $0.sourceEventID == decision }
        XCTAssertEqual(candidates.count, 1)
        XCTAssertEqual(candidates.first?.relation, "nearby_destination_context")
        XCTAssertEqual(candidates.first?.strength, "candidate")
        XCTAssertFalse(context.links.contains { $0.sourceEventID == other })
    }

    func testEngineDecisionEntersTheTimelineInTheContractShape() throws {
        var timeline = WorkflowTimeline()
        let id = try XCTUnwrap(EngineObservation.append(security("3f2a9c0d1b7e4a55", reason: String(repeating: "r", count: 700), at: 0), to: &timeline))
        XCTAssertEqual(id, "engine:3f2a9c0d1b7e4a55")
        // The same decision is polled every few seconds; it is one observation.
        XCTAssertNil(EngineObservation.append(security("3f2a9c0d1b7e4a55", at: 0), to: &timeline))
        // An id that could not be cited back safely is left out rather than rewritten.
        for bad in ["", "has space", "a/b", "é", String(repeating: "a", count: 65)] {
            XCTAssertNil(EngineObservation.append(security(bad, at: 0), to: &timeline), bad)
        }
        XCTAssertNotNil(EngineObservation.append(security("no-agent", agent: nil, at: 1), to: &timeline))
        XCTAssertEqual(timeline.events.count, 2)

        let context = WorkflowContext.build(from: timeline, sources: [.init("engine", "active", "decisions")], now: now.addingTimeInterval(2))
        let wire = try WireCodec.encode(id: "workflow", command: .workflowContext(context))
        let payload = try XCTUnwrap((JSONSerialization.jsonObject(with: wire) as? [String: Any])?["context"] as? [String: Any])
        // No observation has a UUID, so the context is named after the session.
        XCTAssertEqual(payload["contextID"] as? String, timeline.sessionID.uuidString)
        let events = try XCTUnwrap(payload["events"] as? [[String: Any]])
        let event = try XCTUnwrap(events.first)
        XCTAssertEqual(event["id"] as? String, "engine:3f2a9c0d1b7e4a55")
        XCTAssertEqual(event["kind"] as? String, "security_event"); XCTAssertEqual(event["collector"] as? String, "BoxCopEngine")
        XCTAssertEqual(event["phase"] as? String, "observed"); XCTAssertEqual(event["provenance"] as? String, "engine_record")
        XCTAssertEqual(event["availability"] as? String, "available"); XCTAssertEqual(event["sessionID"] as? String, timeline.sessionID.uuidString)
        XCTAssertEqual(event["relatedEventIDs"] as? [String], [])
        XCTAssertNil(event["pid"]); XCTAssertNil(event["bundleID"]); XCTAssertNil(event["windowTitle"])
        let fields = try XCTUnwrap(event["fields"] as? [String: [String: Any]])
        // Only what the contract allows: no command, package, host or rule ids.
        XCTAssertEqual(Set(fields.keys), ["layer", "outcome", "title", "reason", "subject", "agent"])
        XCTAssertEqual(fields["layer"]?["value"] as? String, "install_gate"); XCTAssertEqual(fields["outcome"]?["value"] as? String, "blocked")
        XCTAssertEqual(fields["title"]?["value"] as? String, "Blocked install of evil-pkg 1.2.3")
        XCTAssertEqual(fields["subject"]?["value"] as? String, "evil-pkg@1.2.3"); XCTAssertEqual(fields["agent"]?["value"] as? String, "claude")
        XCTAssertEqual((fields["reason"]?["value"] as? String)?.count, 600); XCTAssertEqual(fields["reason"]?["truncated"] as? Bool, true)
        XCTAssertEqual(fields["title"]?["provenance"] as? String, "engine_record"); XCTAssertEqual(fields["title"]?["truncated"] as? Bool, false)
        // A value the engine did not report is omitted, never sent as null.
        let second = try XCTUnwrap(events.last?["fields"] as? [String: [String: Any]])
        XCTAssertEqual(Set(second.keys), ["layer", "outcome", "title", "reason", "subject"])
        XCTAssertTrue(second.values.allSatisfy { $0["value"] is String })
    }
    func testFindingsMapBackToEventsRows() throws {
        var timeline = WorkflowTimeline(), importer = NetworkWorkflowImporter()
        let decision = try XCTUnwrap(EngineObservation.append(security("evt-install", at: 0), to: &timeline))
        let flow = event(1)
        importer.ingest(page([flow]), into: &timeline)
        var rows: [String: String] = [:]
        for event in timeline.events { if let row = EngineObservation.rowID(for: event) { rows[event.id] = row } }
        let connection = try XCTUnwrap(timeline.events.first { $0.kind == "network_connection" })
        // The collector health note is context for the model, not a row in Events.
        XCTAssertEqual(rows, [decision: "engine:evt-install", connection.id: "network:" + flow.id.uuidString])
        XCTAssertEqual(decision, FeedEvent(security("evt-install", at: 0)).id)

        typealias Finding = WorkflowJudgmentStatus.Finding
        let notes = EngineObservation.explanations([
            Finding(summary: "The agent asked for a release that is confirmed malware.", recommendation: "Check where the package name came from.",
                    eventIDs: [decision, connection.id]),
            Finding(summary: "The same process then tried a listed host.", recommendation: "", eventIDs: [connection.id, UUID().uuidString]),
            // A decision that has left the timeline map still lands on its row; anything else unknown is dropped.
            Finding(summary: "Earlier block.", recommendation: "Nothing to do.", eventIDs: ["engine:evt-older", "engine:not valid", "network:x"]),
            Finding(summary: " ", recommendation: "", eventIDs: [decision])
        ], rows: rows)
        XCTAssertEqual(notes, [
            "engine:evt-install": "The agent asked for a release that is confirmed malware. Check where the package name came from.",
            "network:" + flow.id.uuidString: "The agent asked for a release that is confirmed malware. Check where the package name came from. The same process then tried a listed host.",
            "engine:evt-older": "Earlier block. Nothing to do."])
        // The explanation reaches the row the detail panel shows.
        let feed = EventFeed.merge(security: [security("evt-install", at: 0)], network: [], findings: [], explanations: notes)
        XCTAssertEqual(feed.first?.explanation, "The agent asked for a release that is confirmed malware. Check where the package name came from.")
    }
}
