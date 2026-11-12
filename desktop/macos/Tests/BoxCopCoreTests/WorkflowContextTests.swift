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
        let first = timeline.append(kind: "agent_instruction", collector: "agent.hook", at: now, provenance: "reported",
            fields: ["run_id": WorkflowField("run", provenance: "reported"), "hook_source": WorkflowField("claude", provenance: "reported")])
        let second = timeline.append(kind: "agent_tool_call", collector: "agent.hook", at: now.addingTimeInterval(3), provenance: "reported",
            fields: ["run_id": WorkflowField("run", provenance: "reported"), "hook_source": WorkflowField("claude", provenance: "reported")])
        let other = timeline.append(kind: "agent_tool_call", collector: "agent.hook", at: now.addingTimeInterval(4), provenance: "reported",
            fields: ["run_id": WorkflowField("run", provenance: "reported"), "hook_source": WorkflowField("cursor", provenance: "reported")])
        let context = WorkflowContext.build(from: timeline, sources: [], now: now.addingTimeInterval(5))
        XCTAssertEqual(context.links.filter { $0.relation == "same_kernel_process_instance" }.count, 1)
        XCTAssertTrue(context.links.contains { $0.sourceEventID == first && $0.targetEventID == second && $0.relation == "same_agent_run_reported" })
        XCTAssertFalse(context.links.contains { $0.targetEventID == other })
        XCTAssertTrue(context.links.contains { $0.strength == "candidate" }) // bare PID/reused PID is only a candidate
    }
    func testNetworkBurstKeepsOtherInputsAndArtifactReferencesWithoutReadingThem() throws {
        var timeline = WorkflowTimeline()
        let image = timeline.append(kind: "visual_context", collector: "ScreenCaptureKit.window", pid: 42, at: now,
            fields: ["capture_id": WorkflowField("image-1"), "artifact_path": WorkflowField("/does-not-exist/fake.png"),
                     "recognized_text": WorkflowField("Synthetic screen text", provenance: "derived")])
        let prompt = timeline.append(kind: "agent_instruction", collector: "agent.hook", at: now,
            provenance: "reported", fields: ["instruction": WorkflowField("Synthetic prompt", provenance: "reported")])
        var importer = NetworkWorkflowImporter()
        let events = (1...90).map { event($0) }
        importer.ingest(page(events), into: &timeline)
        importer.ingest(page(events, after: importer.cursor), into: &timeline)
        let context = WorkflowContext.build(from: timeline, sources: [.init("screen", "active", "consented")], now: now.addingTimeInterval(100))
        XCTAssertLessThanOrEqual(context.events.count, 64)
        XCTAssertTrue(context.events.contains { $0.id == image })
        XCTAssertTrue(context.events.contains { $0.id == prompt })
        XCTAssertEqual(context.artifacts.first?.localPath, "/does-not-exist/fake.png")
        XCTAssertGreaterThan(context.omittedEvents, 0)
        XCTAssertLessThanOrEqual(try context.exportData().count, 96 * 1024)
    }
    func testEmailReviewHistorySurvivesBrowserByteBudgetPressure() throws {
        var timeline = WorkflowTimeline()
        var evidence = Set<UUID>()
        for turn in 0..<3 {
            for kind in ["agent_instruction", "agent_tool_result"] {
                evidence.insert(timeline.append(kind: kind, collector: "agent.hook",
                    at: now.addingTimeInterval(Double(turn * 120)), provenance: "reported",
                    fields: ["run_id": WorkflowField("synthetic-run"), "hook_source": WorkflowField("test"),
                             "instruction": WorkflowField(String(repeating: "Synthetic revision. ", count: 20))]))
            }
        }
        evidence.insert(timeline.append(kind: "browser_email_draft", collector: "browser.extension",
            at: now.addingTimeInterval(300), fields: ["body_text": WorkflowField("Synthetic final email")]))
        for _ in 0..<40 {
            _ = timeline.append(kind: "browser_request", collector: "browser.extension",
                at: now.addingTimeInterval(301), fields: ["url": WorkflowField(String(repeating: "x", count: 3000))])
        }
        let context = WorkflowContext.build(from: timeline, sources: [], now: now.addingTimeInterval(302))
        XCTAssertTrue(evidence.isSubset(of: Set(context.events.map(\.id))))
        XCTAssertGreaterThan(context.omittedEvents, 0)
        XCTAssertLessThanOrEqual(try context.exportData().count, 96 * 1024)
    }
    func testBudgetsMissingReferencesAndNetworkOnlyPrivacy() throws {
        var timeline = WorkflowTimeline()
        for _ in 0..<30 {
            timeline.append(kind: "window_context", collector: "Accessibility", at: now,
                fields: Dictionary(uniqueKeysWithValues: (0..<20).map { ("field\($0)", WorkflowField(String(repeating: "a", count: 4097))) }), relatedEventIDs: [UUID()])
        }
        var importer = NetworkWorkflowImporter(); importer.ingest(page([event(0)]), into: &timeline)
        let context = WorkflowContext.build(from: timeline, sources: [.init("screen", "permission_missing", "not available")], now: now)
        XCTAssertLessThanOrEqual(try context.exportData().count, 96 * 1024)
        XCTAssertTrue(context.issues.contains("context_window_or_budget_omissions"))
        XCTAssertTrue(context.issues.contains("collector_coverage_incomplete"))
        let privateContext = WorkflowContext.build(from: timeline, sources: [], now: now, networkOnly: true)
        XCTAssertTrue(privateContext.events.allSatisfy { $0.collector == "NetworkExtension" })
        XCTAssertFalse(String(decoding: try privateContext.exportData(), as: UTF8.self).contains("field0"))
    }
    func testWireUsesISO8601AndReportsUpstreamTruncation() throws {
        var timeline = WorkflowTimeline()
        let adapter = try AdapterEvent.decode(Data(#"{"version":1,"kind":"agent_tool_call","fields":{"run_id":"run","arguments":"short clipped text","status":"arguments_truncated"}}"#.utf8))
        XCTAssertTrue(adapter.fields["arguments"]!.truncated)
        timeline.append(kind: adapter.kind, collector: adapter.collector, at: now, provenance: "reported", fields: adapter.fields)
        let context = WorkflowContext.build(from: timeline, sources: [], now: now)
        let wire = try WireCodec.encode(id: "workflow", command: .workflowContext(context))
        let object = try JSONSerialization.jsonObject(with: wire) as! [String: Any]
        let payload = object["context"] as! [String: Any]
        XCTAssertNotNil(payload["generatedAt"] as? String)
        XCTAssertEqual(payload["enforcement"] as? String, "context_only_not_authorization")
        XCTAssertTrue(context.issues.contains("truncated_fields"))
    }
    func testBrowserNetworkDomainMatchIsOnlyCandidateAndTimeBounded() {
        var timeline = WorkflowTimeline(), importer = NetworkWorkflowImporter()
        let browser = timeline.append(kind: "browser_request", collector: "browser.extension", at: now, provenance: "reported",
            fields: ["url": WorkflowField("https://example.com/upload", provenance: "reported")])
        importer.ingest(page([event(2), event(20)]), into: &timeline)
        let context = WorkflowContext.build(from: timeline, sources: [], now: now.addingTimeInterval(21))
        let candidates = context.links.filter { $0.sourceEventID == browser }
        XCTAssertEqual(candidates.count, 1)
        XCTAssertEqual(candidates.first?.relation, "nearby_destination_context")
        XCTAssertEqual(candidates.first?.strength, "candidate")
    }
}
