import XCTest
@testable import BoxCopCore

final class EventFeedTests: XCTestCase {
    let now = Date(timeIntervalSince1970: 1_800_000_000)
    private func security(_ id: String, _ layer: SecurityEvent.Layer, _ outcome: SecurityEvent.Outcome, at offset: TimeInterval,
                          agent: String? = "claude", command: String? = nil, package: String? = nil, host: String? = nil) -> SecurityEvent {
        SecurityEvent(id: id, time: now.addingTimeInterval(offset), layer: layer, outcome: outcome, title: "Event \(id)",
                      reason: "Reason \(id)", subject: package ?? host ?? "subject", agent: agent, command: command, package: package, host: host,
                      policyIDs: ["rule-\(id)"])
    }
    private func network(at offset: TimeInterval, blocked: Bool) -> NetworkActivityEvent {
        let threat = blocked ? NetworkThreatMatch(hostname: "bad.example", source: "Threat list", revision: "r1", reason: "listed") : nil
        var event = NetworkActivityEvent(timestamp: now.addingTimeInterval(offset), remoteAddress: "192.0.2.9", remotePort: "443", localAddress: nil,
                                         localPort: nil, hostname: "bad.example", hostnameSource: "flow_remote_hostname", url: nil, transport: "tcp",
                                         socketFamily: 2, socketType: 1, socketProtocol: 6, flowType: "socket", threat: threat)
        event.process.executable = "/usr/bin/curl"; event.process.signingIdentifier = "com.apple.curl"; event.process.teamIdentifier = nil
        event.process.ancestors = [NetworkProcessAncestor(pid: 20, executable: "/bin/zsh"), NetworkProcessAncestor(pid: 10, executable: "/Applications/Cursor.app/Contents/MacOS/Cursor")]
        event.responsibleApp.executable = "/Applications/Cursor.app/Contents/MacOS/Cursor"
        return event
    }
    private func approval(_ id: String, status: String = "pending", created: TimeInterval, expires: TimeInterval = 600) -> ApprovalItem {
        ApprovalItem(id: id, application: "codex", reasons: ["Review external communications"], command: "gog send --to team@example.com",
                     status: status, created: now.addingTimeInterval(created), expires: now.addingTimeInterval(expires))
    }
    private func finding(_ id: String) -> FindingItem {
        FindingItem(id: id, name: "node", version: "18.2.0", path: "/opt/homebrew/bin/node", advisories: ["CVE-2026-0001"],
                    guidance: "Update to a patched release.", fixedVersions: "18.20.4", checkedAt: now.addingTimeInterval(-3600))
    }

    func testMergeTakesEverySourceAndOnlyBlockedConnections() {
        let rows = EventFeed.merge(security: [security("a", .installGate, .blocked, at: -10, package: "evil-pkg")],
                                   network: [network(at: -5, blocked: true), network(at: -4, blocked: false)],
                                   approvals: [approval("q1", created: -30)], findings: [finding("f1")], now: now)
        XCTAssertEqual(rows.count, 4)
        XCTAssertEqual(Set(rows.map(\.layer)), [.installGate, .outboundControl, .agentChecks, .machineHealth])
        XCTAssertEqual(rows.map(\.status), [.held, .blocked, .blocked, .finding])
    }

    func testPendingApprovalsArePinnedThenNewestFirst() {
        let rows = EventFeed.merge(security: [security("old", .agentActions, .blocked, at: -100), security("new", .agentActions, .blocked, at: -1)],
                                   network: [network(at: -50, blocked: true)],
                                   approvals: [approval("older", created: -500), approval("newer", created: -400), approval("done", status: "approved", created: -20)],
                                   findings: [], now: now)
        XCTAssertEqual(rows.prefix(2).map(\.id), ["approval:newer", "approval:older"])
        XCTAssertTrue(rows.prefix(2).allSatisfy(\.pinned))
        XCTAssertEqual(rows.dropFirst(2).map(\.id).first, "engine:new")
        XCTAssertEqual(Array(rows.dropFirst(2).map(\.time)), rows.dropFirst(2).map(\.time).sorted(by: >))
        XCTAssertEqual(rows.first { $0.id == "approval:done" }?.status, .approved)
        XCTAssertNil(rows.first { $0.id == "approval:done" }?.approvalID)
    }

    func testExpiredApprovalIsNotPinnedAndEngineDuplicateOfAnApprovalIsDropped() {
        let rows = EventFeed.merge(security: [security("q1", .agentActions, .held, at: -30), security("other", .agentActions, .held, at: -31),
                                              security("other", .agentActions, .held, at: -32)],
                                   network: [], approvals: [approval("q1", created: -30), approval("late", created: -900, expires: -1)], findings: [], now: now)
        XCTAssertEqual(rows.map(\.id), ["approval:q1", "engine:other", "approval:late"])
        XCTAssertEqual(rows.last?.status, .rejected)
        XCTAssertFalse(rows.last?.pinned ?? true)
    }

    func testFiltersByStatusLayerAndSearch() {
        let rows = EventFeed.merge(security: [security("pkg", .installGate, .blocked, at: -10, package: "evil-pkg"),
                                              security("warn", .agentActions, .warned, at: -11, command: "cat ~/.aws/credentials")],
                                   network: [network(at: -5, blocked: true)], approvals: [approval("q1", created: -30)], findings: [finding("f1")], now: now)
        XCTAssertEqual(EventFeed.filter(rows, EventFilter(kind: .all)).count, 5)
        XCTAssertEqual(Set(EventFeed.filter(rows, EventFilter(kind: .blocked)).map(\.id)), ["engine:pkg", "network:" + rows.first { $0.layer == .outboundControl }!.id.dropFirst(8)])
        XCTAssertEqual(EventFeed.filter(rows, EventFilter(kind: .held)).map(\.id), ["approval:q1"])
        XCTAssertEqual(EventFeed.filter(rows, EventFilter(kind: .findings)).map(\.id), ["finding:f1"])
        XCTAssertEqual(EventFeed.filter(rows, EventFilter(layer: .agentChecks)).map(\.id), ["approval:q1", "engine:warn"])
        XCTAssertEqual(EventFeed.filter(rows, EventFilter(kind: .blocked, layer: .agentChecks)).count, 0)
        XCTAssertEqual(EventFeed.filter(rows, EventFilter(search: "EVIL")).map(\.id), ["engine:pkg"])
        XCTAssertEqual(EventFeed.filter(rows, EventFilter(search: "cursor")).map(\.layer), [.outboundControl])
        XCTAssertEqual(EventFeed.filter(rows, EventFilter(search: "  ")).count, 5)
    }

    func testActionsFollowTheKindOfEvent() {
        let contained = FeedEvent(security("c", .containment, .blocked, at: 0, command: "npm install", package: "left-pad", host: "collector.example"))
        XCTAssertEqual(contained.actions, [.allowForPackage(package: "left-pad", host: "collector.example"), .copyDetails])
        XCTAssertEqual(contained.chain, ["Claude Code", "npm install", "install script of left-pad"])
        XCTAssertEqual(FeedEvent(security("i", .installGate, .blocked, at: 0, package: "evil-pkg")).actions, [.copyDetails])
        XCTAssertEqual(FeedEvent(approval: approval("q", created: 0), now: now).actions, [.approve, .reject, .copyDetails])
        XCTAssertEqual(FeedEvent(approval: approval("q", status: "rejected", created: 0), now: now).actions, [.copyDetails])
        XCTAssertEqual(FeedEvent(finding: finding("f")).actions, [.openHealth, .copyDetails])
        XCTAssertEqual(FeedEvent(network: network(at: 0, blocked: true))?.actions, [.copyDetails])
        XCTAssertNil(FeedEvent(network: network(at: 0, blocked: false)))
    }

    func testNetworkRowNamesTheAppProcessChainAndSigningIdentity() throws {
        let row = try XCTUnwrap(FeedEvent(network: network(at: 0, blocked: true)))
        XCTAssertEqual(row.title, "Blocked connection to bad.example")
        XCTAssertEqual(row.subject, "bad.example:443")
        XCTAssertEqual(row.source, "Cursor")
        XCTAssertEqual(row.chain, ["Cursor", "zsh", "curl"])
        XCTAssertEqual(row.signing, "com.apple.curl")
    }

    func testExplanationsAttachByRowIDAndCopyTextStaysWithinTheRow() {
        let rows = EventFeed.merge(security: [security("pkg", .installGate, .blocked, at: -10, command: "npm install evil-pkg", package: "evil-pkg")],
                                   network: [], approvals: [], findings: [], explanations: ["engine:pkg": "The model's view."], now: now)
        XCTAssertEqual(rows[0].explanation, "The model's view.")
        let text = rows[0].detailsText
        for expected in ["What happened: Event pkg", "Status: Blocked", "Layer: Install gate", "Why: Reason pkg", "Started by: Claude Code -> npm install evil-pkg",
                         "Rules: rule-pkg", "Local model: The model's view.", "Reference: engine:pkg"] {
            XCTAssertTrue(text.contains(expected), expected)
        }
    }
}
