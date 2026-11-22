import XCTest
@testable import BoxCopCore

final class EventFeedTests: XCTestCase {
    let now = Date(timeIntervalSince1970: 1_800_000_000)
    private func security(_ id: String, _ layer: SecurityEvent.Layer, _ outcome: SecurityEvent.Outcome, at offset: TimeInterval,
                          agent: String? = "claude", command: String? = nil, package: String? = nil, host: String? = nil,
                          title: String? = nil, reason: String? = nil, ecosystem: String? = nil, version: String? = nil, allowable: Bool = false) -> SecurityEvent {
        SecurityEvent(id: id, time: now.addingTimeInterval(offset), layer: layer, outcome: outcome, title: title ?? "Event \(id)",
                      reason: reason ?? "Reason \(id)", subject: package ?? host ?? "subject", agent: agent, command: command, package: package, host: host,
                      policyIDs: ["rule-\(id)"], ecosystem: ecosystem, version: version, allowable: allowable)
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
    private func finding(_ id: String) -> FindingItem {
        FindingItem(id: id, name: "node", version: "18.2.0", path: "/opt/homebrew/bin/node", advisories: ["CVE-2026-0001"],
                    guidance: "Update to a patched release.", fixedVersions: "18.20.4", checkedAt: now.addingTimeInterval(-3600))
    }

    func testMergeTakesEverySourceAndOnlyBlockedConnections() {
        let rows = EventFeed.merge(security: [security("a", .installGate, .blocked, at: -10, package: "evil-pkg"), security("w", .agentActions, .warned, at: -30)],
                                   network: [network(at: -5, blocked: true), network(at: -4, blocked: false)], findings: [finding("f1")])
        XCTAssertEqual(rows.count, 4)
        XCTAssertEqual(Set(rows.map(\.layer)), [.installGate, .outboundControl, .agentChecks, .machineHealth])
        XCTAssertEqual(rows.map(\.status), [.blocked, .blocked, .warned, .finding])
        XCTAssertEqual(rows.map(\.status.label), ["Blocked", "Blocked", "Warned", "Finding"])
    }

    func testRowsAreNewestFirstAndDuplicateIDsKeepOneRow() {
        let rows = EventFeed.merge(security: [security("old", .agentActions, .blocked, at: -100), security("new", .agentActions, .blocked, at: -1),
                                              security("new", .agentActions, .blocked, at: -2)],
                                   network: [network(at: -50, blocked: true)], findings: [])
        XCTAssertEqual(rows.count, 3)
        XCTAssertEqual(rows.first?.id, "engine:new")
        XCTAssertEqual(rows.last?.id, "engine:old")
        XCTAssertEqual(rows.map(\.time), rows.map(\.time).sorted(by: >))
    }

    func testFiltersByStatusLayerAndSearch() {
        let rows = EventFeed.merge(security: [security("pkg", .installGate, .blocked, at: -10, package: "evil-pkg"),
                                              security("warn", .agentActions, .warned, at: -11, command: "cat ~/.aws/credentials")],
                                   network: [network(at: -5, blocked: true)], findings: [finding("f1")])
        XCTAssertEqual(EventFilter.Kind.allCases.map(\.rawValue), ["All", "Blocked", "Findings"])
        XCTAssertEqual(EventFeed.filter(rows, EventFilter(kind: .all)).count, 4)
        XCTAssertEqual(Set(EventFeed.filter(rows, EventFilter(kind: .blocked)).map(\.id)), ["engine:pkg", "network:" + rows.first { $0.layer == .outboundControl }!.id.dropFirst(8)])
        XCTAssertEqual(EventFeed.filter(rows, EventFilter(kind: .findings)).map(\.id), ["finding:f1"])
        XCTAssertEqual(EventFeed.filter(rows, EventFilter(layer: .agentChecks)).map(\.id), ["engine:warn"])
        XCTAssertEqual(EventFeed.filter(rows, EventFilter(kind: .blocked, layer: .agentChecks)).count, 0)
        XCTAssertEqual(EventFeed.filter(rows, EventFilter(search: "EVIL")).map(\.id), ["engine:pkg"])
        XCTAssertEqual(EventFeed.filter(rows, EventFilter(search: "cursor")).map(\.layer), [.outboundControl])
        XCTAssertEqual(EventFeed.filter(rows, EventFilter(search: "  ")).count, 4)
    }

    func testActionsFollowTheKindOfEvent() {
        let contained = FeedEvent(security("c", .containment, .blocked, at: 0, command: "npm install", package: "left-pad", host: "collector.example"))
        XCTAssertEqual(contained.actions, [.allowForPackage(package: "left-pad", host: "collector.example"), .copyDetails])
        XCTAssertEqual(contained.chain, ["Claude Code", "npm install", "install script of left-pad"])
        XCTAssertEqual(FeedEvent(security("i", .installGate, .blocked, at: 0, package: "evil-pkg")).actions, [.copyDetails])
        XCTAssertEqual(FeedEvent(finding: finding("f")).actions, [.openHealth, .copyDetails])
        XCTAssertEqual(FeedEvent(network: network(at: 0, blocked: true))?.actions, [.copyDetails])
        XCTAssertNil(FeedEvent(network: network(at: 0, blocked: false)))
    }

    func testOnlyAReportedReleaseTheEngineMarksAllowableCanBeAllowed() {
        let release = PackageRelease(ecosystem: "npm", package: "left-pad", version: "1.0.1")
        let reported = FeedEvent(security("r", .installGate, .blocked, at: 0, package: "left-pad", title: "Blocked install of left-pad 1.0.1 (reported as malware)",
                                          reason: "Two sources list this release.", ecosystem: "npm", version: "1.0.1", allowable: true))
        XCTAssertEqual(reported.actions, [.allowRelease(release), .copyDetails])
        XCTAssertEqual(FeedEvent.Action.allowRelease(release).title, "Allow this release")
        XCTAssertEqual(reported.status.label, "Blocked")
        XCTAssertEqual(reported.reason, "Reported as malware, not yet confirmed. Two sources list this release.")
        XCTAssertEqual(release.display, "left-pad@1.0.1")
        XCTAssertEqual(PackageRelease(ecosystem: "PyPI", package: "requests", version: "2.0.0").display, "requests==2.0.0")

        // The engine's own wording is kept when it already says so.
        let worded = FeedEvent(security("w", .installGate, .blocked, at: 0, package: "left-pad", title: "Blocked install of left-pad 1.0.1 (reported as malware)",
                                        reason: "This release is reported as malware by ghsa, but not yet confirmed.", ecosystem: "npm", version: "1.0.1", allowable: true))
        XCTAssertEqual(worded.reason, "This release is reported as malware by ghsa, but not yet confirmed.")

        // Already allowed: still labelled as the reported tier, but there is nothing left to allow.
        let allowed = FeedEvent(security("a", .installGate, .blocked, at: 0, package: "left-pad", title: "Blocked install of left-pad 1.0.1 (reported as malware)",
                                         reason: "", ecosystem: "npm", version: "1.0.1"))
        XCTAssertEqual(allowed.actions, [.copyDetails]); XCTAssertEqual(allowed.release, release)
        XCTAssertEqual(allowed.reason, "Reported as malware, not yet confirmed.")

        // Confirmed malware, a whole-package refusal, an unknown ecosystem and other layers never offer it, whatever `allowable` says.
        let confirmed = FeedEvent(security("c", .installGate, .blocked, at: 0, package: "evil", ecosystem: "npm", version: "1.0.0"))
        XCTAssertEqual(confirmed.actions, [.copyDetails]); XCTAssertEqual(confirmed.reason, "Reason c")
        XCTAssertEqual(FeedEvent(security("n", .installGate, .blocked, at: 0, package: "evil", ecosystem: "npm", allowable: true)).actions, [.copyDetails])
        XCTAssertEqual(FeedEvent(security("e", .installGate, .blocked, at: 0, package: "evil", ecosystem: "cargo", version: "1.0.0", allowable: true)).actions, [.copyDetails])
        XCTAssertEqual(FeedEvent(security("x", .agentActions, .blocked, at: 0, package: "evil", ecosystem: "npm", version: "1.0.0", allowable: true)).actions, [.copyDetails])
        XCTAssertEqual(FeedEvent(security("o", .installGate, .warned, at: 0, package: "evil", ecosystem: "npm", version: "1.0.0", allowable: true)).actions, [.copyDetails])
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
                                   network: [], findings: [], explanations: ["engine:pkg": "The model's view."])
        XCTAssertEqual(rows[0].explanation, "The model's view.")
        let text = rows[0].detailsText
        for expected in ["What happened: Event pkg", "Status: Blocked", "Layer: Install gate", "Why: Reason pkg", "Started by: Claude Code", "Command: npm install evil-pkg",
                         "Rules: rule-pkg", "Local model: The model's view.", "Reference: engine:pkg"] {
            XCTAssertTrue(text.contains(expected), expected)
        }
    }
}
