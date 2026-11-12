import XCTest
@testable import BoxCopCore

final class SecurityActivityTests: XCTestCase {
    func testFeedExcludesRoutineAndProspectiveDecisions() {
        var timeline = WorkflowTimeline()
        timeline.append(kind: "app_focus", collector: "test")
        timeline.append(kind: "policy_decision", collector: "test", fields: ["action": WorkflowField("block")])
        timeline.append(kind: "network_connection", collector: "test", fields: ["decision": WorkflowField("observed_allowed")])
        timeline.append(kind: "screen_assessment", collector: "test", fields: ["assessment": WorkflowField("no_rule_match_not_safe")])
        XCTAssertTrue(SecurityActivityItem.make(records: [], events: timeline.events).isEmpty)
    }

    func testBlocksRetainReasonsAndSortNewestFirst() {
        var timeline = WorkflowTimeline()
        timeline.append(kind: "network_connection", collector: "NetworkExtension", at: Date(timeIntervalSince1970: 10),
                        fields: ["decision": WorkflowField("blocked_threat_domain"), "threat_reason": WorkflowField("Known phishing domain"), "hostname": WorkflowField("example.test")])
        timeline.append(kind: "screen_share_preflight", collector: "test", availability: "share_held_unavailable", at: Date(timeIntervalSince1970: 20))
        let items = SecurityActivityItem.make(records: [], events: timeline.events)
        XCTAssertEqual(items.map(\.title), ["Screen share held", "Connection blocked"])
        XCTAssertEqual(items.last?.summary, "Known phishing domain")
        XCTAssertTrue(items.last?.detail.contains("example.test") == true)
    }
}
