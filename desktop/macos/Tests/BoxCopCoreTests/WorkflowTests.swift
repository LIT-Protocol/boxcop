import XCTest
@testable import BoxCopCore

final class WorkflowTests: XCTestCase {
    func testBoundedTimelineExportsGapsAndObservedProvenance() throws {
        var timeline = WorkflowTimeline(capacity: 2)
        for kind in ["app_launched", "app_focus", "app_terminated"] {
            timeline.append(kind: kind, collector: "NSWorkspace", bundleID: "com.apple.TextEdit", pid: 1)
        }
        XCTAssertEqual(timeline.events.map(\.sequence), [2, 3])
        XCTAssertEqual(timeline.dropped, 1)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: timeline.exportData()) as? [String: Any])
        XCTAssertEqual(object["droppedEvents"] as? Int, 1)
        XCTAssertEqual(object["synthetic"] as? Bool, false)
        let events = try XCTUnwrap(object["events"] as? [[String: Any]])
        XCTAssertEqual(events.first?["provenance"] as? String, "observed")
        XCTAssertNil(events.first?["content"])
    }
    func testClearDropsPrivateTitlesAndRotatesSession() throws {
        var timeline = WorkflowTimeline()
        let session = timeline.sessionID
        timeline.append(kind: "window_context", collector: "Accessibility", windowTitle: "private document")
        XCTAssertTrue(String(decoding: try timeline.exportData(), as: UTF8.self).contains("private document"))
        timeline.clear()
        XCTAssertNotEqual(timeline.sessionID, session)
        XCTAssertFalse(String(decoding: try timeline.exportData(), as: UTF8.self).contains("private document"))
        XCTAssertTrue(timeline.events.isEmpty)
    }
    func testUnavailableContextDoesNotBecomeEmptyTitleOrSuccess() {
        var timeline = WorkflowTimeline()
        timeline.append(kind: "window_context", collector: "Accessibility", availability: "accessibility_denied")
        XCTAssertNil(timeline.events.first?.windowTitle)
        XCTAssertEqual(timeline.events.first?.availability, "accessibility_denied")
        timeline.append(kind: "window_context", collector: "Accessibility", windowTitle: String(repeating: "x", count: 1000))
        XCTAssertEqual(timeline.events.last?.windowTitle?.count, 512)
    }
}
