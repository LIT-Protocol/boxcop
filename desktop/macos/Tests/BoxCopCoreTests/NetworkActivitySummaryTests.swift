import XCTest
@testable import BoxCopCore

final class NetworkActivitySummaryTests: XCTestCase {
    private let now = Date()
    private func event(host: String? = "Example.com.", daysAgo: Int = 0, process: String = "/usr/bin/curl", app: String? = "/Applications/Terminal.app/Contents/MacOS/Terminal") -> NetworkActivityEvent {
        var event = NetworkActivityEvent(timestamp: Calendar.current.date(byAdding: .day, value: -daysAgo, to: now)!,
            remoteAddress: "192.0.2.1", remotePort: "443", localAddress: nil, localPort: nil,
            hostname: host, hostnameSource: host == nil ? "unavailable" : "flow_url", url: nil,
            transport: "tcp", socketFamily: 2, socketType: 1, socketProtocol: 6, flowType: "socket")
        event.process.executable = process
        event.responsibleApp.executable = app
        return event
    }
    private func directory() throws -> URL {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        return dir
    }
    func testAggregationPreservesAppProcessAndHostnameProvenance() {
        var summary = NetworkActivitySummary(since: now)
        summary.record(event(), now: now)
        summary.record(event(host: "example.com"), now: now)
        summary.record(event(host: nil), now: now)
        summary.record(event(process: "/usr/bin/python3"), now: now)
        XCTAssertEqual(summary.rows.count, 3)
        XCTAssertEqual(summary.rows.first?.attempts, 2)
        XCTAssertEqual(summary.rows.first?.destination, "example.com")
        XCTAssertEqual(summary.rows.first?.appName, "Terminal")
        XCTAssertEqual(summary.rows.first?.processName, "curl")
        XCTAssertEqual(summary.rows.filter { !$0.isDomain }.first?.destination, "192.0.2.1")
    }
    func testBlockedSummaryUsesMatchedHostnameAndReason() {
        var summary = NetworkActivitySummary(since: now)
        let threat = NetworkThreatMatch(hostname: "blocked.example", source: "test", revision: "1", reason: "Test reason")
        let blocked = NetworkActivityEvent(timestamp: now, remoteAddress: "192.0.2.1", remotePort: "443",
            localAddress: nil, localPort: nil, hostname: "other.example", hostnameSource: "flow_url", url: nil,
            transport: "tcp", socketFamily: 2, socketType: 1, socketProtocol: 6, flowType: "socket", threat: threat)
        summary.record(blocked, now: now)
        XCTAssertEqual(summary.rows.first?.blocked, 1)
        XCTAssertEqual(summary.rows.first?.destination, "blocked.example")
        XCTAssertEqual(summary.rows.first?.blockedReason, "Test reason")
    }
    func testSevenCalendarDaysAndUnknownAttribution() {
        var summary = NetworkActivitySummary(since: now)
        summary.record(event(daysAgo: 6), now: now)
        summary.record(event(daysAgo: 7), now: now)
        var unknown = event(app: nil)
        unknown.process = .init()
        summary.record(unknown, now: now)
        XCTAssertEqual(summary.rows.count, 2)
        XCTAssertEqual(summary.rows.last?.app, "Unknown process")
        summary.prune(now: Calendar.current.date(byAdding: .day, value: 7, to: now)!)
        XCTAssertTrue(summary.rows.isEmpty)
    }
    func testSummarySurvivesRawRotationAndRestart() throws {
        let dir = try directory()
        let store = try NetworkSummaryStore(directory: dir, encryption: try journalTestCipher())
        XCTAssertNil(try store.load())
        let journal = try NetworkActivityJournal(directory: dir, limit: 2048, encryption: try journalTestCipher())
        var summary = NetworkActivitySummary(since: now)
        for _ in 0..<50 {
            let event = event()
            summary.record(event, now: now)
            try journal.append(event)
        }
        try store.save(summary)
        let loaded = try XCTUnwrap(NetworkSummaryStore(directory: dir, encryption: try journalTestCipher()).load())
        XCTAssertEqual(loaded.rows.first?.attempts, 50)
        XCTAssertLessThan(try journal.events().count, 50)
        let attributes = try FileManager.default.attributesOfItem(atPath: dir.appendingPathComponent("network-summary.json").path)
        XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o600)
    }
    func testCapacityReportsLossButExistingCountersKeepUpdating() {
        var summary = NetworkActivitySummary(since: now)
        for i in 0...NetworkActivitySummary.capacity {
            summary.record(event(host: "host\(i).example.com"), now: now)
        }
        XCTAssertEqual(summary.rows.count, NetworkActivitySummary.capacity)
        XCTAssertEqual(summary.omitted, 1)
        summary.record(event(host: "host0.example.com"), now: now)
        XCTAssertEqual(summary.rows.first?.attempts, 2)
    }
    func testRejectsSymlinkAndCorruptCheckpoint() throws {
        let dir = try directory(), victim = dir.appendingPathComponent("victim")
        try Data("unchanged".utf8).write(to: victim)
        let path = dir.appendingPathComponent("network-summary.json")
        try FileManager.default.createSymbolicLink(at: path, withDestinationURL: victim)
        let store = try NetworkSummaryStore(directory: dir, encryption: try journalTestCipher())
        XCTAssertThrowsError(try store.load())
        // Atomic replacement cannot follow and overwrite the link target.
        try store.save(NetworkActivitySummary())
        XCTAssertEqual(try String(contentsOf: victim), "unchanged")
        try Data("invalid".utf8).write(to: path)
        XCTAssertThrowsError(try store.load())
    }
}
