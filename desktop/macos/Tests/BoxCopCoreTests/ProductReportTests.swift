import XCTest
@testable import BoxCopCore

final class ProductReportTests: XCTestCase {
    private let now = ISO8601DateFormatter().date(from: "2026-11-06T18:01:00Z")!
    private var since: Date { now.addingTimeInterval(-120) }
    private func fixture(_ name: String) throws -> Data {
        try Data(contentsOf: Bundle.module.url(forResource: name, withExtension: nil, subdirectory: "Fixtures")!)
    }
    private func changed(_ key: String, _ value: Any) throws -> Data {
        let bytes = try fixture("product-crash.ips"), newline = bytes.firstIndex(of: 10)!
        var body = try JSONSerialization.jsonObject(with: bytes[bytes.index(after: newline)...]) as! [String: Any]
        body[key] = value
        return Data(bytes[...newline]) + (try JSONSerialization.data(withJSONObject: body))
    }
    func testCrashProjectionMatchesServerFixtureAndExcludesAllPrivateCanaries() throws {
        let projected = try XCTUnwrap(CrashReport.project(fixture("product-crash.ips"), since: since, now: now))
        let encoded = try JSONEncoder().encode(projected.report)
        let expected = try JSONSerialization.jsonObject(with: fixture("product-reports.json")) as! [NSDictionary]
        XCTAssertEqual(try JSONSerialization.jsonObject(with: encoded) as? NSDictionary, expected[0])
        let text = String(decoding: encoded, as: UTF8.self)
        for forbidden in ["PRIVATE", "/Users/", "captureTime", "crashReporterKey", "timestamp", "pid", "symbol", "asi", "procPath"] {
            XCTAssertFalse(text.contains(forbidden), forbidden)
        }
    }
    func testFeedbackMatchesServerFixtureAndValidatesUTF8RatherThanCharacters() throws {
        let expected = try JSONSerialization.jsonObject(with: fixture("product-reports.json")) as! [NSDictionary]
        let report = try XCTUnwrap(AlertFeedbackReport(id: UUID(uuidString: expected[1]["report_id"] as! String)!,
            build: ProductBuild(version: "0.1.0", build: "777")!, category: .paste, text: expected[1]["text"] as! String))
        XCTAssertEqual(try JSONSerialization.jsonObject(with: JSONEncoder().encode(report)) as? NSDictionary, expected[1])
        XCTAssertFalse(AlertFeedbackReport.validText(" \n\t"))
        XCTAssertFalse(AlertFeedbackReport.validText("bad\0text"))
        XCTAssertTrue(AlertFeedbackReport.validText(String(repeating: "😀", count: 1000)))
        XCTAssertFalse(AlertFeedbackReport.validText(String(repeating: "😀", count: 1001)))
        XCTAssertTrue(AlertFeedbackReport.validText("Exact text\nincluding <script>markup</script> stays text."))
        XCTAssertNil(ProductBuild(version: "private/path", build: "1"))
    }
    func testOnlyRecentFatalBoxCopCrashesAfterConsentAreEligible() throws {
        let bytes = try fixture("product-crash.ips")
        XCTAssertNil(CrashReport.project(bytes, since: now, now: now))
        XCTAssertNil(CrashReport.project(bytes, since: since, now: now.addingTimeInterval(8 * 86400)))
        XCTAssertNil(CrashReport.project(bytes, since: since, now: since))
        for flag in ["isSimulated", "isNonFatal"] {
            XCTAssertNil(CrashReport.project(try changed(flag, true), since: since, now: now))
            XCTAssertNil(CrashReport.project(try changed(flag, "1"), since: since, now: now))
        }
        XCTAssertNil(CrashReport.project(try changed("procName", "AnotherApp"), since: since, now: now))
        XCTAssertNil(CrashReport.project(try changed("bundleInfo", ["CFBundleIdentifier": "other", "CFBundleShortVersionString": "0.1.0", "CFBundleVersion": "777"]), since: since, now: now))
        XCTAssertNil(CrashReport.project(try changed("faultingThread", -1), since: since, now: now))
        XCTAssertNil(CrashReport.project(try changed("faultingThread", 20), since: since, now: now))
        XCTAssertNil(CrashReport.project(try changed("osVersion", ["train": "macOS PRIVATE-OS"]), since: since, now: now))
        XCTAssertNil(CrashReport.project(Data("bad report".utf8), since: since, now: now))
        XCTAssertNil(CrashReport.project(Data(repeating: 32, count: CrashReport.maximumFileBytes + 1), since: since, now: now))
    }
    func testUnknownExceptionMessagesAndBadFramesCannotBecomeArbitraryUploadFields() throws {
        let unknown = try XCTUnwrap(CrashReport.project(changed("exception", ["type": "PRIVATE-TYPE", "signal": "PRIVATE-SIGNAL"]), since: since, now: now))
        XCTAssertEqual(unknown.report.exception, "UNKNOWN"); XCTAssertEqual(unknown.report.signal, "UNKNOWN")
        let frames: [[String: Any]] = [["imageIndex": -1, "imageOffset": 10], ["imageIndex": 20, "imageOffset": 10],
                                      ["imageIndex": 0, "imageOffset": UInt64.max], ["imageIndex": 0, "imageOffset": 15]]
        let projected = try XCTUnwrap(CrashReport.project(changed("threads", [["frames": frames]]), since: since, now: now))
        XCTAssertEqual(projected.report.frames.count, 1); XCTAssertEqual(projected.report.frames[0].image_offset, 15)
        let capped = try XCTUnwrap(CrashReport.project(changed("threads", [["frames": Array(repeating: frames[3], count: 100)]]), since: since, now: now))
        XCTAssertEqual(capped.report.frames.count, 64)
    }
    func testConsentRestartRetryAndOptOutDoNotBackfillOrDuplicate() throws {
        let candidate = try XCTUnwrap(CrashReport.project(fixture("product-crash.ips"), since: since, now: now))
        var state = CrashReportingState()
        XCTAssertFalse(state.shouldSend(candidate))
        state.setEnabled(true, now: since)
        XCTAssertTrue(state.shouldSend(candidate)) // An upload failure leaves it eligible.
        state.acknowledge(candidate, now: now)
        state = try JSONDecoder().decode(CrashReportingState.self, from: JSONEncoder().encode(state))
        XCTAssertFalse(state.shouldSend(candidate))
        var aged = state
        aged.prune(now: now.addingTimeInterval(8 * 86400))
        XCTAssertFalse(String(decoding: try JSONEncoder().encode(aged), as: UTF8.self).contains(candidate.report.report_id.uuidString))
        state.setEnabled(false, now: now)
        XCTAssertNil(state.enabledSince)
        XCTAssertFalse(String(decoding: try JSONEncoder().encode(state), as: UTF8.self).contains(candidate.report.report_id.uuidString))
        state.setEnabled(true, now: now)
        XCTAssertFalse(state.shouldSend(candidate))
    }
    func testScannerRejectsSymlinksOtherAppsAndOversizedFilesWithoutChangingSource() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let bytes = try fixture("product-crash.ips")
        let source = directory.appendingPathComponent("BoxCop-fixture.ips")
        try bytes.write(to: source)
        try bytes.write(to: directory.appendingPathComponent("OtherApp-fixture.ips"))
        try FileManager.default.createSymbolicLink(at: directory.appendingPathComponent("BoxCop-link.ips"), withDestinationURL: source)
        try Data(repeating: 0, count: CrashReport.maximumFileBytes + 1).write(to: directory.appendingPathComponent("BoxCop-big.ips"))
        var state = CrashReportingState()
        XCTAssertTrue(CrashReport.candidates(in: [directory], state: state, now: now).isEmpty)
        state.setEnabled(true, now: since)
        let reports = CrashReport.candidates(in: [directory], state: state, now: now)
        XCTAssertEqual(reports.count, 1)
        state.acknowledge(try XCTUnwrap(reports.first), now: now)
        XCTAssertTrue(CrashReport.candidates(in: [directory], state: state, now: now).isEmpty)
        XCTAssertEqual(try Data(contentsOf: source), bytes)
    }
}
