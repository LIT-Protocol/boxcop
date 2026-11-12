import XCTest
import BoxCopCore
@testable import BoxCop

private final class ReportProtocol: URLProtocol {
    static var handler: ((ReportProtocol) -> Void)?
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() { Self.handler?(self) }
    override func stopLoading() {}
    func respond(_ status: Int, body: String = "{\"accepted\":true}") {
        client?.urlProtocol(self, didReceive: HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: nil, headerFields: nil)!, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Data(body.utf8)); client?.urlProtocolDidFinishLoading(self)
    }
    func payload() -> [String: Any] {
        if let data = request.httpBody { return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] ?? [:] }
        guard let stream = request.httpBodyStream else { return [:] }
        stream.open(); defer { stream.close() }
        var data = Data(), buffer = [UInt8](repeating: 0, count: 1024)
        while stream.hasBytesAvailable {
            let n = stream.read(&buffer, maxLength: buffer.count); if n <= 0 { break }; data.append(buffer, count: n)
        }
        return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] ?? [:]
    }
}

@MainActor final class ProductSupportTests: XCTestCase {
    private func client() -> ProductReportClient {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [ReportProtocol.self]
        return ProductReportClient(session: URLSession(configuration: configuration))
    }
    private func settle(_ condition: @escaping () -> Bool) async {
        for _ in 0..<100 {
            if condition() { return }
            try? await Task.sleep(nanoseconds: 10_000_000)
        }
        XCTFail("State did not settle")
    }
    func testFeedbackRequiresExplicitSendKeepsTextAndIDOnFailureThenConfirmsReceipt() async throws {
        var ids: [String] = []
        ReportProtocol.handler = { request in
            XCTAssertEqual(request.request.url, ProductReportClient.endpoint)
            XCTAssertNil(request.request.value(forHTTPHeaderField: "Authorization"))
            XCTAssertNil(request.request.value(forHTTPHeaderField: "Cookie"))
            let payload = request.payload()
            ids.append(payload["report_id"] as! String)
            request.respond(ids.count == 1 ? 503 : 202)
        }
        defer { ReportProtocol.handler = nil }
        let draft = AlertFeedbackDraft(client: client()), build = ProductBuild(version: "0.1.0", build: "777")!
        draft.text = "This alert was unclear."
        XCTAssertTrue(ids.isEmpty)
        draft.send(build: build, category: .paste)
        await settle { !draft.sending }
        XCTAssertFalse(draft.sent); XCTAssertEqual(draft.text, "This alert was unclear.")
        XCTAssertTrue(draft.message?.contains("Couldn’t confirm") == true)
        draft.send(build: build, category: .paste)
        await settle { draft.sent }
        XCTAssertEqual(ids.count, 2); XCTAssertEqual(ids[0], ids[1])
        draft.send(build: build, category: .paste)
        XCTAssertEqual(ids.count, 2)
    }
    func testInvalidFeedbackNoRequestsAndCancellationCannotReportSuccess() async {
        let started = expectation(description: "request started")
        ReportProtocol.handler = { _ in started.fulfill() }
        defer { ReportProtocol.handler = nil }
        let draft = AlertFeedbackDraft(client: client()), build = ProductBuild(version: "0.1.0", build: "777")!
        draft.text = " \n "
        draft.send(build: build, category: .emailReview)
        XCTAssertFalse(draft.sending)
        draft.text = "Please make this clearer."
        draft.send(build: build, category: .emailReview)
        await fulfillment(of: [started], timeout: 2)
        draft.cancel()
        await settle { !draft.sending }
        XCTAssertFalse(draft.sent); XCTAssertNil(draft.message)
    }
    func testHTTPFailuresAndMalformedSuccessDoNotBecomeReceipts() async throws {
        let report = AlertFeedbackReport(build: ProductBuild(version: "0.1.0", build: "777")!, category: .paste, text: "Feedback")!
        let transport = client()
        for (status, body) in [(200, "{\"accepted\":true}"), (202, "{\"accepted\":false}"), (202, "not JSON"), (302, ""), (422, ""), (429, "")] {
            ReportProtocol.handler = { $0.respond(status, body: body) }
            do { try await transport.send(report); XCTFail("Accepted invalid receipt \(status)") } catch { }
        }
        ReportProtocol.handler = nil
    }
    func testCrashConsentPersistsAndOptOutCancelsInFlightAndClearsState() async throws {
        let suite = "BoxCop.SupportTests.\(UUID().uuidString)", defaults = UserDefaults(suiteName: suite)!
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { defaults.removePersistentDomain(forName: suite); try? FileManager.default.removeItem(at: directory); ReportProtocol.handler = nil }
        let started = expectation(description: "crash request started")
        ReportProtocol.handler = { _ in started.fulfill() }
        let support = ProductSupport(defaults: defaults, client: client(), reportDirectories: [directory])
        XCTAssertFalse(support.crashReportingEnabled)
        support.activate(); support.setCrashReporting(true); support.stop()
        // Place a crash strictly after the stored consent cutoff, then simulate reopening.
        try await Task.sleep(nanoseconds: 20_000_000)
        let formatter = DateFormatter(); formatter.locale = Locale(identifier: "en_US_POSIX"); formatter.dateFormat = "yyyy-MM-dd HH:mm:ss.SSSS Z"
        let fixtureURL = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("BoxCopCoreTests/Fixtures/product-crash.ips")
        let fixture = try String(contentsOf: fixtureURL, encoding: .utf8).replacingOccurrences(of: "2026-11-06 10:00:00.0000 -0800", with: formatter.string(from: Date()))
        try Data(fixture.utf8).write(to: directory.appendingPathComponent("BoxCop-test.ips"))
        let reopened = ProductSupport(defaults: defaults, client: client(), reportDirectories: [directory])
        XCTAssertTrue(reopened.crashReportingEnabled)
        reopened.activate()
        await fulfillment(of: [started], timeout: 3)
        reopened.setCrashReporting(false)
        XCTAssertFalse(reopened.crashReportingEnabled)
        XCTAssertFalse(defaults.dictionaryRepresentation().keys.contains { $0.hasPrefix("boxcop.support.") })
        await settle { reopened.crashStatus.isEmpty }
        XCTAssertFalse(ProductSupport(defaults: defaults, client: client(), reportDirectories: [directory]).crashReportingEnabled)
        reopened.stop()
    }
}
