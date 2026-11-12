import XCTest
@testable import BoxCopCore

final class NetworkActivityTests: XCTestCase {
    private func event(_ host: String = "192.0.2.1") -> NetworkActivityEvent {
        .init(remoteAddress: host, remotePort: "443", localAddress: nil, localPort: nil,
              hostname: nil, hostnameSource: "unavailable", url: nil, transport: "tcp",
              socketFamily: 2, socketType: 1, socketProtocol: 6, flowType: "socket")
    }
    private func directory() throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        addTeardownBlock { try? FileManager.default.removeItem(at: url) }
        return url
    }
    func testHostnameProvenanceAndUnknownIdentitySurviveExport() throws {
        XCTAssertEqual(NetworkActivityEvent.destination(urlHost: "example.org", remoteHostname: "other.org").source, "flow_url")
        XCTAssertEqual(NetworkActivityEvent.destination(urlHost: nil, remoteHostname: "example.org").name, "example.org")
        XCTAssertNil(NetworkActivityEvent.destination(urlHost: nil, remoteHostname: nil).name)
        let decoded = try JSONDecoder().decode(NetworkActivityEvent.self, from: JSONEncoder().encode(event()))
        XCTAssertNil(decoded.process.pid)
        XCTAssertNil(decoded.hostname)
        XCTAssertEqual(decoded.remoteAddress, "192.0.2.1")
        XCTAssertEqual(decoded.decision, "observed_allowed")
    }
    func testJournalPersistsAcrossRestartAndRotatesWithinBound() throws {
        let dir = try directory(), limit = 2048
        let journal = try NetworkActivityJournal(directory: dir, limit: limit, encryption: try journalTestCipher())
        var last: NetworkActivityEvent!
        for _ in 0..<25 { last = event(); try journal.append(last) }
        let restored = try NetworkActivityJournal(directory: dir, limit: limit, encryption: try journalTestCipher()).events()
        XCTAssertEqual(restored.last?.id, last.id)
        XCTAssertGreaterThan(restored.count, 1)
        XCTAssertLessThan(restored.count, 25)
        for file in try FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil) {
            let values = try FileManager.default.attributesOfItem(atPath: file.path)
            XCTAssertLessThanOrEqual((values[.size] as! NSNumber).intValue, limit)
            XCTAssertEqual((values[.posixPermissions] as! NSNumber).intValue, 0o600)
        }
    }
    func testLegacyHistoryMigratesBeforeAppendAndRejectsWrongKey() throws {
        let dir = try directory(), first = event("private.example")
        let file = dir.appendingPathComponent("connections.jsonl")
        var legacy = try JSONEncoder().encode(first); legacy.append(10)
        try legacy.write(to: file)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        let journal = try NetworkActivityJournal(directory: dir, encryption: journalTestCipher())
        XCTAssertEqual(try journal.events().map(\.id), [first.id])
        let encrypted = try Data(contentsOf: file)
        XCTAssertFalse(String(decoding: encrypted, as: UTF8.self).contains("private.example"))
        XCTAssertThrowsError(try NetworkActivityJournal(directory: dir, encryption: journalTestCipher(byte: 8)))
        XCTAssertEqual(try Data(contentsOf: file), encrypted)
        try journal.append(event())
        XCTAssertEqual(try journal.events().count, 2)
    }
    func testJournalRejectsSymlinksAndPublicDirectory() throws {
        let dir = try directory(), victim = dir.appendingPathComponent("victim")
        try Data("unchanged".utf8).write(to: victim)
        try FileManager.default.createSymbolicLink(at: dir.appendingPathComponent("connections.jsonl"), withDestinationURL: victim)
        XCTAssertThrowsError(try NetworkActivityJournal(directory: dir, encryption: try journalTestCipher()))
        XCTAssertEqual(try String(contentsOf: victim), "unchanged")
        let publicDir = try directory()
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: publicDir.path)
        XCTAssertThrowsError(try NetworkActivityJournal(directory: publicDir, encryption: try journalTestCipher()))
    }
    func testJournalRejectsOversizedEventWithoutLosingHistory() throws {
        let dir = try directory(), journal = try NetworkActivityJournal(directory: dir, limit: 2048, encryption: try journalTestCipher())
        let first = event(); try journal.append(first)
        XCTAssertThrowsError(try journal.append(event(String(repeating: "x", count: 3000))))
        XCTAssertEqual(try journal.events().map(\.id), [first.id])
    }
}
