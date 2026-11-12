import XCTest
#if canImport(Security)
import Security
#endif
@testable import BoxCopCore

func journalTestCipher(purpose: String = "fixture", byte: UInt8 = 7) throws -> JournalEncryption {
#if canImport(CryptoKit)
    return JournalEncryption(purpose: purpose, keyProvider: { _ in Data(repeating: byte, count: 32) })
#else
    throw XCTSkip("Encrypted journal persistence requires macOS CryptoKit and Keychain")
#endif
}

final class JournalEncryptionTests: XCTestCase {
    func testRandomNonceRoundTripWrongKeyTamperingAndPurposeBinding() throws {
        let cipher = try journalTestCipher(), plaintext = Data("private selected text".utf8)
        let a = try cipher.seal(plaintext), b = try cipher.seal(plaintext)
        XCTAssertNotEqual(a, b)
        XCTAssertFalse(String(decoding: a, as: UTF8.self).contains("private selected text"))
        XCTAssertEqual(try cipher.open(a), plaintext)
        XCTAssertThrowsError(try journalTestCipher(byte: 8).open(a))
        XCTAssertThrowsError(try journalTestCipher(purpose: "other").open(a))
        var tampered = a; tampered[tampered.count - 5] = tampered[tampered.count - 5] == 65 ? 66 : 65
        XCTAssertThrowsError(try cipher.open(tampered))
        XCTAssertThrowsError(try cipher.open(plaintext))
    }
    func testMigrationIsPrivateIdempotentAndPreservesTruncatedTail() throws {
        let cipher = try journalTestCipher()
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("legacy.jsonl")
        try Data("{\"secret\":1}\npartial".utf8).write(to: file)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        try cipher.migrate(file, maximumBytes: 1024)
        let migrated = try Data(contentsOf: file)
        XCTAssertFalse(String(decoding: migrated, as: UTF8.self).contains("secret"))
        XCTAssertNotEqual(migrated.last, 10)
        let rows = try migrated.split(separator: 10).map { try cipher.open(Data($0)) }
        XCTAssertEqual(rows, [Data("{\"secret\":1}".utf8), Data("partial".utf8)])
        try cipher.migrate(file, maximumBytes: 1024)
        XCTAssertEqual(try Data(contentsOf: file), migrated)
        XCTAssertThrowsError(try journalTestCipher(byte: 8).migrate(file, maximumBytes: 1024))
        XCTAssertEqual(try Data(contentsOf: file), migrated)
        XCTAssertEqual((try FileManager.default.attributesOfItem(atPath: file.path)[.posixPermissions] as? NSNumber)?.intValue, 0o600)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: dir.path), ["legacy.jsonl"])
    }
    func testUnavailableKeyNeverFallsBackToPlaintextOrCreatesOnRead() async throws {
        _ = try journalTestCipher()
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let unavailable = JournalEncryption(purpose: "fixture", keyProvider: { _ in throw JournalEncryption.Failure.unavailable })
        let journal = try WorkflowJournal(directory: dir, encryption: unavailable)
        var timeline = WorkflowTimeline(); timeline.onAppend = { journal.append($0) }
        timeline.append(kind: "private-event", collector: "fixture")
        await journal.flush()
        XCTAssertTrue(journal.state().failed)
        XCTAssertEqual(journal.state().written, 0)
        XCTAssertEqual(journal.state().dropped, 1)
        XCTAssertFalse(try FileManager.default.contentsOfDirectory(atPath: dir.path).contains { $0.hasSuffix(".jsonl") })
        let record = try journalTestCipher().seal(Data("secret".utf8))
        let reader = JournalEncryption(purpose: "fixture", keyProvider: { create in
            XCTAssertFalse(create); throw JournalEncryption.Failure.unavailable
        })
        XCTAssertThrowsError(try reader.open(record))
    }
    func testExportAuthenticatesBeforeWritingAndPreservesReplayHealth() async throws {
        let cipher = try journalTestCipher()
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let source = root.appendingPathComponent("source"), output = root.appendingPathComponent("export")
        defer { try? FileManager.default.removeItem(at: root) }
        let journal = try WorkflowJournal(directory: source, encryption: cipher)
        var timeline = WorkflowTimeline(); timeline.onAppend = { journal.append($0) }
        timeline.append(kind: "security_event", collector: "fixture", fields: ["text": WorkflowField("private-text")])
        await journal.flush()
        try JournalExport.run(purpose: "workflow", source: source, destination: output, encryption: cipher)
        let exported = try FileManager.default.contentsOfDirectory(at: output, includingPropertiesForKeys: nil)
        let row = try Data(contentsOf: XCTUnwrap(exported.first { $0.pathExtension == "jsonl" }))
        XCTAssertTrue(String(decoding: row, as: UTF8.self).contains("private-text"))
        XCTAssertTrue(exported.contains { $0.lastPathComponent == "health.json" })
        XCTAssertThrowsError(try JournalExport.run(purpose: "workflow", source: source, destination: output, encryption: cipher))
        let badOutput = root.appendingPathComponent("bad-export")
        XCTAssertThrowsError(try JournalExport.run(purpose: "workflow", source: source, destination: badOutput, encryption: journalTestCipher(byte: 8)))
        XCTAssertFalse(FileManager.default.fileExists(atPath: badOutput.path))
        let encrypted = try FileManager.default.contentsOfDirectory(at: source, includingPropertiesForKeys: nil).first { $0.pathExtension == "jsonl" }!
        XCTAssertFalse(try String(contentsOf: encrypted).contains("private-text"))
    }
#if canImport(Security)
    func testKeychainPersistsKeyAndNeverCreatesDuringRead() throws {
        let path = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".keychain-db").path
        let password = UUID().uuidString
        var keychain: SecKeychain?
        let status = password.withCString { SecKeychainCreate(path, UInt32(password.utf8.count), $0, false, nil, &keychain) }
        XCTAssertEqual(status, errSecSuccess)
        guard let keychain else { return XCTFail("No temporary keychain") }
        defer { SecKeychainDelete(keychain) }
        let first = try JournalEncryption.keychainKey(purpose: "test", create: true, allowInteraction: false, keychainPath: path)
        let second = try JournalEncryption.keychainKey(purpose: "test", create: false, allowInteraction: false, keychainPath: path)
        XCTAssertEqual(first.count, 32)
        XCTAssertEqual(first, second)
        XCTAssertThrowsError(try JournalEncryption.keychainKey(purpose: "missing", create: false, allowInteraction: false, keychainPath: path))
    }
#endif

}
