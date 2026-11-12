import XCTest
@testable import BoxCopCore

final class SoftwareConsoleTests: XCTestCase {
    func testReadsPublishedConsoleAndRejectsUnsafePaths() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        let id = String(repeating: "a", count: 24)
        let file = directory.appendingPathComponent(id + ".json")
        let bytes = Data(#"{"text":"compiling…","status":"running","updated_at":"now","truncated":false}"#.utf8)
        XCTAssertTrue(FileManager.default.createFile(atPath: file.path, contents: bytes, attributes: [.posixPermissions: 0o600]))
        XCTAssertEqual(SoftwareConsole.read(id: id, directory: directory)?.text, "compiling…")
        XCTAssertNil(SoftwareConsole.read(id: "../outside", directory: directory))
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: file.path)
        XCTAssertNil(SoftwareConsole.read(id: id, directory: directory))
        try FileManager.default.removeItem(at: file)
        let target = directory.appendingPathComponent("target")
        try bytes.write(to: target)
        try FileManager.default.createSymbolicLink(at: file, withDestinationURL: target)
        XCTAssertNil(SoftwareConsole.read(id: id, directory: directory))
    }
}
