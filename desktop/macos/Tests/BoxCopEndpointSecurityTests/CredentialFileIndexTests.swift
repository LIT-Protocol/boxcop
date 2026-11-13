import XCTest
import Darwin
@testable import BoxCopEndpointSecurity

final class CredentialFileIndexTests: XCTestCase {
    func testExistingAliasesMatchWithoutReadingContentsAndRefreshTracksReplacement() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root.appendingPathComponent(".aws"), withIntermediateDirectories: true)
        let secret = root.appendingPathComponent(".aws/credentials")
        try Data("synthetic fixture".utf8).write(to: secret)
        let alias = root.appendingPathComponent("alias")
        try FileManager.default.linkItem(at: secret, to: alias)
        var info = stat()
        XCTAssertEqual(stat(alias.path, &info), 0)
        let old = CredentialFileIndex.load(homes: [root.path])
        XCTAssertEqual(old[CredentialFileID(info)], "AWS credentials")
        let symlink = root.appendingPathComponent("symlink")
        try FileManager.default.createSymbolicLink(at: symlink, withDestinationURL: secret)
        XCTAssertEqual(stat(symlink.path, &info), 0)
        XCTAssertEqual(old[CredentialFileID(info)], "AWS credentials")
        try FileManager.default.removeItem(at: secret)
        try Data("replacement fixture".utf8).write(to: secret)
        XCTAssertEqual(stat(secret.path, &info), 0)
        XCTAssertNil(old[CredentialFileID(info)])
        XCTAssertEqual(CredentialFileIndex.load(homes: [root.path])[CredentialFileID(info)], "AWS credentials")
    }
}
