import XCTest
@testable import BoxCopCore

final class ProbeTests: XCTestCase {
    func testExplicitExecutableArgumentsAndPrivateDataDirectory() throws {
        let options = try ProbeOptions(arguments: ["--executable", "/usr/bin/python3", "--arguments", "[\"-m\",\"server.desktop\"]", "--data-dir", "/private/probe"])
        XCTAssertEqual(options.configuration.executableURL.path, "/usr/bin/python3")
        XCTAssertEqual(options.configuration.arguments, ["-m", "server.desktop"])
        XCTAssertEqual(options.configuration.dataDirectory.path, "/private/probe")
    }
    func testMalformedOrMissingProbeConfigurationIsRejected() {
        for arguments in [[], ["--executable", "/x"], ["--executable", "relative", "--data-dir", "/d"], ["--executable", "/x", "--data-dir", "relative"], ["--executable", "/x", "--data-dir", "/d", "--unknown", "x"], ["--executable", "/x", "--data-dir", "/d", "--arguments", "not-json"], ["--executable", "/x", "--data-dir", "/d", "--data-dir", "/e"]] {
            XCTAssertThrowsError(try ProbeOptions(arguments: arguments))
        }
    }
}
