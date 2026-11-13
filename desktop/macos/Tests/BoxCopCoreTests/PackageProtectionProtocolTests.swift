import XCTest
@testable import BoxCopCore

final class PackageProtectionProtocolTests: XCTestCase {
    func testPackageCommandsAndRecoverableStatus() throws {
        let request = try WireCodec.encode(id: "p1", command: .packageProtection(.enable))
        let value = try JSONSerialization.jsonObject(with: request) as! [String: Any]
        XCTAssertEqual(value["op"] as? String, "package_protection")
        XCTAssertEqual(value["action"] as? String, "enable")
        let reply = #"{"version":1,"id":"p1","ok":true,"result":{"packageProtection":{"configured":true,"routed":true,"active":false,"busy":false,"stale":true,"summary":"Retry","generated_at":null,"update_error":null}}}"#
        let response = try WireCodec.decode(Data(reply.utf8))
        guard case let .packageProtection(status) = response.result else { return XCTFail("Wrong response") }
        XCTAssertTrue(status.routed)
        XCTAssertFalse(status.active)
        XCTAssertFalse(status.busy)
    }
    func testAllowAndRevokeNameOneExactRelease() throws {
        func request(_ command: EngineCommand) throws -> [String: Any] {
            try XCTUnwrap(JSONSerialization.jsonObject(with: WireCodec.encode(id: "p1", command: command)) as? [String: Any])
        }
        let release = PackageRelease(ecosystem: "npm", package: "left-pad", version: "1.0.1")
        let allow = try request(.packageProtection(.allow, release: release))
        // The envelope's `version` stays the protocol number; the release version travels under its own key.
        XCTAssertEqual(Set(allow.keys), ["version", "id", "op", "action", "ecosystem", "package", "package_version"])
        XCTAssertEqual(allow["version"] as? Int, 1)
        XCTAssertEqual(allow["action"] as? String, "allow"); XCTAssertEqual(allow["ecosystem"] as? String, "npm")
        XCTAssertEqual(allow["package"] as? String, "left-pad"); XCTAssertEqual(allow["package_version"] as? String, "1.0.1")
        let revoke = try request(.packageProtection(.revoke, release: PackageRelease(ecosystem: "PyPI", package: "requests", version: "2.0.0")))
        XCTAssertEqual(revoke["action"] as? String, "revoke"); XCTAssertEqual(revoke["ecosystem"] as? String, "PyPI")
        // Status, enable and disable carry no release; allow and revoke must.
        XCTAssertEqual(Set(try request(.packageProtection(.status)).keys), ["version", "id", "op", "action"])
        XCTAssertThrowsError(try WireCodec.encode(id: "p1", command: .packageProtection(.allow)))
        XCTAssertThrowsError(try WireCodec.encode(id: "p1", command: .packageProtection(.enable, release: release)))
        for bad in [PackageRelease(ecosystem: "cargo", package: "x", version: "1"), PackageRelease(ecosystem: "npm", package: "", version: "1"),
                    PackageRelease(ecosystem: "npm", package: "x", version: ""), PackageRelease(ecosystem: "npm", package: String(repeating: "a", count: 215), version: "1"),
                    PackageRelease(ecosystem: "npm", package: "x", version: String(repeating: "1", count: 129))] {
            XCTAssertThrowsError(try WireCodec.encode(id: "p1", command: .packageProtection(.allow, release: bad)))
        }
    }
    func testStatusListsExceptionsAndTheReasonAChangeWasRefused() throws {
        func status(_ extra: String) throws -> PackageProtectionStatus {
            let reply = #"{"version":1,"id":"p1","ok":true,"result":{"packageProtection":{"configured":true,"routed":true,"active":true,"busy":false,"stale":false,"summary":"On","generated_at":"2026-11-12T00:00:00Z","update_error":null\#(extra)}}}"#
            guard case let .packageProtection(status) = try WireCodec.decode(Data(reply.utf8)).result else { throw EngineFailure.protocolViolation }
            return status
        }
        let listed = try status(#","exceptions":[{"ecosystem":"npm","package":"left-pad","version":"1.0.1","added":"2026-11-12T10:00:00Z"},{"ecosystem":"PyPI","package":"requests","version":"2.0.0","added":"2026-11-12T11:00:00Z"}],"exception_error":null"#)
        XCTAssertEqual(listed.exceptions.map(\.release), [PackageRelease(ecosystem: "npm", package: "left-pad", version: "1.0.1"),
                                                          PackageRelease(ecosystem: "PyPI", package: "requests", version: "2.0.0")])
        XCTAssertEqual(listed.exceptions.first?.added, "2026-11-12T10:00:00Z"); XCTAssertNil(listed.exceptionError)
        XCTAssertEqual(Set(listed.exceptions.map(\.id)).count, 2)
        // An engine that predates exceptions omits both keys.
        let old = try status("")
        XCTAssertTrue(old.exceptions.isEmpty); XCTAssertNil(old.exceptionError)
        // A refusal is shown as the engine wrote it; the list is unchanged.
        let refused = try status(#","exceptions":[],"exception_error":"Confirmed malware cannot be allowed.""#)
        XCTAssertEqual(refused.exceptionError, "Confirmed malware cannot be allowed.")
        // One malformed row does not hide the others, and `added` is optional.
        let mixed = try status(#","exceptions":[{"ecosystem":"cargo","package":"x","version":"1"},{"package":"y"},{"ecosystem":"npm","package":"ok","package_version":"3.0.0"}]"#)
        XCTAssertEqual(mixed.exceptions.map(\.release.display), ["ok@3.0.0"]); XCTAssertNil(mixed.exceptions.first?.added)
        XCTAssertTrue(try status(#","exceptions":"none""#).exceptions.isEmpty)
        // The protocol number is still strictly an integer.
        XCTAssertThrowsError(try WireCodec.decode(Data(#"{"version":"1","id":"p1","ok":true,"result":{"stopped":true}}"#.utf8)))
    }
    func testExplicitPackageListenerCanCoexistWithPipeEngine() throws {
        let reply = #"{"version":1,"id":"p1","ok":true,"result":{"ready":true,"protocol":1,"engine":"rules","network_listener":true,"package_registry_listener":true}}"#
        XCTAssertNotNil(try WireCodec.decode(Data(reply.utf8)).result)
    }
    func testInstallScriptCommandsBlockedConnectionsAndListener() throws {
        let request = try WireCodec.encode(id: "s1", command: .scriptProtection(.allow, package: "left-pad", host: "downloads.example"))
        let value = try JSONSerialization.jsonObject(with: request) as! [String: Any]
        XCTAssertEqual(value["op"] as? String, "script_protection")
        XCTAssertEqual(value["action"] as? String, "allow")
        XCTAssertEqual(value["package"] as? String, "left-pad")
        XCTAssertEqual(value["host"] as? String, "downloads.example")
        let status = try JSONSerialization.jsonObject(with: WireCodec.encode(id: "s2", command: .scriptProtection(.status))) as! [String: Any]
        XCTAssertEqual(status["package"] as? String, "")
        XCTAssertThrowsError(try WireCodec.encode(id: "s3", command: .scriptProtection(.allow, package: String(repeating: "a", count: 256), host: "x")))
        let reply = #"{"version":1,"id":"s1","ok":true,"result":{"scriptProtection":{"routed":true,"active":true,"summary":"On","blocked":[{"id":"ab12","time":"2026-11-11T10:00:00+00:00","package":"left-pad","package_version":"1.0.0","event":"postinstall","agent":null,"project":"/work/app","host":"collector.example","port":443,"count":2,"message":"Blocked"}],"exceptions":[{"package":"electron","host":"github.com"}]}}}"#
        guard case let .scriptProtection(result) = try WireCodec.decode(Data(reply.utf8)).result else { return XCTFail("Wrong response") }
        XCTAssertTrue(result.active)
        XCTAssertEqual(result.blocked.first?.host, "collector.example")
        XCTAssertNil(result.blocked.first?.agent)
        XCTAssertEqual(result.exceptions, [ScriptDestinationException(package: "electron", host: "github.com")])
        let listener = #"{"version":1,"id":"p1","ok":true,"result":{"ready":true,"protocol":1,"engine":"rules","network_listener":true,"install_script_listener":true}}"#
        XCTAssertNotNil(try WireCodec.decode(Data(listener.utf8)).result)
        let undeclared = #"{"version":1,"id":"p1","ok":true,"result":{"ready":true,"protocol":1,"engine":"rules","network_listener":true}}"#
        XCTAssertThrowsError(try WireCodec.decode(Data(undeclared.utf8)))
    }
}
