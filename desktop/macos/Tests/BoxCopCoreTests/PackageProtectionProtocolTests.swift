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
    func testExplicitPackageListenerCanCoexistWithPipeEngine() throws {
        let reply = #"{"version":1,"id":"p1","ok":true,"result":{"ready":true,"protocol":1,"engine":"rules+sequence","monitoring":false,"network_listener":true,"package_registry_listener":true}}"#
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
        let listener = #"{"version":1,"id":"p1","ok":true,"result":{"ready":true,"protocol":1,"engine":"rules+sequence","monitoring":false,"network_listener":true,"install_script_listener":true}}"#
        XCTAssertNotNil(try WireCodec.decode(Data(listener.utf8)).result)
        let undeclared = #"{"version":1,"id":"p1","ok":true,"result":{"ready":true,"protocol":1,"engine":"rules+sequence","monitoring":false,"network_listener":true}}"#
        XCTAssertThrowsError(try WireCodec.decode(Data(undeclared.utf8)))
    }
}
