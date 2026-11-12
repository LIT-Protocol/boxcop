import Foundation
import XCTest
@testable import BoxCopCore

final class HostHookSupervisorTests: XCTestCase {
    private func run(_ script: String, timeout: TimeInterval = 1) -> Data? {
        HostHookSupervisor.run(executable: URL(fileURLWithPath: "/bin/sh"),
                               arguments: ["-c", script], harness: "claude", environment: [:],
                               input: .nullDevice, timeout: timeout)
    }
    func testValidAllowAndDenyArePreserved() {
        XCTAssertEqual(run("printf '{}'"), Data("{}".utf8))
        let deny = "{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"deny\"}}"
        XCTAssertEqual(run("printf '%s' '\(deny)'"), Data(deny.utf8))
    }
    func testCrashAndNonzeroExitCannotApprove() {
        XCTAssertNil(run("kill -KILL $$"))
        XCTAssertNil(run("printf '{}'; exit 1"))
    }
    func testHungEngineReturnsBeforeVendorDeadline() {
        let started = Date()
        XCTAssertNil(run("exec /bin/sleep 10", timeout: 0.1))
        XCTAssertLessThan(Date().timeIntervalSince(started), 1)
    }
    func testInvalidMissingAndOversizedOutputCannotApprove() {
        XCTAssertNil(run("printf 'not-json'"))
        XCTAssertNil(run("exit 0"))
        XCTAssertNil(run("i=0; while [ $i -lt 70000 ]; do printf x; i=$((i+1)); done", timeout: 2))
        XCTAssertNil(HostHookSupervisor.validatedResponse(Data("[]".utf8), harness: "claude"))
        XCTAssertNil(HostHookSupervisor.validatedResponse(Data("{}".utf8), harness: "cursor"))
        XCTAssertNotNil(HostHookSupervisor.validatedResponse(Data("{\"permission\":\"deny\"}".utf8), harness: "cursor"))
    }
    func testMissingExecutableCannotApprove() {
        XCTAssertNil(HostHookSupervisor.run(executable: URL(fileURLWithPath: "/nonexistent-engine"),
                      arguments: [], harness: "claude", environment: [:], input: .nullDevice))
    }
    func testDescendantHoldingOutputOpenDoesNotHangParent() {
        let started = Date()
        let response = run("/bin/sleep 1 & printf '{}'", timeout: 0.3)
        #if os(macOS)
        XCTAssertEqual(response, Data("{}".utf8))
        #else
        // Portable Foundation can delay termination notification while the
        // descendant retains stdout. A bounded, fail-closed timeout is valid;
        // accepting malformed output or waiting for the descendant is not.
        XCTAssertTrue(response == nil || response == Data("{}".utf8))
        #endif
        XCTAssertLessThan(Date().timeIntervalSince(started), 0.8)
    }
    func testLauncherModesCoverOnlyKeptFlags() {
        XCTAssertEqual(HostHookSupervisor.launchModes("--host-agent-hook"), ["claude", "codex", "cursor"])
        XCTAssertEqual(HostHookSupervisor.launchModes("--host-agent-integrations"), ["auto", "install", "status", "remove"])
        for dropped in ["--provider-integrations", "--host-agent-correction", "--agent-corrections", "--reviewed-transfer"] {
            XCTAssertNil(HostHookSupervisor.launchModes(dropped))
        }
    }
    func testPreflightValidatorRejectsOtherHookShapes() {
        let block = Data("{\"decision\":\"block\",\"reason\":\"BoxCop: fixed text.\"}".utf8)
        XCTAssertNil(HostHookSupervisor.validatedResponse(block, harness: "claude"))
        XCTAssertNil(run("printf '{\"systemMessage\":\"x\"}'"))
    }
    func testSupervisorFailureIsPrivateAndContainsNoInput() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                                               attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        HostHookSupervisor.recordFailure(harness: "claude", directory: directory)
        let path = directory.appendingPathComponent("claude-supervisor-receipt.json")
        let record = try JSONSerialization.jsonObject(with: Data(contentsOf: path)) as! [String: Any]
        XCTAssertEqual(record["state"] as? String, "error")
        XCTAssertEqual(record["source"] as? String, "native_supervisor")
        XCTAssertEqual(Set(record.keys), Set(["schema_version", "harness", "state", "at", "source"]))
        let attributes = try FileManager.default.attributesOfItem(atPath: path.path)
        XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o600)
    }
}
