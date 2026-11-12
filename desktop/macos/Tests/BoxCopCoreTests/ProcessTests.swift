import XCTest
@testable import BoxCopCore
#if os(Linux)
import Glibc
#else
import Darwin
#endif

final class ProcessTests: XCTestCase {
    func config(_ mode: String = "normal") throws -> EngineConfiguration {
        let fixture = try XCTUnwrap(Bundle.module.url(forResource: "peer", withExtension: "pl", subdirectory: "Fixtures"))
        return EngineConfiguration(executableURL: URL(fileURLWithPath: "/usr/bin/perl"), arguments: [fixture.path, mode], dataDirectory: FileManager.default.temporaryDirectory.appendingPathComponent("boxcop-swift-tests-\(UUID().uuidString)"))
    }
    func testRealProcessHandshakeRequestsAndStop() async throws {
        let client = EngineClient(requestTimeout: 1)
        try await client.start(configuration: config("partial"))
        let state = await client.snapshot()
        XCTAssertTrue(state.ready)
        let pid = try XCTUnwrap(state.pid)
        let result = try await client.request(.recent(5))
        guard case let .recent(items, total) = result else { return XCTFail("Not recent") }
        XCTAssertTrue(items.isEmpty); XCTAssertEqual(total, 0)
        await client.stop()
        let stopped = await client.snapshot()
        XCTAssertFalse(stopped.ready); XCTAssertNil(stopped.pid)
        XCTAssertEqual(kill(pid, 0), -1)
    }
    func testStartDoesNotDeclareReadyOnLaunchAlone() async throws {
        for mode in ["notready", "eof", "malformed", "wrongid", "oversized", "silent"] {
            let client = EngineClient(requestTimeout: 0.15, startupTimeout: 0.15)
            do { try await client.start(configuration: config(mode)); XCTFail("Unexpected ready: \(mode)") }
            catch { XCTAssertTrue(error is EngineFailure) }
            let snapshot = await client.snapshot(); XCTAssertFalse(snapshot.ready)
            await client.stop()
        }
    }
    func testStderrCannotBlockOrLeakToCaller() async throws {
        let client = EngineClient(requestTimeout: 1)
        try await client.start(configuration: config("stderr"))
        do { _ = try await client.request(.policies); XCTFail("Expected safe error") }
        catch { XCTAssertEqual(error as? EngineFailure, .invalidRequest); XCTAssertFalse(String(describing: error).contains("PRIVATE_MARKER")) }
        await client.stop()
    }
    func testTimeoutDisconnectsAndRestartDropsObsoleteReplies() async throws {
        let client = EngineClient(requestTimeout: 0.15)
        try await client.start(configuration: config("slow"))
        do { _ = try await client.request(.recent(1)); XCTFail("Expected timeout") }
        catch { XCTAssertEqual(error as? EngineFailure, .timedOut) }
        try await client.start(configuration: config())
        let result = try await client.request(.recent(1))
        guard case .recent = result else { return XCTFail("Not recent") }
        await client.stop()
    }
    func testPauseKillsChildAndCompletesPendingRequest() async throws {
        let client = EngineClient(requestTimeout: 5)
        try await client.start(configuration: config("slow"))
        let running = await client.snapshot()
        let pid = try XCTUnwrap(running.pid)
        let pending = Task { try await client.request(.recent(1)) }
        try await Task.sleep(nanoseconds: 30_000_000)
        await client.stop()
        do { _ = try await pending.value; XCTFail("Pending request escaped stop") }
        catch { XCTAssertEqual(error as? EngineFailure, .cancelled) }
        XCTAssertEqual(kill(pid, 0), -1)
    }
    func testBackpressureIsBoundedAndVisible() async throws {
        let client = EngineClient(requestTimeout: 2, maximumPending: 1)
        try await client.start(configuration: config("slow"))
        let pending = Task { try await client.request(.recent(1)) }
        try await Task.sleep(nanoseconds: 30_000_000)
        do { _ = try await client.request(.recent(1)); XCTFail("Expected backpressure") }
        catch { XCTAssertEqual(error as? EngineFailure, .backpressure) }
        await client.stop(); _ = try? await pending.value
    }
    func testChildExitNotifiesCoverageOwnerAndClearsReadiness() async throws {
        let lost = expectation(description: "Coverage owner sees child exit")
        let client = EngineClient(requestTimeout: 1, onFailure: { failure in
            if failure == .disconnected { lost.fulfill() }
        })
        try await client.start(configuration: config("readyexit"))
        await fulfillment(of: [lost], timeout: 2)
        let state = await client.snapshot()
        XCTAssertFalse(state.ready); XCTAssertNil(state.pid)
        await client.stop()
    }
    /// Reaping must not wait on a run-loop wake-up: on GitHub-hosted Macs `Process.waitUntilExit()`
    /// stayed asleep after its child had already been reaped. Every stop must return and reap promptly.
    func testRepeatedStopsReturnAndReapEveryChild() async throws {
        let normal = try config(), exiting = try config("eof")
        let finished = expectation(description: "Every stop returned")
        let cycles = Task {
            do {
                for cycle in 0..<20 {
                    let client = EngineClient(requestTimeout: 1, startupTimeout: 1)
                    if cycle.isMultiple(of: 2) {
                        try await client.start(configuration: normal)
                        let running = await client.snapshot()
                        let pid = try XCTUnwrap(running.pid)
                        await client.stop()
                        XCTAssertEqual(kill(pid, 0), -1, "Child \(cycle) was not reaped")
                    } else {
                        _ = try? await client.start(configuration: exiting)
                        await client.stop()
                    }
                }
            } catch {
                XCTFail("Start/stop cycle failed: \(error)")
            }
            finished.fulfill()
        }
        await fulfillment(of: [finished], timeout: 30)
        cycles.cancel()
    }
    func testCancelledStartupCannotLeaveOwnedChildRunning() async throws {
        let client = EngineClient(requestTimeout: 5)
        let configuration = try config("silent")
        let startup = Task { try await client.start(configuration: configuration) }
        try await Task.sleep(nanoseconds: 30_000_000)
        startup.cancel()
        let start = ProcessInfo.processInfo.systemUptime
        do { try await startup.value; XCTFail("Cancelled startup succeeded") }
        catch { XCTAssertEqual(error as? EngineFailure, .cancelled) }
        XCTAssertLessThan(ProcessInfo.processInfo.systemUptime - start, 1)
        let state = await client.snapshot(); XCTAssertNil(state.pid)
        await client.stop()
    }
    func testBundledConfigurationIgnoresEnvironmentOverrides() throws {
        let config = try EngineConfiguration.resolve(bundleURL: URL(fileURLWithPath: "/Applications/BoxCop.app"), environment: ["BOXCOP_ENGINE_EXECUTABLE": "/wrong", "BOXCOP_ENGINE_ARGUMENTS": "not json"], dataDirectory: URL(fileURLWithPath: "/test-data"))
        XCTAssertEqual(config.executableURL.path, "/Applications/BoxCop.app/Contents/Resources/engine/boxcop-engine")
        XCTAssertEqual(config.arguments, [])
        let development = try EngineConfiguration.resolve(bundleURL: URL(fileURLWithPath: "/dev/build"), environment: ["BOXCOP_ENGINE_EXECUTABLE": "/usr/bin/perl", "BOXCOP_ENGINE_ARGUMENTS": "[\"script.pl\"]"], dataDirectory: URL(fileURLWithPath: "/test-data"))
        XCTAssertEqual(development.arguments, ["script.pl"])
        XCTAssertThrowsError(try EngineConfiguration.resolve(bundleURL: URL(fileURLWithPath: "/dev/build"), environment: ["BOXCOP_ENGINE_EXECUTABLE": "relative"], dataDirectory: URL(fileURLWithPath: "/test-data")))
        XCTAssertNil(EngineConfiguration.cleanEnvironment(["PYTHONPATH": "private", "PYTHONHOME": "private"])["PYTHONPATH"])
        XCTAssertNil(EngineConfiguration.cleanEnvironment(["PYTHONHOME": "private"])["PYTHONHOME"])
    }
}
