import XCTest
@testable import BoxCopCore

/// Lifecycle contracts for a resident endpoint: slow first launch, sleep/wake and explicit auto-start.
final class LifecycleTests: XCTestCase {
    private func peer(_ mode: String) throws -> EngineConfiguration {
        let fixture = try XCTUnwrap(Bundle.module.url(forResource: "peer", withExtension: "pl", subdirectory: "Fixtures"))
        return EngineConfiguration(executableURL: URL(fileURLWithPath: "/usr/bin/perl"), arguments: [fixture.path, mode],
                                   dataDirectory: FileManager.default.temporaryDirectory.appendingPathComponent("boxcop-lifecycle-\(UUID().uuidString)"))
    }

    /// A frozen helper's first launch can be slow while macOS validates its bundled libraries.
    func testSlowFirstStartupUsesStartupDeadlineNotPerRequestDeadline() async throws {
        let client = EngineClient(requestTimeout: 0.15, startupTimeout: 3)
        try await client.start(configuration: peer("slowstart"))
        let state = await client.snapshot()
        XCTAssertTrue(state.ready)
        guard case .recent = try await client.request(.recent(1)) else { return XCTFail("Not recent") }
        await client.stop()
    }

    func testStartupDeadlineStillFailsClosedForSilentHelper() async throws {
        let client = EngineClient(requestTimeout: 3, startupTimeout: 0.2)
        let started = ProcessInfo.processInfo.systemUptime
        do { try await client.start(configuration: peer("silent")); XCTFail("Silent helper became ready") }
        catch { XCTAssertEqual(error as? EngineFailure, .timedOut) }
        XCTAssertLessThan(ProcessInfo.processInfo.systemUptime - started, 2)
        let snapshot = await client.snapshot()
        XCTAssertFalse(snapshot.ready)
        await client.stop()
    }

    func testChildEnvironmentDropsInterpreterLoaderAndDevelopmentOverrides() {
        let cleaned = EngineConfiguration.cleanEnvironment([
            "PATH": "/usr/bin:/bin", "HOME": "/Users/example", "LANG": "en_US.UTF-8",
            "PYTHONPATH": "x", "PYTHONHOME": "x", "PYTHONSTARTUP": "x", "PYTHONINSPECT": "1", "PYTHONWARNINGS": "x",
            "DYLD_INSERT_LIBRARIES": "x", "DYLD_LIBRARY_PATH": "x", "LD_PRELOAD": "x", "LD_LIBRARY_PATH": "x",
            "BOXCOP_ENGINE_EXECUTABLE": "/x", "BOXCOP_ENGINE_ARGUMENTS": "[]"
        ])
        XCTAssertEqual(cleaned, ["PATH": "/usr/bin:/bin", "HOME": "/Users/example", "LANG": "en_US.UTF-8"])
    }

    func testOlderPreferencesWithoutAutoStartKeepConsentAndDefaultOff() throws {
        let legacy = Data(#"{"monitoring":true,"guardShortcut":true,"notifications":false,"role":"hr"}"#.utf8)
        let choices = try JSONDecoder().decode(ConsentChoices.self, from: legacy)
        XCTAssertTrue(choices.monitoring)
        XCTAssertTrue(choices.guardShortcut)
        XCTAssertEqual(choices.role, .hr)
        XCTAssertFalse(choices.notifications, "Preserve an existing notification opt-out")
        XCTAssertFalse(choices.autoStart)
    }

    func testAutoStartIsOffByDefaultAndRequiresMonitoringConsent() {
        var choices = ConsentChoices()
        XCTAssertFalse(choices.autoStart)
        XCTAssertFalse(choices.startsAutomatically)
        choices.autoStart = true
        XCTAssertFalse(choices.startsAutomatically)
        choices.monitoring = true
        XCTAssertTrue(choices.startsAutomatically)
    }

    func testWakeResumesOnlyASessionThatSleepInterrupted() {
        var resume = SleepResume()
        resume.sleep(wasRunning: true)
        XCTAssertTrue(resume.wake(consent: true))
        XCTAssertFalse(resume.wake(consent: true), "Resume is single-use")

        resume.sleep(wasRunning: false)
        XCTAssertFalse(resume.wake(consent: true), "A stopped session stays stopped")

        resume.sleep(wasRunning: true)
        resume.userStopped()
        XCTAssertFalse(resume.wake(consent: true), "An explicit pause or revocation wins")

        resume.sleep(wasRunning: true)
        XCTAssertFalse(resume.wake(consent: false), "Revoked consent never resumes")
    }
}
