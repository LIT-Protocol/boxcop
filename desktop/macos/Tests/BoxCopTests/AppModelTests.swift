import XCTest
import BoxCopCore
@testable import BoxCop

/// The view model computed from fixture state: no engine, hooks, extension or notifications are touched.
final class AppModelTests: XCTestCase {
    @MainActor func testFixtureStatesMapToTheFourOverallWords() throws {
        XCTAssertEqual(try Fixtures.model(.protected).summary.overall, .protected)
        XCTAssertEqual(try Fixtures.model(.partly).summary.overall, .partlyProtected)
        XCTAssertEqual(try Fixtures.model(.notProtected).summary.overall, .notProtected)
        XCTAssertEqual(try Fixtures.model(.paused).summary.overall, .paused)
    }

    @MainActor func testPartlyStateListsWhatNeedsThePerson() throws {
        let model = try Fixtures.model(.partly)
        XCTAssertEqual(model.needsYou.map(\.id), ["approval:rq-send", "network", "hooks", "findings"])
        XCTAssertEqual(model.pendingApprovalCount, 1)
        XCTAssertEqual(model.layer(.outboundControl).state, .needsSetup)
        XCTAssertEqual(model.layer(.agentChecks).state, .needsSetup)
        XCTAssertEqual(model.layer(.smartTriage).detail, "Downloading the model: 41% of 2.7 GB.")
        XCTAssertFalse(model.fixable(model.layer(.smartTriage)))
        let menu = MenuState(model)
        XCTAssertEqual(menu.statusLine, "BoxCop: Partly protected")
        XCTAssertEqual(menu.approvalsLine, "1 approval waiting")
        XCTAssertNotNil(menu.dot)
    }

    @MainActor func testProtectedStateIsQuiet() throws {
        let model = try Fixtures.model(.protected)
        XCTAssertTrue(model.needsYou.isEmpty)
        XCTAssertTrue(model.layers.prefix(4).allSatisfy { $0.state == .on })
        let menu = MenuState(model)
        XCTAssertNil(menu.dot); XCTAssertNil(menu.approvalsLine); XCTAssertEqual(menu.pauseLine, "Pause Protection")
    }

    @MainActor func testPausedTurnsOffRoutingAndThreatBlockingButNotHooks() throws {
        let model = try Fixtures.model(.paused)
        XCTAssertEqual(model.layer(.installGate).state, .off)
        XCTAssertEqual(model.layer(.containment).state, .off)
        XCTAssertEqual(model.layer(.outboundControl).state, .off)
        XCTAssertEqual(model.layer(.agentChecks).state, .on)
        XCTAssertEqual(MenuState(model).pauseLine, "Resume Protection")
    }

    @MainActor func testEventListMergesAllSourcesWithTheApprovalPinned() throws {
        let model = try Fixtures.model(.active)
        let events = model.events
        XCTAssertEqual(events.first?.id, "approval:rq-send")
        XCTAssertEqual(Set(events.map(\.layer)), [.installGate, .containment, .outboundControl, .agentChecks, .machineHealth])
        XCTAssertEqual(events.filter { $0.status == .finding }.count, 4)
        XCTAssertNotNil(events.first { $0.id == "engine:evt-install" }?.explanation)
        XCTAssertEqual(events.first { $0.id == "engine:evt-script" }?.actions.first,
                       .allowForPackage(package: "sharp-prebuild", host: "collector.telemetry-cdn.example"))
        // Explanations are shown only while smart triage is on.
        model.wanted.remove(.smartTriage)
        XCTAssertNil(model.events.first { $0.id == "engine:evt-install" }?.explanation)
    }

    @MainActor func testIgnoringAFindingRemovesItFromEventsAndBadges() throws {
        let model = try Fixtures.model(.active)
        let finding = try XCTUnwrap(model.activeFindings.first)
        model.ignoreFinding(finding)
        XCTAssertEqual(model.activeFindings.count, 3)
        XCTAssertFalse(model.events.contains { $0.id == "finding:" + finding.id })
        model.restoreFinding(try XCTUnwrap(model.ignoredFindings.first))
        XCTAssertEqual(model.activeFindings.count, 4)
    }

    @MainActor func testNetworkClientAcceptsOnlyKnownCommands() {
        for command in ["network-activity", "network-activity-export", "network-threat-blocking-on", "network-threat-blocking-off",
                        "network-workflow start", "network-workflow " + UUID().uuidString] {
            XCTAssertTrue(NetworkServiceClient.allowed(command), command)
        }
        for command in ["status", "pause", "network-review", "network-decide x", "network-workflow ../x", "network-activity\nstatus", ""] {
            XCTAssertFalse(NetworkServiceClient.allowed(command), command)
        }
        XCTAssertEqual(NetworkServiceClient.socketPath, "/var/run/local.boxcop.network.sock")
        XCTAssertNil(NetworkServiceClient.request("network-activity", path: "/nonexistent/boxcop-test.sock"))
    }

    @MainActor func testHookStatusParsingAndFailingActionOutranksSummary() throws {
        let json = #"{"summary":"Agent action hooks","harnesses":{"claude":{"state":"callback_observed","last_callback":{"at":"2026-11-12T20:00:00Z"},"actions":{"Bash":{"state":"callback_error"}}},"codex":{"state":"not_detected"}}}"#
        let snapshot = try XCTUnwrap(HostAgents.parse(Data(json.utf8)))
        XCTAssertEqual(snapshot.connections.map(\.id), ["claude", "codex"])
        XCTAssertEqual(snapshot.connections[0].health, .needsRepair)
        XCTAssertEqual(snapshot.connections[0].lastCallback, "2026-11-12T20:00:00Z")
        XCTAssertEqual(snapshot.connections[1].health, .notDetected)
        XCTAssertNil(HostAgents.parse(Data("not json".utf8)))
    }

    @MainActor func testUpdaterDoesNotStartWithoutAFeed() throws {
        // The test bundle has no SUFeedURL: validation reports "skipped" instead of creating Sparkle objects.
        XCTAssertFalse(AppUpdater.feedConfigured)
        XCTAssertFalse(try AppUpdater.validateStartup())
        let updater = AppUpdater()
        updater.start()
        XCTAssertFalse(updater.enabled)
    }
}
