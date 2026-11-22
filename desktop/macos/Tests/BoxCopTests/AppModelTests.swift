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
        XCTAssertEqual(model.needsYou.map(\.id), ["network", "hooks", "findings"])
        XCTAssertEqual(model.layer(.outboundControl).state, .needsSetup)
        XCTAssertEqual(model.layer(.agentChecks).state, .needsSetup)
        XCTAssertEqual(model.layer(.smartTriage).detail, "Downloading the model: 41% of 2.7 GB.")
        XCTAssertFalse(model.fixable(model.layer(.smartTriage)))
        let menu = MenuState(model)
        XCTAssertEqual(menu.statusLine, "BoxCop: Partly protected")
        XCTAssertNotNil(menu.dot)
    }

    @MainActor func testPackageSetupOffersRepairOnlyAfterTheWorkerFinishes() throws {
        let model = try Fixtures.model(.protected)
        for busy in [true, false] {
            let summary = busy ? "Downloading and verifying the malware list…" : "Package signing key changed"
            model.packageStatus = try Fixtures.decode(PackageProtectionStatus.self, #"{"configured":true,"routed":false,"active":false,"busy":\#(busy),"stale":true,"summary":"\#(summary)"}"#)
            XCTAssertEqual(model.layer(.installGate), LayerStatus(.installGate, busy ? .working : .needsSetup, summary))
            XCTAssertEqual(model.fixable(model.layer(.installGate)), !busy)
            XCTAssertEqual(model.needsYou.contains { $0.id == LayerID.installGate.rawValue }, !busy)
        }
    }

    @MainActor func testProtectedStateIsQuiet() throws {
        let model = try Fixtures.model(.protected)
        XCTAssertTrue(model.needsYou.isEmpty)
        XCTAssertTrue(model.layers.prefix(4).allSatisfy { $0.state == .on })
        let menu = MenuState(model)
        XCTAssertNil(menu.dot); XCTAssertEqual(menu.pauseLine, "Pause Protection")
    }

    @MainActor func testPausedTurnsOffRoutingAndThreatBlockingButNotHooks() throws {
        let model = try Fixtures.model(.paused)
        XCTAssertEqual(model.layer(.installGate).state, .off)
        XCTAssertEqual(model.layer(.containment).state, .off)
        XCTAssertEqual(model.layer(.outboundControl).state, .off)
        XCTAssertEqual(model.layer(.agentChecks).state, .on)
        XCTAssertEqual(MenuState(model).pauseLine, "Resume Protection")
    }

    @MainActor func testEventListMergesAllSourcesNewestFirst() throws {
        let model = try Fixtures.model(.active)
        let events = model.events
        XCTAssertEqual(events.first?.id, "engine:evt-reported")
        XCTAssertEqual(Set(events.map(\.status)), [.blocked, .warned, .finding])
        XCTAssertEqual(events.first?.actions.first, .allowRelease(PackageRelease(ecosystem: "npm", package: "color-string-fmt", version: "2.1.4")))
        XCTAssertEqual(events.first { $0.id == "engine:evt-install" }?.actions, [.copyDetails])
        XCTAssertEqual(EventDetail.confirmation(try XCTUnwrap(events.first?.release)),
                       "color-string-fmt 2.1.4 is reported as malware but not confirmed. Allowing lets package managers install this exact release.")
        XCTAssertEqual(Set(events.map(\.layer)), [.installGate, .containment, .outboundControl, .agentChecks, .machineHealth])
        XCTAssertEqual(events.filter { $0.status == .finding }.count, 4)
        XCTAssertNotNil(events.first { $0.id == "engine:evt-install" }?.explanation)
        XCTAssertEqual(events.first { $0.id == "engine:evt-script" }?.actions.first,
                       .allowForPackage(package: "sharp-prebuild", host: "collector.telemetry-cdn.example"))
        // Explanations are shown only while smart triage is on.
        model.wanted.remove(.smartTriage)
        XCTAssertNil(model.events.first { $0.id == "engine:evt-install" }?.explanation)
    }

    @MainActor func testInstallGateExceptionsAndTriageSetupErrorReachTheModel() throws {
        let model = try Fixtures.model(.protected)
        XCTAssertEqual(model.packageStatus?.exceptions.map(\.release.display), ["node-ipc-relay@10.1.3", "fastapi-cache-tools==0.4.0"])
        // Triage is off and a model is on disk: the card can offer to remove it, and the status line says it is there.
        XCTAssertEqual(model.layer(.smartTriage), LayerStatus(.smartTriage, .off, "Turn on smart triage in BoxCop. The model is already downloaded."))
        model.modelBytes = nil
        XCTAssertEqual(model.layer(.smartTriage).detail, "Turn on smart triage in BoxCop. The model is a 2.7 GB download on first use.")

        let message = "Not enough free disk space to download the triage model. It needs 6.8 GB free (a 2.7 GB download plus 4 GB left over) and 3.1 GB is available."
        model.wanted.insert(.smartTriage)
        model.judgment = try Fixtures.decode(WorkflowJudgmentStatus.self, #"{"state":"waiting","model":"local","promptVersion":"v7","advisoryOnly":true,"setup":{"state":"error","downloadedBytes":0,"totalBytes":2740937888,"message":"\#(message)"}}"#)
        XCTAssertEqual(model.layer(.smartTriage), LayerStatus(.smartTriage, .needsSetup, message))
        XCTAssertTrue(model.fixable(model.layer(.smartTriage)))
        XCTAssertEqual(model.summary.overall, .partlyProtected)
    }

    @MainActor func testModelOnDiskIsFoundOnlyWhenADownloadIsComplete() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("boxcop-models-" + UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        XCTAssertNil(EngineTools.downloadedModelBytes(in: directory))
        let workflow = directory.appendingPathComponent("workflow")
        try FileManager.default.createDirectory(at: workflow, withIntermediateDirectories: true)
        try Data(count: 4096).write(to: workflow.appendingPathComponent("download.part"))
        XCTAssertNil(EngineTools.downloadedModelBytes(in: directory))
        // A sparse file stands in for the model: the size is what is checked, not the content.
        let model = workflow.appendingPathComponent("abc.gguf")
        FileManager.default.createFile(atPath: model.path, contents: nil)
        let handle = try FileHandle(forWritingTo: model)
        try handle.truncate(atOffset: 150_000_000); try handle.close()
        XCTAssertEqual(EngineTools.downloadedModelBytes(in: directory), 150_004_096)
        XCTAssertTrue(EngineTools.modelDirectory.path.hasSuffix("/Library/Application Support/BoxCop/models"))
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

extension AppModelTests {
    @MainActor func testCredentialFailuresAppearOnOverview() throws {
        let model = try Fixtures.model(.protected)
        var status = CredentialProtectionStatus(state: "needsPermission", detail: "Full Disk Access required")
        status.enabled = true
        model.network.credentials = status
        XCTAssertTrue(model.attentionNeeded)
        XCTAssertTrue(model.needsYou.contains { $0.id == "credentials" })
        status.state = "active"
        model.network.credentials = status
        XCTAssertFalse(model.needsYou.contains { $0.id == "credentials" })
        status.state = "degraded"
        model.network.credentials = status
        XCTAssertTrue(model.needsYou.contains { $0.id == "credentials" })
    }
}
