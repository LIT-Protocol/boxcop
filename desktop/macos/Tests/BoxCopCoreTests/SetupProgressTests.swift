import XCTest
@testable import BoxCopCore

final class SetupProgressTests: XCTestCase {
    func testOlderWizardStepsResumeOnTheList() {
        XCTAssertEqual(SetupPage(storedStep: 0), .welcome)
        XCTAssertEqual(SetupPage(storedStep: 5), .finish)
        for older in [1, 2, 3, 4, 6, 99] { XCTAssertEqual(SetupPage(storedStep: older), .protections) }
    }
    func testNothingIsMissingWhenNothingWasChosen() {
        XCTAssertNil(SetupRequirements.missing(wantsNetwork: false, wantsPaste: false, wantsScreen: false,
                                               network: false, accessibility: false, screenRecording: false))
    }
    func testChosenProtectionsWaitForTheirOwnApprovals() {
        XCTAssertEqual(SetupRequirements.missing(wantsNetwork: true, wantsPaste: true, wantsScreen: true,
                                                 network: false, accessibility: false, screenRecording: false), .network)
        XCTAssertEqual(SetupRequirements.missing(wantsNetwork: false, wantsPaste: true, wantsScreen: false,
                                                 network: false, accessibility: false, screenRecording: true), .accessibility)
        XCTAssertNil(SetupRequirements.missing(wantsNetwork: false, wantsPaste: true, wantsScreen: false,
                                               network: false, accessibility: true, screenRecording: false))
    }
    func testScreenProtectionNeedsScreenRecordingThenAccessibility() {
        XCTAssertEqual(SetupRequirements.nextForScreen(accessibility: false, screenRecording: false), .screenRecording)
        XCTAssertEqual(SetupRequirements.nextForScreen(accessibility: false, screenRecording: true), .accessibility)
        XCTAssertNil(SetupRequirements.nextForScreen(accessibility: true, screenRecording: true))
    }
    func testAccessibilityForScreenAloneDoesNotReopenSetup() {
        XCTAssertNil(SetupRequirements.missing(wantsNetwork: false, wantsPaste: false, wantsScreen: true,
                                               network: false, accessibility: false, screenRecording: true))
        XCTAssertEqual(SetupRequirements.missing(wantsNetwork: false, wantsPaste: false, wantsScreen: true,
                                                 network: false, accessibility: true, screenRecording: false), .screenRecording)
    }
    func testScreenAccessibilityReopensSetupOnlyWhenSetupAskedForIt() {
        XCTAssertEqual(SetupRequirements.missing(wantsNetwork: false, wantsPaste: false, wantsScreen: true, screenNeedsAccessibility: true,
                                                 network: false, accessibility: false, screenRecording: true), .accessibility)
    }
    func testOneConnectedAgentDoesNotSpeakForTheOthers() {
        XCTAssertEqual(AgentSetupCopy.status(of: [(id: "claude", state: "callback observed"), (id: "codex", state: "not configured")], attempted: false),
                       .available(["Claude Code", "Codex"]))
        XCTAssertEqual(AgentSetupCopy.status(of: [(id: "claude", state: "callback observed"), (id: "codex", state: "not configured")], attempted: true), .failed)
        XCTAssertEqual(AgentSetupCopy.status(of: [(id: "claude", state: "callback observed"), (id: "codex", state: "configured not observed")], attempted: true),
                       .added(["Claude Code", "Codex"], codexAsks: true))
        XCTAssertEqual(AgentSetupCopy.status(of: [(id: "claude", state: "callback observed"), (id: "cursor", state: "callback observed")], attempted: true),
                       .on(["Claude Code", "Cursor"]))
    }
    func testAFailingCheckOutranksAToolsSummary() {
        XCTAssertEqual(AgentSetupCopy.effectiveState(summary: "configured not observed", actions: ["configured not observed", "callback error"]), "callback error")
        XCTAssertEqual(AgentSetupCopy.effectiveState(summary: "configured not observed", actions: ["configured not observed"]), "configured not observed")
    }
    func testCodexIsSaidToAskOnlyBeforeItsHookHasRun() {
        XCTAssertEqual(AgentSetupCopy.status(of: [(id: "codex", state: "configured not observed")], attempted: true), .added(["Codex"], codexAsks: true))
        XCTAssertEqual(AgentSetupCopy.status(of: [(id: "codex", state: "callback stale")], attempted: true), .added(["Codex"], codexAsks: false))
        XCTAssertEqual(AgentSetupCopy.addedLine(tools: ["Codex"], codexAsks: false), "Codex is ready.")
    }
    func testAgentsThatCannotBeUsedAreNotCalledReady() {
        XCTAssertNil(AgentSetupCopy.status(of: [(id: "claude", state: "not detected")], attempted: false))
        XCTAssertEqual(AgentSetupCopy.status(of: [(id: "claude", state: "callback error")], attempted: true), .failed)
        XCTAssertEqual(AgentSetupCopy.status(of: [(id: "claude", state: "configured not observed"), (id: "cursor", state: "callback error")], attempted: true),
                       .added(["Claude Code"], codexAsks: false))
    }
    func testAgentLinesNameOnlyTheToolsFound() {
        XCTAssertEqual(AgentSetupCopy.availableLine(tools: ["Claude Code", "Codex", "Cursor"]),
                       "Blocks dangerous commands in Claude Code, Codex and Cursor.")
        XCTAssertEqual(AgentSetupCopy.availableLine(tools: ["Cursor"]), "Blocks dangerous commands in Cursor.")
    }
    func testAddedLineOnlyMentionsApprovalWhenCodexIsPresent() {
        XCTAssertEqual(AgentSetupCopy.addedLine(tools: ["Claude Code", "Codex", "Cursor"]),
                       "Claude Code and Cursor are ready, and Codex will ask for approval.")
        XCTAssertEqual(AgentSetupCopy.addedLine(tools: ["Claude Code", "Cursor"]), "Claude Code and Cursor are ready.")
        XCTAssertEqual(AgentSetupCopy.addedLine(tools: ["Cursor"]), "Cursor is ready.")
        XCTAssertEqual(AgentSetupCopy.addedLine(tools: ["Claude Code", "Codex"]), "Claude Code is ready, and Codex will ask for approval.")
        XCTAssertEqual(AgentSetupCopy.addedLine(tools: ["Codex"]), "Codex will ask for approval.")
    }
    func testPackageManagersAreFoundWithoutRunningTheShell() {
        XCTAssertFalse(PackageManagerDetection.isPresent(home: "/Users/a") { _ in false })
        XCTAssertTrue(PackageManagerDetection.isPresent(home: "/Users/a") { $0 == "/opt/homebrew/bin/pnpm" })
        XCTAssertTrue(PackageManagerDetection.isPresent(home: "/Users/a") { $0 == "/Users/a/.nvm/versions/node" })
        XCTAssertFalse(PackageManagerDetection.isPresent(home: "/Users/a") { $0 == "/Users/b/.npm" })
    }
    func testRebaselineKeepsEarlierClipboardFromBeingRead() {
        var state = MonitoringState()
        XCTAssertTrue(state.start(consent: true, baselineRevision: 4))
        XCTAssertTrue(state.observe(revision: 5))
        XCTAssertTrue(state.mayRead(revision: 5))
        state.rebaseline(revision: 5)
        XCTAssertFalse(state.mayRead(revision: 5))
        XCTAssertFalse(state.observe(revision: 5))
        XCTAssertTrue(state.observe(revision: 6))
        XCTAssertTrue(state.mayRead(revision: 6))
    }
}
