import XCTest
@testable import BoxCopCore

final class MonitoringHealthTests: XCTestCase {
    private func health(starting: Bool = false, stopping: Bool = false, running: Bool = false, consent: Bool = true,
                        guardRequested: Bool = true, guardActive: Bool = false, failed: Bool = false) -> MonitoringHealth {
        MonitoringHealth(starting: starting, stopping: stopping, running: running, consent: consent,
                         guardRequested: guardRequested, guardActive: guardActive, failed: failed)
    }
    func testRunningIsHealthyOnlyWhenRequestedPasteProtectionIsActive() {
        XCTAssertEqual(health(running: true, guardActive: true), .monitoring)
        XCTAssertEqual(health(running: true, guardRequested: false), .monitoring)
        XCTAssertEqual(health(running: true), .pasteProtectionUnavailable)
    }
    func testErrorsStayVisibleUntilRetriedUnlessConsentWasRevoked() {
        XCTAssertEqual(health(failed: true), .failed)
        XCTAssertEqual(health(stopping: true, failed: true), .failed)
        XCTAssertEqual(health(consent: false, failed: true), .off)
        XCTAssertEqual(health(starting: true, failed: true), .starting)
    }
    func testRecoveryIsVisibleAndCanBePausedOrRetried() {
        let recovering = MonitoringHealth(starting: false, stopping: true, running: false, consent: true,
            guardRequested: true, guardActive: false, failed: true, recovering: true)
        XCTAssertEqual(recovering, .recovering)
        XCTAssertEqual(MenuAction.available(for: recovering, setupPending: false), [.restart, .pause])
        XCTAssertEqual(MonitoringHealth(starting: false, stopping: false, running: false, consent: false,
            guardRequested: true, guardActive: false, failed: true, recovering: true), .off)
    }
    func testStoppedStates() {
        XCTAssertEqual(health(stopping: true), .pausing)
        XCTAssertEqual(health(), .paused)
        XCTAssertEqual(health(consent: false), .off)
        XCTAssertEqual(health(stopping: true, consent: false), .off)
    }
    func testOnlyProblemsNeedAttention() {
        XCTAssertEqual(MonitoringHealth.allCases.filter(\.needsAttention), [.recovering, .pasteProtectionUnavailable, .failed])
    }
    func testMenuOffersTheFixThenPauseOrResume() {
        XCTAssertEqual(MenuAction.available(for: .monitoring, setupPending: false), [.pause])
        XCTAssertEqual(MenuAction.available(for: .starting, setupPending: false), [.pause])
        XCTAssertEqual(MenuAction.available(for: .pasteProtectionUnavailable, setupPending: false), [.retryPasteProtection, .pause])
        XCTAssertEqual(MenuAction.available(for: .failed, setupPending: false), [.restart])
        XCTAssertEqual(MenuAction.available(for: .paused, setupPending: false), [.resume])
        XCTAssertEqual(MenuAction.available(for: .pausing, setupPending: false), [.resume])
        XCTAssertEqual(MenuAction.available(for: .off, setupPending: false), [])
    }
    func testUnfinishedSetupLeadsAndReplacesResume() {
        XCTAssertEqual(MenuAction.available(for: .off, setupPending: true), [.finishSetup])
        XCTAssertEqual(MenuAction.available(for: .paused, setupPending: true), [.finishSetup])
        XCTAssertEqual(MenuAction.available(for: .monitoring, setupPending: true), [.finishSetup, .pause])
        XCTAssertEqual(MenuAction.available(for: .failed, setupPending: true), [.finishSetup, .restart])
    }
    func testMenuCopyUsesPlainTitleCaseWithoutCoverageClaims() {
        let jargon = ["engine", "guard", "collection", "dlp", "shortcut", "protected", "safe"]
        let copy = MonitoringHealth.allCases.map(\.summary) + MenuAction.allCases.map(\.rawValue)
        for text in copy {
            XCTAssertFalse(jargon.contains { text.lowercased().contains($0) }, text)
        }
        for action in MenuAction.allCases {
            XCTAssertTrue(action.rawValue.split(separator: " ").allSatisfy { $0.first?.isUppercase == true }, action.rawValue)
        }
    }
}
