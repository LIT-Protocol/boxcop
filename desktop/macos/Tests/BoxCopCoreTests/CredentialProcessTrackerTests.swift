import XCTest
@testable import BoxCopCore

final class CredentialProcessTrackerTests: XCTestCase {
    func testAgentSignatureMustBeValidAndMatchBothTeamAndIdentifier() {
        XCTAssertTrue(CredentialAgentIdentity.recognized(team: "2DC432GLL2", identifier: "codex", flags: 1))
        XCTAssertFalse(CredentialAgentIdentity.recognized(team: "OTHER12345", identifier: "codex", flags: 1))
        XCTAssertFalse(CredentialAgentIdentity.recognized(team: "2DC432GLL2", identifier: "other", flags: 1))
        XCTAssertFalse(CredentialAgentIdentity.recognized(team: "2DC432GLL2", identifier: "codex", flags: 0))
        XCTAssertFalse(CredentialAgentIdentity.recognized(team: "2DC432GLL2", identifier: "codex", flags: 3))
    }
    func testScopeRequiresTrustedIdentityOrTrackedAncestry() {
        var tracker = CredentialProcessTracker()
        let agent = Data([1]), child = Data([2]), grandchild = Data([3])
        XCTAssertEqual(tracker.scope(token: child, parent: agent, responsible: nil, trustedAgent: false), .unknown)
        XCTAssertEqual(tracker.scope(token: agent, parent: nil, responsible: nil, trustedAgent: true), .agent)
        tracker.fork(parent: agent, child: child)
        tracker.exit(token: agent)
        XCTAssertEqual(tracker.scope(token: child, parent: nil, responsible: nil, trustedAgent: false), .agent)
        XCTAssertEqual(tracker.scope(token: grandchild, parent: child, responsible: nil, trustedAgent: false), .agent)
        tracker.exit(token: child)
        XCTAssertEqual(tracker.scope(token: Data([2, 1]), parent: nil, responsible: nil, trustedAgent: false), .unknown)
        XCTAssertEqual(tracker.scope(token: child, parent: nil, responsible: nil, trustedAgent: false), .unknown)
    }
    func testResponsibleProcessAndCapacityDegradation() {
        var tracker = CredentialProcessTracker(capacity: 1)
        let agent = Data([1])
        _ = tracker.scope(token: agent, parent: nil, responsible: nil, trustedAgent: true)
        XCTAssertEqual(tracker.scope(token: Data([2]), parent: nil, responsible: agent, trustedAgent: false), .agent)
        XCTAssertTrue(tracker.degraded)
        var fresh = CredentialProcessTracker()
        fresh.lostEvents()
        XCTAssertTrue(fresh.degraded)
    }
    func testExceptionsExpireAndDoNotCrossProcessesOrFiles() {
        var exceptions = CredentialExceptions()
        let id = UUID(), now: TimeInterval = 1000
        let access = CredentialExceptions.Access(process: Data([1]), device: 1, inode: 2)
        XCTAssertFalse(exceptions.approve(id, now: now))
        exceptions.record(id, access: access)
        XCTAssertTrue(exceptions.approve(id, now: now))
        XCTAssertFalse(exceptions.approve(id, now: now))
        XCTAssertTrue(exceptions.allows(access, now: now + 299))
        XCTAssertFalse(exceptions.allows(access, now: now + 300))
        XCTAssertFalse(exceptions.allows(.init(process: Data([2]), device: 1, inode: 2), now: now))
        XCTAssertFalse(exceptions.allows(.init(process: Data([1]), device: 1, inode: 3), now: now))
        XCTAssertFalse(exceptions.allows(.init(process: Data([1]), device: 2, inode: 2), now: now))
    }
}
