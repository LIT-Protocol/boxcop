import XCTest
@testable import BoxCopCore

final class SettingsHelperPlacementTests: XCTestCase {
    private let screen = CGRect(x: 0, y: 50, width: 1920, height: 1120)
    private let size = CGSize(width: 225, height: 56)
    private let main = CGRect(x: 180, y: 340, width: 715, height: 625)

    func testApprovalDialogDoesNotBecomeAnchor() throws {
        let dialog = CGRect(x: 409, y: 528, width: 260, height: 250)
        let frame = try XCTUnwrap(SettingsHelperPlacement.frame(windows: [dialog, main], panelSize: size, visibleFrames: [screen]))
        XCTAssertEqual(frame.maxY, main.minY - 8)
        XCTAssertEqual(frame.midX, main.midX)
        XCTAssertFalse(frame.intersects(dialog))
    }

    func testNoRoomBelowHidesInsteadOfCoveringControls() {
        let lowWindow = CGRect(x: 180, y: 60, width: 715, height: 625)
        XCTAssertNil(SettingsHelperPlacement.frame(windows: [lowWindow], panelSize: size, visibleFrames: [screen]))
    }

    func testAnotherSettingsWindowInTheWayHidesPanel() {
        let dialog = CGRect(x: 409, y: 260, width: 260, height: 250)
        XCTAssertNil(SettingsHelperPlacement.frame(windows: [dialog, main], panelSize: size, visibleFrames: [screen]))
    }

    func testUsesDisplayContainingSettings() throws {
        let offset = CGFloat(-1920)
        let frame = try XCTUnwrap(SettingsHelperPlacement.frame(windows: [main.offsetBy(dx: offset, dy: 0)],
            panelSize: size, visibleFrames: [screen, screen.offsetBy(dx: offset, dy: 0)]))
        XCTAssertEqual(frame.midX, main.midX + offset)
        XCTAssertEqual(frame.maxY, main.minY - 8)
    }
}
