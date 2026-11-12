import XCTest
@testable import BoxCopCore

final class MonitoringRecoveryTests: XCTestCase {
    func testTransientFailuresBackOffAndCap() {
        var recovery = MonitoringRecovery()
        let delays = (0..<9).map { recovery.nextDelay(for: .timedOut, at: Double($0)) }
        XCTAssertEqual(delays, [2, 4, 8, 16, 32, 60, 60, 60, 60])
        for failure: EngineFailure in [.disconnected, .launchFailed, .notReady] {
            XCTAssertNotNil(recovery.nextDelay(for: failure, at: 10))
        }
    }
    func testRapidRestartsDoNotResetBackoffButStableSessionDoes() {
        var recovery = MonitoringRecovery()
        XCTAssertEqual(recovery.nextDelay(for: .disconnected, at: 0), 2)
        recovery.started(at: 2)
        XCTAssertEqual(recovery.nextDelay(for: .disconnected, at: 3), 4)
        recovery.started(at: 7)
        XCTAssertEqual(recovery.nextDelay(for: .timedOut, at: 67), 2)
    }
    func testPermanentAndCancelledFailuresRequireManualAction() {
        for failure: EngineFailure in [.invalidConfiguration, .protocolViolation, .lineTooLarge,
                                       .invalidRequest, .internalError, .backpressure, .cancelled] {
            var recovery = MonitoringRecovery()
            XCTAssertNil(recovery.nextDelay(for: failure, at: 0))
        }
    }
}
