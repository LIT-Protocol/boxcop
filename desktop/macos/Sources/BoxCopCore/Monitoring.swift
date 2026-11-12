import Foundation

public enum IdentityValidation {
    public static func bundle(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        func alphanumeric(_ c: UInt8) -> Bool { (65...90).contains(c) || (97...122).contains(c) || (48...57).contains(c) }
        return (1...255).contains(bytes.count) && bytes.first.map(alphanumeric) == true && bytes.allSatisfy { alphanumeric($0) || $0 == 45 || $0 == 46 }
    }
    public static func requestID(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        return (1...64).contains(bytes.count) && bytes.allSatisfy { (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || $0 == 45 || $0 == 95 }
    }
}

/// Retry only transient helper failures. Rapid crashes retain backoff until a session
/// has run for a minute; merely completing the readiness handshake is not recovery.
public struct MonitoringRecovery: Sendable {
    private var delay: TimeInterval = 1
    private var startedAt: TimeInterval?
    public init() {}
    public mutating func started(at uptime: TimeInterval) { startedAt = uptime }
    public mutating func nextDelay(for failure: EngineFailure, at uptime: TimeInterval) -> TimeInterval? {
        defer { startedAt = nil }
        switch failure {
        case .disconnected, .timedOut, .launchFailed, .notReady: break
        default: return nil
        }
        if let startedAt, uptime - startedAt >= 60 { delay = 1 }
        delay = min(delay * 2, 60)
        return delay
    }
}
