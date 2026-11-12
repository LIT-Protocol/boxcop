import Foundation

public enum Role: String, Codable, CaseIterable, Sendable { case engineering, hr, finance }
public enum DecisionAction: String, Codable, Sendable { case allow, warn, block }

/// Only explicit preferences are persisted. Running state and clipboard text are not preferences.
public struct ConsentChoices: Codable, Equatable, Sendable {
    public var monitoring = false
    public var guardShortcut = false
    public var notifications = true
    public var role: Role = .engineering
    /// Separate explicit opt-in: start collection when the app launches (including at login).
    public var autoStart = false
    public init() {}
    private enum CodingKeys: String, CodingKey { case monitoring, guardShortcut, notifications, role, autoStart }
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        monitoring = try container.decode(Bool.self, forKey: .monitoring)
        guardShortcut = try container.decode(Bool.self, forKey: .guardShortcut)
        notifications = try container.decode(Bool.self, forKey: .notifications)
        role = try container.decode(Role.self, forKey: .role)
        // Older preferences predate this choice; absence means off, never on.
        autoStart = try container.decodeIfPresent(Bool.self, forKey: .autoStart) ?? false
    }
    /// Auto-start never substitutes for monitoring consent.
    public var startsAutomatically: Bool { monitoring && autoStart }
}

/// Sleep interrupts collection. Wake resumes only that interrupted session, once, if consent remains.
public struct SleepResume: Sendable {
    private var interrupted = false
    public init() {}
    public mutating func sleep(wasRunning: Bool) { interrupted = wasRunning }
    /// An explicit pause, consent revocation, role change or engine failure cancels a pending resume.
    public mutating func userStopped() { interrupted = false }
    public mutating func wake(consent: Bool) -> Bool {
        defer { interrupted = false }
        return interrupted && consent
    }
}

public struct MonitoringState: Sendable {
    public private(set) var running = false
    public private(set) var generation: UInt64 = 0
    public private(set) var baselineRevision: Int?
    public private(set) var lastRevision: Int?
    public init() {}
    @discardableResult public mutating func start(consent: Bool, baselineRevision: Int) -> Bool {
        guard consent else { return false }
        generation &+= 1
        running = true
        self.baselineRevision = baselineRevision
        lastRevision = baselineRevision
        return true
    }
    public mutating func pause() {
        generation &+= 1
        running = false
        baselineRevision = nil
        lastRevision = nil
    }
    public mutating func observe(revision: Int) -> Bool {
        guard running, revision != lastRevision else { return false }
        lastRevision = revision
        return true
    }
    /// Paste protection can turn on after the session starts. Earlier clipboard text stays unread.
    public mutating func rebaseline(revision: Int) {
        guard running else { return }
        baselineRevision = revision
        lastRevision = revision
    }
    /// Guard mode must not read the clipboard that existed before Start/Resume either.
    public func mayRead(revision: Int) -> Bool { running && revision != baselineRevision }
}

public enum ClipboardUnsupported: String, Sendable {
    case sensitiveType, passwordManager, missingIdentity, notPlainText, unreadable, oversized, empty, changed, baseline
    public var message: String {
        switch self {
        case .sensitiveType: return "Skipped concealed, transient or auto-generated clipboard content."
        case .passwordManager: return "Skipped clipboard while a password manager was frontmost."
        case .missingIdentity: return "Unsupported: the frontmost app has no valid bundle identity."
        case .notPlainText: return "Unsupported: clipboard is not plain text."
        case .unreadable: return "Clipboard unreadable or access denied/restricted. Check macOS privacy settings."
        case .oversized: return "Clipboard exceeds the inspection budget. Paste is allowed without a content check."
        case .empty: return "Unsupported: empty clipboard text."
        case .changed: return "Clipboard or frontmost app changed during evaluation; retry."
        case .baseline: return "Copy new text after Start/Resume. Pre-existing clipboard is not read."
        }
    }
}

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

public enum ClipboardPolicy {
    public static let maximumScalars = 4096
    private static let sensitiveTypes: Set<String> = [
        "org.nspasteboard.concealedtype", "org.nspasteboard.transienttype", "org.nspasteboard.autogeneratedtype",
        "com.agilebits.onepassword", "com.1password.1password"
    ]
    private static let managerPrefixes = ["com.agilebits.", "com.1password.", "com.bitwarden.", "com.lastpass.", "com.dashlane.", "com.keepass", "org.keepass", "com.strongbox.", "com.markmcguill.", "com.enpass.", "in.sinew.", "com.apple.passwords", "com.apple.keychainaccess"]
    public static func preflight(types: [String], bundleID: String?) -> ClipboardUnsupported? {
        guard let bundleID, IdentityValidation.bundle(bundleID) else { return .missingIdentity }
        if managerPrefixes.contains(where: { bundleID.lowercased().hasPrefix($0) }) { return .passwordManager }
        if types.contains(where: { sensitiveTypes.contains($0.lowercased()) }) { return .sensitiveType }
        guard types.contains("public.utf8-plain-text"), !types.contains("public.file-url"), !types.contains("NSFilenamesPboardType") else { return .notPlainText }
        return nil
    }
    public static func validateText(_ text: String?) -> ClipboardUnsupported? {
        guard let text else { return .unreadable }
        guard !text.isEmpty else { return .empty }
        // Count scalars, not grapheme clusters; never classify a truncated prefix.
        guard text.unicodeScalars.prefix(maximumScalars + 1).count <= maximumScalars else { return .oversized }
        return nil
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

/// Poll-driven paste recovery. A successful start only resets backoff after a stable
/// minute, so repeated OS tap timeouts cannot create a rapid restart loop.
public struct PasteProtectionRecovery: Sendable {
    private var delay: TimeInterval = 1
    private var startedAt: TimeInterval?
    private var retryAt: TimeInterval?
    public init() {}
    public mutating func started(at uptime: TimeInterval) {
        startedAt = uptime
        retryAt = nil
    }
    @discardableResult public mutating func failed(at uptime: TimeInterval) -> TimeInterval {
        if let startedAt, uptime - startedAt >= 60 { delay = 1 }
        startedAt = nil
        delay = min(delay * 2, 60)
        retryAt = uptime + delay
        return delay
    }
    public func shouldRetry(at uptime: TimeInterval, requested: Bool, accessibility: Bool, secureInput: Bool) -> Bool {
        guard requested, accessibility, !secureInput, let retryAt else { return false }
        return uptime >= retryAt
    }
}
