import Foundation

/// One plain status for the menu bar and window. It reports what is running, never a
/// general "protected" claim; coverage detail and diagnostics stay in the window.
public enum MonitoringHealth: CaseIterable, Equatable, Sendable {
    case recovering, starting, monitoring, pasteProtectionUnavailable, pausing, paused, failed, off

    public init(starting: Bool, stopping: Bool, running: Bool, consent: Bool,
                guardRequested: Bool, guardActive: Bool, failed: Bool, recovering: Bool = false) {
        if starting { self = .starting }
        else if running { self = guardRequested && !guardActive ? .pasteProtectionUnavailable : .monitoring }
        // Revoked consent is a choice, not a fault; an engine error stays visible until retried.
        else if !consent { self = .off }
        else if recovering { self = .recovering }
        else if failed { self = .failed }
        else { self = stopping ? .pausing : .paused }
    }

    public var summary: String {
        switch self {
        case .recovering: return "Restarting monitoring…"
        case .starting: return "Starting…"
        case .monitoring: return "Monitoring"
        case .pasteProtectionUnavailable: return "Paste protection unavailable"
        case .pausing: return "Pausing…"
        case .paused: return "Monitoring paused"
        case .failed: return "Monitoring stopped after an error"
        case .off: return "Monitoring is off"
        }
    }

    /// Requested protection is down. Shown on the menu-bar icon without opening the menu.
    public var needsAttention: Bool { self == .pasteProtectionUnavailable || self == .failed || self == .recovering }
}

/// Menu-bar actions. The window keeps navigation, configuration and repair details.
public enum MenuAction: String, CaseIterable, Sendable {
    case finishSetup = "Finish Setup…"
    case retryPasteProtection = "Retry Paste Protection"
    case restart = "Restart Monitoring"
    case pause = "Pause Monitoring"
    case resume = "Resume Monitoring"

    /// Unfinished setup first, then the fix for what is wrong, then pause or resume.
    /// While setup is unfinished, the setup assistant starts monitoring instead of Resume.
    public static func available(for health: MonitoringHealth, setupPending: Bool) -> [MenuAction] {
        var actions: [MenuAction] = setupPending ? [.finishSetup] : []
        switch health {
        case .starting, .monitoring: actions.append(.pause)
        case .pasteProtectionUnavailable: actions += [.retryPasteProtection, .pause]
        case .recovering: actions += [.restart, .pause]
        case .failed: actions.append(.restart)
        case .pausing, .paused: if !setupPending { actions.append(.resume) }
        case .off: break
        }
        return actions
    }
}
