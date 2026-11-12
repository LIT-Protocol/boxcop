import Foundation

public enum InterventionKind: String, Sendable {
    case fileAccess, appLaunch, network
    public var title: String {
        switch self {
        case .fileAccess: return "File access blocked"
        case .appLaunch: return "App launch blocked"
        case .network: return "Connection blocked"
        }
    }
    public var message: String {
        switch self {
        case .fileAccess: return "BoxCop stopped a process from opening a protected file. Open BoxCop to review protection settings before trying again."
        case .appLaunch: return "BoxCop stopped a process from launching under its protection rules. Open BoxCop to review protection settings before trying again."
        case .network: return "BoxCop stopped an outgoing connection because it wasn’t approved or couldn’t be checked. Open BoxCop to check protection status before retrying."
        }
    }
}

#if os(macOS)
/// Best-effort feedback to the running UI, never an authorization channel.
/// No paths, clipboard contents, hostnames, or process details cross this channel.
public enum InterventionSignal {
    public static let name = Notification.Name("local.boxcop.intervention")
    private static let queue = DispatchQueue(label: "boxcop.intervention-feedback")
    private static let lock = NSLock()
    private static var lastSent: [String: TimeInterval] = [:]
    public static func post(_ kind: InterventionKind, uid: UInt32?) {
        let audience = uid.map(String.init) ?? "unknown"
        let key = audience + ":" + kind.rawValue
        let now = ProcessInfo.processInfo.systemUptime
        lock.lock()
        let previous = lastSent[key]
        if let previous, now - previous < 2 { lock.unlock(); return }
        lastSent[key] = now
        lock.unlock()
        // Never wait for UI delivery in an ES callback or a network verdict.
        queue.async {
            DistributedNotificationCenter.default().postNotificationName(name, object: audience,
                userInfo: ["category": kind.rawValue], options: [.deliverImmediately, .postToAllSessions])
        }
    }
}
#endif
