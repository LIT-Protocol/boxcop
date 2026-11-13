import Foundation

/// ES audit tokens include process incarnation; a reused PID cannot inherit scope.
/// Called serially by the ES handler. Bounded to avoid untrusted process churn.
public struct CredentialProcessTracker {
    private var scoped: Set<Data> = []
    public private(set) var degraded = false
    private let capacity: Int
    public init(capacity: Int = 32768) { self.capacity = capacity }
    public mutating func scope(token: Data, parent: Data?, responsible: Data?, trustedAgent: Bool) -> CredentialProtectionPolicy.Scope {
        let inherited = parent.map { scoped.contains($0) } == true || responsible.map { scoped.contains($0) } == true
        guard trustedAgent || inherited || scoped.contains(token) else { return .unknown }
        if scoped.count < capacity || scoped.contains(token) { scoped.insert(token) }
        else { degraded = true }
        return .agent
    }
    public mutating func fork(parent: Data, child: Data) {
        _ = scope(token: child, parent: parent, responsible: nil, trustedAgent: false)
    }
    public mutating func exit(token: Data) { scoped.remove(token) }
    public mutating func lostEvents() { degraded = true }
}

public struct CredentialProtectionStatus: Codable, Sendable {
    public var enabled = false
    public var state: String
    public var detail: String
    public var blocked: UInt64 = 0
    public var unresolved: UInt64 = 0
    public var responseFailures: UInt64 = 0
    public var lastUnresolvedPath: String?
    public var events: [CredentialBlockEvent] = []
    public init(state: String, detail: String) { self.state = state; self.detail = detail }
}
public struct CredentialBlockEvent: Codable, Identifiable, Sendable {
    public let id: UUID
    public let date: Date
    public let process: String
    public let credential: String
    public init(process: String, credential: String) {
        id = UUID(); date = Date(); self.process = process; self.credential = credential
    }
}

public enum CredentialAgentIdentity {
    // Verified against installed Developer ID binaries. Keep both team AND ID.
    public static func recognized(team: String, identifier: String, flags: UInt32) -> Bool {
        let identities: Set<String> = [
            "Q6L2SF6YDW:com.anthropic.claudefordesktop",
            "Q6L2SF6YDW:com.anthropic.claude-code",
            "2DC432GLL2:codex",
            "VDXQ22DGB9:com.todesktop.230313mzl4w4u92"
        ]
        // CS_VALID and !CS_ADHOC from cs_blobs.h. Metadata must originate in ES.
        return flags & 0x1 != 0 && flags & 0x2 == 0 && identities.contains(team + ":" + identifier)
    }
}
