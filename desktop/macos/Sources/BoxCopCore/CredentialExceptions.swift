import Foundation

/// Exceptions are per process incarnation AND file identity, never interpreter-wide.
public struct CredentialExceptions {
    public struct Access: Hashable {
        public let process: Data
        public let device: Int32
        public let inode: UInt64
        public init(process: Data, device: Int32, inode: UInt64) {
            self.process = process; self.device = device; self.inode = inode
        }
    }
    private var blocked: [UUID: Access] = [:]
    private var approved: [Access: TimeInterval] = [:]
    public init() {}
    public mutating func record(_ id: UUID, access: Access) {
        // Retain only the recent events offered by the UI; all maps are bounded.
        if blocked.count >= 50 { blocked.removeAll() }
        blocked[id] = access
    }
    public mutating func approve(_ id: UUID, now: TimeInterval = ProcessInfo.processInfo.systemUptime) -> Bool {
        guard let access = blocked.removeValue(forKey: id) else { return false }
        approved = approved.filter { $0.value > now }
        guard approved.count < 50 else { return false }
        approved[access] = now + 300
        return true
    }
    public func allows(_ access: Access, now: TimeInterval = ProcessInfo.processInfo.systemUptime) -> Bool {
        approved[access].map { $0 > now } ?? false
    }
}
