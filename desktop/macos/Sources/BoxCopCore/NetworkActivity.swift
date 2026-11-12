import Foundation

public struct NetworkProcessMetadata: Codable, Sendable {
    public var pid: UInt32?
    public var uid: UInt32?
    public var incarnation: UInt32?
    public var executable: String?
    public var name: String?
    public var signingIdentifier: String?
    public var teamIdentifier: String?
    public var codeHash: String?
    public var signingFlags: UInt32?
    public var signingAuthorities: [String]?
    public var signingStatus = "unavailable"
    public var arguments: [String]?
    public var ancestors: [NetworkProcessAncestor]?
    public var metadataStatus = "unavailable"
    public init() {}
}
public struct NetworkProcessAncestor: Codable, Sendable {
    public let pid: UInt32
    public let executable: String?
    public init(pid: UInt32, executable: String?) { self.pid = pid; self.executable = executable }
}
public struct NetworkActivityEvent: Codable, Identifiable, Sendable {
    public let id: UUID
    public let timestamp: Date
    public var process: NetworkProcessMetadata
    public var responsibleApp: NetworkProcessMetadata
    public let remoteAddress: String?
    public let remotePort: String?
    public let localAddress: String?
    public let localPort: String?
    public let hostname: String?
    public let hostnameSource: String
    public let url: String?
    public let transport: String
    public let socketFamily: Int32?
    public let socketType: Int32?
    public let socketProtocol: Int32?
    public let flowType: String
    public let direction: String
    public let decision: String
    public let bootSessionID: String?
    public let threat: NetworkThreatMatch?
    public init(id: UUID = UUID(), timestamp: Date = Date(), remoteAddress: String?, remotePort: String?, localAddress: String?, localPort: String?, hostname: String?, hostnameSource: String, url: String?, transport: String, socketFamily: Int32?, socketType: Int32?, socketProtocol: Int32?, flowType: String, threat: NetworkThreatMatch? = nil, bootSessionID: String? = nil) {
        self.id = id; self.timestamp = timestamp; self.process = .init(); self.responsibleApp = .init()
        self.remoteAddress = remoteAddress; self.remotePort = remotePort; self.localAddress = localAddress; self.localPort = localPort
        self.hostname = hostname; self.hostnameSource = hostnameSource; self.url = url; self.transport = transport
        self.socketFamily = socketFamily; self.socketType = socketType; self.socketProtocol = socketProtocol; self.flowType = flowType
        self.direction = "outbound"; self.decision = threat == nil ? "observed_allowed" : "blocked_threat_domain"; self.threat = threat; self.bootSessionID = bootSessionID
    }
    /// Preserve attribution provenance. Never present an IP or reverse lookup as a verified domain.
    public static func destination(urlHost: String?, remoteHostname: String?) -> (name: String?, source: String) {
        if let host = urlHost, !host.isEmpty { return (String(host.prefix(512)), "flow_url") }
        if let host = remoteHostname, !host.isEmpty { return (String(host.prefix(512)), "flow_remote_hostname") }
        return (nil, "unavailable")
    }
}
public struct NetworkActivitySnapshot: Codable, Sendable {
    public var summary: NetworkActivitySummary?
    public var summaryError: String?
    public let mode: String
    public let events: [NetworkActivityEvent]
    public let observed: UInt64
    public let dropped: UInt64
    public let writeFailures: UInt64
    public let lastFlow: Date?
    public let startedAt: Date
    public let retentionBytes: Int
    public let threatProtection: NetworkThreatStatus?
    public let blocked: UInt64?
    public init(events: [NetworkActivityEvent], observed: UInt64, dropped: UInt64, writeFailures: UInt64, lastFlow: Date?, startedAt: Date, retentionBytes: Int, threatProtection: NetworkThreatStatus? = nil, blocked: UInt64 = 0) {
        mode = "observe_all"; self.events = events; self.observed = observed; self.dropped = dropped; self.writeFailures = writeFailures
        self.lastFlow = lastFlow; self.startedAt = startedAt; self.retentionBytes = retentionBytes
        self.threatProtection = threatProtection; self.blocked = blocked
    }
}
