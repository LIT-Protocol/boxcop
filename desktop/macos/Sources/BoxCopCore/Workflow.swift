import Foundation

public struct WorkflowField: Codable, Equatable, Sendable {
    public let value: String?
    public let provenance: String
    public let availability: String
    public let truncated: Bool
    public init(_ value: String?, provenance: String = "observed", availability: String? = nil, truncated: Bool = false) {
        self.value = value.map { String(String.UnicodeScalarView($0.unicodeScalars.prefix(4096))) }
        self.provenance = provenance
        self.availability = availability ?? (value == nil ? "not_collected" : "available")
        self.truncated = truncated || (value?.unicodeScalars.count ?? 0) > 4096
    }
}

/// Evidence, separate from policy decisions. Per-field provenance survives export.
public struct WorkflowEvent: Codable, Identifiable, Equatable, Sendable {
    public let id: UUID
    public let sessionID: UUID
    public let sequence: Int
    public let observedAt: Date
    public let receivedAt: Date
    public let kind: String
    public let phase: String
    public let collector: String
    public let provenance: String
    public let bundleID: String?
    public let pid: Int32?
    public let windowTitle: String?
    public let availability: String
    public let fields: [String: WorkflowField]
    public let relatedEventIDs: [UUID]
}

public struct WorkflowTimeline: Sendable {
    public private(set) var events: [WorkflowEvent] = []
    public private(set) var dropped = 0
    public private(set) var sessionID = UUID()
    private var sequence = 0
    public var onAppend: (@Sendable (WorkflowEvent) -> Void)?
    public let capacity: Int
    public init(capacity: Int = 2000) { self.capacity = max(1, capacity) }
    public mutating func clear() { events = []; dropped = 0; sequence = 0; sessionID = UUID() }
    @discardableResult public mutating func append(kind: String, collector: String, bundleID: String? = nil, pid: Int32? = nil,
                                windowTitle: String? = nil, availability: String = "available", at: Date = Date(),
                                phase: String = "observed", provenance: String = "observed",
                                fields: [String: WorkflowField] = [:], relatedEventIDs: [UUID] = [], receivedAt: Date? = nil) -> UUID {
        let id = UUID()
        sequence += 1
        events.append(WorkflowEvent(id: id, sessionID: sessionID, sequence: sequence, observedAt: at, receivedAt: receivedAt ?? Date(),
                                    kind: kind, phase: phase, collector: collector, provenance: provenance,
                                    bundleID: bundleID, pid: pid, windowTitle: windowTitle.map { String($0.prefix(512)) },
                                    availability: availability, fields: fields, relatedEventIDs: Array(relatedEventIDs.prefix(16))))
        onAppend?(events[events.count - 1])
        if events.count > capacity { events.removeFirst(); dropped += 1 }
        return id
    }
    public func exportData(synthetic: Bool = false) throws -> Data {
        struct Export: Encodable {
            let schemaVersion = "boxcop.workflow.v2"
            let synthetic: Bool
            let retention = "This explicit export is the bounded in-memory timeline of network and protection events."
            let limitations = ["A connection event is an attempted flow, not proof that data was transferred.",
                               "Agent events are reported by cooperative hooks, not authenticated actors.",
                               "Event relations express nearby observed context, not proven causation."]
            let droppedEvents: Int
            let events: [WorkflowEvent]
        }
        let encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return try encoder.encode(Export(synthetic: synthetic, droppedEvents: dropped, events: events))
    }
}

public enum ContextURL {
    /// Strip userinfo, query and fragment: these commonly contain credentials or private search text.
    public static func sanitize(_ raw: String) -> String? {
        guard raw.count <= 8192, var url = URLComponents(string: raw),
              ["https", "http", "file"].contains(url.scheme?.lowercased() ?? "") else { return nil }
        if url.scheme != "file", url.host?.isEmpty != false { return nil }
        url.user = nil; url.password = nil; url.query = nil; url.fragment = nil
        return url.string.map { String($0.prefix(2048)) }
    }
}
