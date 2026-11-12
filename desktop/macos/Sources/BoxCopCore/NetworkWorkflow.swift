import Foundation

/// Pages the durable network journal, rather than silently treating the latest 100 UI rows as a stream.
public struct NetworkWorkflowPage: Codable, Sendable {
    public let events: [NetworkActivityEvent]
    public let cursor: UUID?
    public let hasMore: Bool
    public let cursorExpired: Bool
    public let oversizedRecords: Int
    public let loggingDropped: UInt64
    public let writeFailures: UInt64
    public let providerStartedAt: Date
    public init(retained: [NetworkActivityEvent], after: UUID?, loggingDropped: UInt64, writeFailures: UInt64, providerStartedAt: Date) {
        let index = after.flatMap { id in retained.firstIndex { $0.id == id } }
        cursorExpired = after != nil && index == nil
        let start = index.map { $0 + 1 } ?? 0
        var page: [NetworkActivityEvent] = [], bytes = 0, consumed = 0, oversized = 0
        let encoder = JSONEncoder()
        for event in retained.dropFirst(start).prefix(64) {
            let size = (try? encoder.encode(event).count) ?? Int.max
            if size > 2 * 1024 * 1024 { consumed += 1; oversized += 1; continue }
            if bytes + size > 2 * 1024 * 1024 { break }
            page.append(event); bytes += size; consumed += 1
        }
        events = page; oversizedRecords = oversized
        cursor = consumed > 0 ? retained[start + consumed - 1].id : after
        hasMore = start + consumed < retained.count
        self.loggingDropped = loggingDropped; self.writeFailures = writeFailures; self.providerStartedAt = providerStartedAt
    }
}

public struct NetworkWorkflowImporter: Sendable {
    public private(set) var cursor: UUID?
    private var seen: Set<UUID> = []
    private var order: [UUID] = []
    private var notBefore = Date.distantPast
    private var lastHealth = ""
    public init() {}
    public mutating func clear(at: Date = Date()) { notBefore = at }
    public mutating func ingest(_ page: NetworkWorkflowPage, into timeline: inout WorkflowTimeline) {
        let health = "\(page.providerStartedAt.timeIntervalSince1970):\(page.loggingDropped):\(page.writeFailures):\(page.cursorExpired):\(page.oversizedRecords)"
        if health != lastHealth {
            timeline.append(kind: "collector_health", collector: "NetworkExtension",
                availability: page.cursorExpired || page.loggingDropped > 0 || page.writeFailures > 0 || page.oversizedRecords > 0 ? "incomplete" : "available",
                fields: ["cursor_expired": WorkflowField(String(page.cursorExpired)),
                         "oversized_records": WorkflowField(String(page.oversizedRecords)),
                         "log_dropped": WorkflowField(String(page.loggingDropped)), "write_failures": WorkflowField(String(page.writeFailures)),
                         "history_scope": WorkflowField("Retained network journal only; prior rotated records are unavailable")])
            lastHealth = health
        }
        for event in page.events {
            guard !seen.contains(event.id) else { continue }
            seen.insert(event.id); order.append(event.id)
            if order.count > 4096 { seen.remove(order.removeFirst()) }
            guard event.timestamp >= notBefore else { continue }
            let process = event.process
            var fields: [String: WorkflowField] = [
                "network_event_id": WorkflowField(event.id.uuidString), "decision": WorkflowField(event.decision),
                "hostname": WorkflowField(event.hostname, provenance: "os_supplied"), "hostname_source": WorkflowField(event.hostnameSource),
                "remote_address": WorkflowField(event.remoteAddress), "remote_port": WorkflowField(event.remotePort),
                "local_address": WorkflowField(event.localAddress), "local_port": WorkflowField(event.localPort),
                "transport": WorkflowField(event.transport), "direction": WorkflowField(event.direction),
                "url": WorkflowField(event.url.flatMap(ContextURL.sanitize), provenance: "os_supplied_sanitized"),
                "executable": WorkflowField(process.executable), "effective_uid": WorkflowField(process.uid.map(String.init)),
                "pid_version": WorkflowField(process.incarnation.map(String.init)), "boot_session_id": WorkflowField(event.bootSessionID),
                "signing_id": WorkflowField(process.signingIdentifier), "team_id": WorkflowField(process.teamIdentifier),
                "signing_status": WorkflowField(process.signingStatus), "code_hash": WorkflowField(process.codeHash),
                "responsible_pid": WorkflowField(event.responsibleApp.pid.map(String.init)),
                "responsible_executable": WorkflowField(event.responsibleApp.executable),
                "process_metadata": WorkflowField(process.metadataStatus),
                "transfer_outcome": WorkflowField(nil, provenance: "unknown", availability: "not_observed")]
            if let args = process.arguments, let data = try? JSONEncoder().encode(args) {
                fields["process_arguments"] = WorkflowField(String(decoding: data, as: UTF8.self))
            }
            if let ancestors = process.ancestors, let data = try? JSONEncoder().encode(ancestors) {
                fields["process_ancestors"] = WorkflowField(String(decoding: data, as: UTF8.self))
            }
            if let threat = event.threat {
                fields["threat_hostname"] = WorkflowField(threat.hostname)
                fields["threat_source"] = WorkflowField(threat.source)
                fields["threat_revision"] = WorkflowField(threat.revision)
                fields["threat_reason"] = WorkflowField(threat.reason)
            }
            timeline.append(kind: "network_connection", collector: "NetworkExtension", pid: process.pid.flatMap(Int32.init(exactly:)),
                at: event.timestamp, phase: "attempted", fields: fields)
        }
        cursor = page.cursor
    }
}
