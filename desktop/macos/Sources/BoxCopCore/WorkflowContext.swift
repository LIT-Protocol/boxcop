import Foundation

public struct WorkflowLink: Codable, Equatable, Sendable {
    public let sourceEventID: String
    public let targetEventID: String
    public let relation: String
    public let strength: String
}

public struct WorkflowSourceState: Codable, Equatable, Sendable {
    public let source: String
    public let state: String
    public let detail: String
    public init(_ source: String, _ state: String, _ detail: String) {
        self.source = String(source.prefix(64)); self.state = String(state.prefix(64)); self.detail = String(detail.prefix(512))
    }
}

public struct WorkflowArtifact: Codable, Equatable, Sendable {
    public let eventID: String
    public let artifactID: String
    public let mediaType: String
    public let localPath: String?
    public let availability: String
}

/// Local, bounded evidence for the local reviewer. Captured text is DATA, never instructions.
/// Links do not authorize an action or establish that a payload was transmitted.
public struct WorkflowContext: Codable, Sendable {
    public let schemaVersion: String
    public let contextID: UUID
    public let sessionID: UUID
    public let revision: Int
    public let generatedAt: Date
    public let events: [WorkflowEvent]
    public let links: [WorkflowLink]
    public let artifacts: [WorkflowArtifact]
    public let sources: [WorkflowSourceState]
    public let omittedEvents: Int
    public let timelineDropped: Int
    public let issues: [String]
    public let enforcement: String

    public static func build(from timeline: WorkflowTimeline, sources: [WorkflowSourceState], now: Date = Date(),
                             maximumEvents: Int = 64, maximumBytes: Int = 96 * 1024, networkOnly: Bool = false) -> WorkflowContext {
        let all = timeline.events.filter { !networkOnly || $0.collector == "NetworkExtension" }
        let recent = all.filter { $0.observedAt >= now.addingTimeInterval(-600) && $0.observedAt <= now.addingTimeInterval(5) }
        let count = max(1, min(maximumEvents, 64))
        // Keep a mix of inputs: a burst of network flows must not crowd out protection decisions.
        var wanted = Set<String>()
        for event in recent.filter({ $0.kind == "security_event" }).suffix(32) where wanted.count < count { wanted.insert(event.id) }
        for event in recent.suffix(12) where wanted.count < count { wanted.insert(event.id) }
        for collector in Set(recent.map(\.collector)).sorted() {
            for event in recent.filter({ $0.collector == collector }).suffix(4) where wanted.count < count { wanted.insert(event.id) }
        }
        for event in recent.reversed() where wanted.count < count { wanted.insert(event.id) }
        var selected = recent.filter { wanted.contains($0.id) }.sorted {
            $0.observedAt == $1.observedAt ? $0.sequence < $1.sequence : $0.observedAt < $1.observedAt
        }
        let budget = max(16 * 1024, min(maximumBytes, 96 * 1024))
        func assemble() -> WorkflowContext {
            let ids = Set(selected.map(\.id))
            var links: [WorkflowLink] = []
            var issues = Set<String>()
            if selected.count < all.count { issues.insert("context_window_or_budget_omissions") }
            if timeline.dropped > 0 { issues.insert("timeline_retention_loss") }
            if all.contains(where: { $0.observedAt > now.addingTimeInterval(5) }) { issues.insert("future_event_timestamp") }
            for event in selected {
                if event.availability != "available" { issues.insert("partial_or_unavailable_observations") }
                if event.fields.values.contains(where: \.truncated) { issues.insert("truncated_fields") }
                for id in event.relatedEventIDs {
                    if ids.contains(id) { links.append(.init(sourceEventID: id, targetEventID: event.id, relation: "recorded_context", strength: "recorded_reference")) }
                    else { issues.insert("reference_outside_context") }
                }
            }
            func value(_ event: WorkflowEvent, _ key: String) -> String? {
                guard let field = event.fields[key], field.availability == "available", !field.truncated,
                      let value = field.value, !value.isEmpty else { return nil }
                return value
            }
            func same(_ a: WorkflowEvent, _ b: WorkflowEvent, _ keys: [String]) -> Bool {
                keys.allSatisfy { value(a, $0) != nil && value(a, $0) == value(b, $0) }
            }
            for (index, target) in selected.enumerated() {
                for source in selected.prefix(index).reversed() {
                    let delta = target.observedAt.timeIntervalSince(source.observedAt)
                    // Delivery order can differ from observation order; no inferred backwards context.
                    guard delta >= 0, delta <= 300 else { continue }
                    var relation: String?, strength = "shared_identifier"
                    if source.kind == "security_event", target.kind == "security_event", same(source, target, ["agent"]) {
                        relation = "same_agent_reported"
                    } else if source.collector == "NetworkExtension", target.collector == "NetworkExtension",
                              source.pid == target.pid, source.pid != nil,
                              same(source, target, ["boot_session_id", "pid_version", "effective_uid"]) {
                        relation = "same_kernel_process_instance"
                    } else if delta <= 5 {
                        let a = source.pid.map(String.init) ?? value(source, "process_id")
                        let b = target.pid.map(String.init) ?? value(target, "process_id")
                        let responsible = value(target, "responsible_pid")
                        if a != nil && (a == b || a == responsible) {
                            relation = "nearby_process_context"; strength = "candidate"
                        } else if source.kind == "security_event", target.collector == "NetworkExtension",
                                  let destination = value(target, "hostname")?.lowercased(),
                                  let subject = value(source, "subject")?.lowercased(), EngineObservation.names(destination, in: subject) {
                            relation = "nearby_destination_context"; strength = "candidate"
                        }
                    }
                    if let relation {
                        links.append(.init(sourceEventID: source.id, targetEventID: target.id, relation: relation, strength: strength))
                    }
                }
            }
            if links.count > 256 { issues.insert("link_budget_exceeded") }
            if sources.contains(where: { $0.state != "active" }) { issues.insert("collector_coverage_incomplete") }
            // The context is named after its newest observation that has a UUID; engine decisions carry their own ids.
            let named = selected.reversed().lazy.compactMap { UUID(uuidString: $0.id) }.first
            return .init(schemaVersion: "boxcop.workflow-context.v1", contextID: named ?? timeline.sessionID,
                sessionID: timeline.sessionID, revision: all.last?.sequence ?? 0, generatedAt: now,
                events: selected, links: Array(links.suffix(256)), artifacts: [], sources: Array(sources.prefix(16)),
                omittedEvents: all.count - selected.count, timelineDropped: timeline.dropped,
                issues: issues.sorted(), enforcement: "context_only_not_authorization")
        }
        let encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601
        while !selected.isEmpty {
            let result = assemble()
            if let data = try? encoder.encode(result), data.count <= budget { return result }
            // Preserve the last observation from each input even when network metadata fills the byte budget.
            // If every remaining source has only one observation, discard the largest observation first.
            let counts = Dictionary(grouping: selected, by: \.collector).mapValues(\.count)
            if let redundant = selected.firstIndex(where: { counts[$0.collector, default: 0] > 1 }) {
                selected.remove(at: redundant)
            } else if let largest = selected.indices.max(by: {
                ((try? encoder.encode(selected[$0]).count) ?? 0) < ((try? encoder.encode(selected[$1]).count) ?? 0)
            }) { selected.remove(at: largest) }
        }
        return assemble()
    }
    public func exportData() throws -> Data {
        let encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(self)
    }
}

/// How an engine `security_events` row enters the triage timeline, and how a finding finds its way back to an Events row.
public enum EngineObservation {
    public static let prefix = "engine:"
    public static let collector = "BoxCopEngine"
    static let provenance = "engine_record"

    /// `engine:<event id>`, which is also the id of the matching row in the Events list. Nil when the id cannot be cited safely.
    public static func id(_ event: SecurityEvent) -> String? {
        valid(event.id) ? prefix + event.id : nil
    }
    static func valid(_ raw: String) -> Bool {
        (1...64).contains(raw.utf8.count) && raw.utf8.allSatisfy { ($0 >= 48 && $0 <= 57) || ($0 >= 65 && $0 <= 90) || ($0 >= 97 && $0 <= 122) || $0 == 45 }
    }
    /// True for an id a judgment may cite: a UUID or an engine event id.
    public static func citable(_ id: String) -> Bool {
        id.hasPrefix(prefix) ? valid(String(id.dropFirst(prefix.count))) : UUID(uuidString: id) != nil
    }

    /// Only what the Events row already shows. A value the engine did not report is left out, not sent as null.
    public static func fields(_ event: SecurityEvent) -> [String: WorkflowField] {
        var fields: [String: WorkflowField] = [:]
        func set(_ name: String, _ value: String?, limit: Int) {
            guard let value, !value.isEmpty else { return }
            let scalars = value.unicodeScalars
            fields[name] = WorkflowField(String(String.UnicodeScalarView(scalars.prefix(limit))), provenance: provenance, truncated: scalars.count > limit)
        }
        set("layer", event.layer.rawValue, limit: 32); set("outcome", event.outcome.rawValue, limit: 32)
        set("title", event.title, limit: 300); set("reason", event.reason, limit: 600)
        set("subject", event.subject, limit: 512); set("agent", event.agent, limit: 64)
        return fields
    }

    /// Adds the decision to the timeline once. Returns its timeline id, or nil when it was skipped.
    @discardableResult public static func append(_ event: SecurityEvent, to timeline: inout WorkflowTimeline) -> String? {
        guard let id = id(event), !timeline.events.contains(where: { $0.id == id }) else { return nil }
        return timeline.append(id: id, kind: "security_event", collector: collector, at: event.time, phase: "observed",
                               provenance: provenance, fields: fields(event))
    }

    /// The Events row a timeline observation belongs to: engine decisions by their own id, connections by the network event id.
    public static func rowID(for event: WorkflowEvent) -> String? {
        if event.kind == "security_event", event.id.hasPrefix(prefix) { return event.id }
        if event.kind == "network_connection", let id = event.fields["network_event_id"]?.value { return "network:" + id }
        return nil
    }

    /// One explanation per Events row, from the findings that cite it. `rows` maps timeline ids to row ids.
    public static func explanations(_ findings: [WorkflowJudgmentStatus.Finding], rows: [String: String]) -> [String: String] {
        var notes: [String: String] = [:]
        for finding in findings {
            let text = [finding.summary, finding.recommendation].map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }.joined(separator: " ")
            guard !text.isEmpty else { continue }
            for id in finding.eventIDs {
                // An engine decision is cited by the id of its own row, so it resolves even after the timeline has moved on.
                guard let row = rows[id] ?? (id.hasPrefix(prefix) && citable(id) ? id : nil) else { continue }
                if let existing = notes[row] { if !existing.contains(text) { notes[row] = existing + " " + text } }
                else { notes[row] = text }
            }
        }
        return notes
    }

    /// Whether `subject` names `host` as a whole host, e.g. `pkg@1.0 → host:443`.
    static func names(_ host: String, in subject: String) -> Bool {
        guard !host.isEmpty else { return false }
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-."))
        return subject.components(separatedBy: allowed.inverted).contains(host)
    }
}
