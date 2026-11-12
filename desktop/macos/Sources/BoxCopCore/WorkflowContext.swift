import Foundation

public struct WorkflowLink: Codable, Equatable, Sendable {
    public let sourceEventID: UUID
    public let targetEventID: UUID
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
    public let eventID: UUID
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
        var wanted = Set<UUID>()
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
                                  let host = value(source, "host")?.lowercased(),
                                  let destination = value(target, "hostname")?.lowercased(), host == destination {
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
            return .init(schemaVersion: "boxcop.workflow-context.v1", contextID: selected.last?.id ?? timeline.sessionID,
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
