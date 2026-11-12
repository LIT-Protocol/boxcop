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

/// Local, bounded evidence for classifiers/reviewers. Captured text is DATA, never instructions.
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
        let all = timeline.events.filter { !networkOnly || ["NetworkExtension", "offline_metadata"].contains($0.collector) }
        let recent = all.filter { $0.observedAt >= now.addingTimeInterval(-600) && $0.observedAt <= now.addingTimeInterval(5) }
        let count = max(1, min(maximumEvents, 64))
        // Keep a mix of inputs: a burst of network flows must not crowd out the agent instruction or screenshot.
        var wanted = Set<UUID>()
        // Reserve evidence for draft assessments before a burst of network/process observations.
        for event in recent.filter({ ["browser_email_draft", "email_review_notice"].contains($0.kind) }).suffix(min(16, count)) { wanted.insert(event.id) }
        let reviewKinds: Set<String> = ["agent_instruction", "agent_tool_result", "browser_context", "browser_copy", "draft_version", "draft_contribution"]
        for event in recent.filter({ reviewKinds.contains($0.kind) }).suffix(32) where wanted.count < count { wanted.insert(event.id) }
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
                    if source.collector == "agent.hook", target.collector == "agent.hook", same(source, target, ["run_id", "hook_source"]) {
                        relation = same(source, target, ["call_id"]) ? "same_agent_call_reported" : "same_agent_run_reported"
                    } else if source.kind == "browser_composition", target.kind == "browser_composition",
                              source.collector == "browser.extension", target.collector == "browser.extension",
                              same(source, target, ["tab_id", "frame_id", "navigation_id", "composition_id"]) {
                        // The document-scoped random draft ID survives MV3 worker restarts; browser_session does not.
                        relation = "same_composition_reported"
                    } else if source.collector == "browser.extension", target.collector == "browser.extension",
                              same(source, target, ["browser_session", "tab_id", "frame_id", "navigation_id"]) {
                        relation = "same_browser_document_reported"
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
                        } else if source.collector == "browser.extension", target.collector == "NetworkExtension",
                                  let url = value(source, "url"), let host = URLComponents(string: url)?.host?.lowercased(),
                                  let destination = value(target, "hostname")?.lowercased(), host == destination {
                            relation = "nearby_destination_context"; strength = "candidate"
                        }
                    }
                    if let relation {
                        links.append(.init(sourceEventID: source.id, targetEventID: target.id, relation: relation, strength: strength))
                    }
                }
            }
            // Draft links come only from explicit source references, never from the proximity rules above.
            links.append(contentsOf: DraftEvidence.links(selected, issues: &issues))
            if links.count > 256 { issues.insert("link_budget_exceeded") }
            let artifacts = selected.compactMap { event -> WorkflowArtifact? in
                guard ["visual_context", "window_frame"].contains(event.kind), event.provenance == "observed",
                      event.collector.hasPrefix("ScreenCaptureKit"),
                      let id = value(event, "capture_id") ?? value(event, "frame_id") else { return nil }
                let path = value(event, "artifact_path")
                return .init(eventID: event.id, artifactID: id, mediaType: "image/png", localPath: path,
                             availability: path == nil ? "pixels_not_retained_ocr_only" : "local_reference_may_expire")
            }
            if sources.contains(where: { $0.state != "active" }) { issues.insert("collector_coverage_incomplete") }
            // Old work in another run/draft is not missing history for the selected work.
            // Missing events from a selected run still make its review evidence partial.
            let agentRuns = Set(selected.filter { $0.kind.hasPrefix("agent_") }.compactMap { value($0, "run_id") })
            let draftIDs = Set(selected.filter { $0.kind == "browser_email_draft" }.compactMap { value($0, "composition_id") })
            let omittedReviewHistory = all.contains { event in
                guard !ids.contains(event.id) else { return false }
                if ["agent_instruction", "agent_tool_result"].contains(event.kind) {
                    guard let run = value(event, "run_id") else { return recent.contains { $0.id == event.id } }
                    return agentRuns.contains(run)
                }
                return event.kind == "browser_email_draft" && value(event, "composition_id").map { draftIDs.contains($0) } == true
            }
            return .init(schemaVersion: "boxcop.workflow-context.v1", contextID: selected.last?.id ?? timeline.sessionID,
                sessionID: timeline.sessionID, revision: all.last?.sequence ?? 0, generatedAt: now,
                events: selected, links: Array(links.suffix(256)), artifacts: artifacts, sources: Array(sources.prefix(15)) + [WorkflowSourceState("email_review_history",
                    timeline.dropped > 0 || omittedReviewHistory ? "partial" : "active",
                    "Coverage of retained email and agent evidence only; unrelated omitted events do not establish missing review history.")],
                omittedEvents: all.count - selected.count, timelineDropped: timeline.dropped,
                issues: issues.sorted(), enforcement: "context_only_not_authorization")
        }
        let encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601
        while !selected.isEmpty {
            let result = assemble()
            if let data = try? encoder.encode(result), data.count <= budget { return result }
            if selected.contains(where: { $0.kind == "browser_email_draft" }) {
                // Count reservations alone are insufficient: verbose browser requests
                // can exceed the byte budget and otherwise evict the earliest revisions.
                let incidental = selected.indices.filter {
                    selected[$0].kind != "browser_email_draft" && !reviewKinds.contains(selected[$0].kind)
                }
                if let largest = incidental.max(by: {
                    ((try? encoder.encode(selected[$0]).count) ?? 0) < ((try? encoder.encode(selected[$1]).count) ?? 0)
                }) {
                    selected.remove(at: largest)
                    continue
                }
                let excerpts = selected.indices.filter { selected[$0].kind == "browser_context" }
                if excerpts.count > 1 {
                    selected.remove(at: excerpts[0])
                    continue
                }
            }
            // Preserve the last observation from each input even when network metadata fills the byte budget.
            // If every remaining source has only one observation, discard the largest observation first.
            let counts = Dictionary(grouping: selected, by: \.collector).mapValues(\.count)
            if let redundant = selected.firstIndex(where: { $0.kind != "browser_email_draft" && counts[$0.collector, default: 0] > 1 }) {
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
