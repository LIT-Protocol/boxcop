import Foundation
import CoreFoundation

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
            let retention = "This explicit export is the bounded UI timeline. Development collection also writes a rotating local journal. Screenshots are separate artifacts."
            let limitations = ["FSEvents reports changes, not file reads or the responsible process.",
                               "App-provided titles and browser DOM are untrusted content, not verified identity.",
                               "Browser/agent adapter events are reported by same-user clients, not authenticated actors.",
                               "Paste/upload attempts are not confirmation of insertion or network egress.",
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

/// Narrow collection-only ingress. This never executes commands or authorizes actions.
public struct AdapterEvent: Sendable {
    public let kind: String
    public let collector: String
    public let phase: String
    public let fields: [String: WorkflowField]
    /// Source observation time, reported only by kinds that carry `observed_at_ms` (compositions).
    public var observedAt: Date? = nil
    /// Taken when the frame is decoded on the receiving queue, before any main-actor hop.
    public let receivedAt: Date
    public static let maximumBytes = 65536
    public static func decode(_ bytes: Data) throws -> AdapterEvent {
        guard bytes.count <= maximumBytes else { throw AdapterError.invalid }
        var validator = try StrictJSON(bytes); try validator.validate()
        guard let object = try JSONSerialization.jsonObject(with: bytes) as? [String: Any],
              Set(object.keys) == ["version", "kind", "fields"],
              let version = object["version"] as? Int, version == 1,
              CFGetTypeID(object["version"] as CFTypeRef) != CFBooleanGetTypeID(),
              let kind = object["kind"] as? String,
              let input = object["fields"] as? [String: String] else { throw AdapterError.invalid }
        if ["browser_email_draft", "email_review_status"].contains(kind) { return try EmailReviewEvidence.decode(kind: kind, input: input) }
        if DraftEvidence.kinds.contains(kind) { return try DraftEvidence.decode(kind: kind, input: input) }
        let browserKinds: Set<String> = ["browser_navigation", "browser_copy", "browser_paste", "browser_click", "browser_file_selected", "browser_upload", "browser_download", "browser_context", "browser_focus", "browser_request", "browser_composition", "browser_pdf_selected"]
        let agentKinds: Set<String> = ["agent_instruction", "agent_tool_call", "agent_tool_result"]
        guard browserKinds.contains(kind) || agentKinds.contains(kind) else { throw AdapterError.invalid }
        let browserKeys: Set<String> = ["url", "page_title", "tab_id", "frame_id", "element_role", "element_label", "selected_text", "account_scope", "account_evidence", "file_name", "file_size", "mime_type", "navigation_id", "context_text", "context_truncated", "download_id", "transfer_state", "bytes_received", "referrer", "browser_session", "request_id", "request_method", "request_type", "status_code", "network_error", "initiator", "observed_at_ms"]
        let agentKeys: Set<String> = ["run_id", "parent_id", "tool", "instruction", "arguments", "result_summary", "status", "resource", "process_id", "duration_ms", "call_id", "hook_source", "code_evidence"]
        let pdfKeys: Set<String> = ["url", "tab_id", "frame_id", "navigation_id", "browser_session", "account_scope", "account_evidence", "file_name", "file_size", "mime_type", "artifact_sha256", "selection_id", "observed_at_ms"]
        guard Set(input.keys).isSubset(of: kind == "browser_pdf_selected" ? pdfKeys : kind == "browser_composition" ? compositionKeys : browserKinds.contains(kind) ? browserKeys : agentKeys), input.count <= 16,
              input.values.allSatisfy({ $0.count <= 4096 }) else { throw AdapterError.invalid }
        if kind == "browser_pdf_selected" {
            guard let raw = input["url"], let url = URL(string: raw), url.scheme == "https", url.host == "mail.google.com",
                  input["frame_id"] == "0", input["mime_type"] == "application/pdf",
                  let hash = input["artifact_sha256"], let count = input["file_size"].flatMap(Int.init),
                  PDFContentIdentity(sha256: hash, byteCount: count) != nil,
                  input["selection_id"].flatMap(UUID.init(uuidString:)) != nil,
                  let stamp = input["observed_at_ms"].flatMap(Double.init), stamp.isFinite,
                  ["navigation_id", "browser_session", "tab_id", "file_name"].allSatisfy({ input[$0]?.isEmpty == false }) else { throw AdapterError.invalid }
        }
        if kind == "browser_composition" { try validateComposition(input) }
        // Browser-side time stamped before the native queue (epoch milliseconds).
        if let stamp = input["observed_at_ms"], stamp.range(of: "^[1-9][0-9]{12}$", options: .regularExpression) == nil {
            throw AdapterError.invalid
        }
        if agentKinds.contains(kind), input["run_id"]?.isEmpty != false { throw AdapterError.invalid }
        var fields = input.mapValues { WorkflowField($0, provenance: "reported") }
        let clipped = input["status"]?.contains("truncated") == true || input["context_truncated"] == "true"
        for key in ["instruction", "arguments", "result_summary", "context_text", "selected_text"] {
            if let text = input[key] {
                fields[key] = WorkflowField(text == "[not retained]" ? nil : text, provenance: "reported",
                    availability: text == "[not retained]" ? "not_retained_by_source" : clipped ? "truncated" : "available", truncated: clipped)
            }
        }
        for name in ["url", "referrer", "initiator"] {
          if let raw = input[name] {
            guard let clean = ContextURL.sanitize(raw), clean.hasPrefix("https://") || clean.hasPrefix("http://") else { throw AdapterError.invalid }
            fields[name] = WorkflowField(clean, provenance: "reported")
          }
        }
        if browserKinds.contains(kind), fields["url"] == nil { throw AdapterError.invalid }
        if let scope = input["account_scope"], !["managed", "personal", "unknown"].contains(scope) { throw AdapterError.invalid }
        if browserKinds.contains(kind) {
            let scope = input["account_scope"]
            let declared = scope == "managed" || scope == "personal"
            fields["account_scope"] = WorkflowField(declared ? scope : nil, provenance: declared ? "declared" : "unknown")
        }
        let attempted = ["browser_paste", "browser_upload", "agent_tool_call"].contains(kind) || input["composition_phase"] == "send_attempted"
        return AdapterEvent(kind: kind, collector: browserKinds.contains(kind) ? "browser.extension" : "agent.hook",
                            phase: attempted ? "attempted" : "observed", fields: fields,
                            observedAt: input["observed_at_ms"].flatMap(Double.init).map { Date(timeIntervalSince1970: $0 / 1000) }, receivedAt: Date())
    }
    /// Gmail draft lifecycle: closed vocabulary only. No text, titles, recipients, lengths or digests.
    static let compositionKeys: Set<String> = ["url", "tab_id", "frame_id", "navigation_id", "browser_session", "account_scope",
        "account_evidence", "composition_id", "composition_phase", "composition_surface", "content_state", "content_origin",
        "send_signal", "revision", "observed_at_ms"]
    static let compositionVocabulary: [String: Set<String>] = [
        "composition_phase": ["opened", "prepared", "send_attempted", "closed"],
        "composition_surface": ["dialog", "inline", "other"],
        "content_state": ["empty", "nonempty"],
        "content_origin": ["typed", "pasted", "dropped", "inserted", "opened_with_content"],
        "send_signal": ["shortcut", "send_control"]]
    private static func validateComposition(_ input: [String: String]) throws {
        func matches(_ value: String?, _ pattern: String) -> Bool { value?.range(of: pattern, options: .regularExpression) != nil }
        for (key, values) in compositionVocabulary { if let value = input[key], !values.contains(value) { throw AdapterError.invalid } }
        guard let phase = input["composition_phase"], input["composition_surface"] != nil, input["content_state"] != nil,
              matches(input["composition_id"], "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"),
              matches(input["revision"], "^[1-9][0-9]{0,5}$"), matches(input["observed_at_ms"], "^[1-9][0-9]{12}$"),
              matches(input["tab_id"], "^[0-9]{1,12}$"), input["frame_id"] == "0",
              matches(input["navigation_id"], "^[A-Za-z0-9_-]{1,128}$"),
              (input["content_origin"] != nil) == (phase == "prepared"), (input["send_signal"] != nil) == (phase == "send_attempted"),
              let raw = input["url"], let url = URLComponents(string: raw), url.scheme?.lowercased() == "https",
              url.host?.lowercased() == "mail.google.com" else { throw AdapterError.invalid }
    }
}
public enum AdapterError: Error { case invalid }
