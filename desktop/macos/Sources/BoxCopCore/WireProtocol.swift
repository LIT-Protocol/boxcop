import Foundation

public enum EventKind: String, Codable, Sendable { case clipboardCopy = "clipboard_copy", pasteAttempt = "paste_attempt", pastePreparation = "paste_prepare" }

/// Transient outbound payload only; never persist, display or log this type.
public struct DesktopEvent: Encodable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let kind: EventKind
    private let content: String
    private let appBundleID: String
    private let appPID: Int32
    private let role: Role
    enum CodingKeys: String, CodingKey { case kind, content, appBundleID = "app_bundle_id", appPID = "app_pid", role }
    public init(kind: EventKind, content: String, bundleID: String, pid: Int32, role: Role) throws {
        guard content.unicodeScalars.prefix(4097).count <= 4096, IdentityValidation.bundle(bundleID), pid > 0 else { throw EngineFailure.invalidRequest }
        self.kind = kind; self.content = content; appBundleID = bundleID; appPID = pid; self.role = role
    }
    public var description: String { "DesktopEvent(transient content omitted)" }
    public var debugDescription: String { description }
}

public enum PackageProtectionAction: String, Sendable { case status, enable, disable }
public struct PackageProtectionStatus: Decodable, Sendable {
    public let configured: Bool, routed: Bool, active: Bool, busy: Bool, stale: Bool
    public let summary: String
    public let generatedAt: String?, updateError: String?
    enum CodingKeys: String, CodingKey {
        case configured, routed, active, busy, stale, summary
        case generatedAt = "generated_at", updateError = "update_error"
    }
}

public enum ScriptProtectionAction: String, Sendable { case status, enable, disable, allow, revoke }
/// One refused connection from a contained package install script. `message` describes only what was blocked.
public struct BlockedScriptConnection: Decodable, Sendable, Identifiable, Equatable {
    public let id: String, time: String, host: String, message: String
    public let package: String?, version: String?, event: String?, agent: String?, project: String?
    public let port: Int, count: Int
    // The wire protocol reserves "version" for integers.
    enum CodingKeys: String, CodingKey { case id, time, host, message, package, version = "package_version", event, agent, project, port, count }
}
public struct ScriptDestinationException: Decodable, Sendable, Hashable {
    public let package: String, host: String
}
public struct ScriptProtectionStatus: Decodable, Sendable {
    public let routed: Bool, active: Bool
    public let summary: String
    public let blocked: [BlockedScriptConnection]
    public let exceptions: [ScriptDestinationException]
}

public enum EngineCommand: Sendable, CustomStringConvertible {
    case packageProtection(PackageProtectionAction)
    case scriptProtection(ScriptProtectionAction, package: String = "", host: String = "")
    case status, evaluate(DesktopEvent), recent(Int), policies, shutdown, workflowContext(WorkflowContext), workflowClear
    public var operation: String {
        switch self { case .packageProtection: return "package_protection"; case .scriptProtection: return "script_protection"; case .workflowContext: return "workflow_context"; case .workflowClear: return "workflow_clear"; case .status: return "status"; case .evaluate: return "evaluate"; case .recent: return "recent"; case .policies: return "policies"; case .shutdown: return "shutdown" }
    }
    public var description: String { operation }
}
private struct Request: Encodable {
    let id: String
    let command: EngineCommand
    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: WireKey.self)
        try c.encode(1, forKey: WireKey("version")); try c.encode(id, forKey: WireKey("id"))
        try c.encode(command.operation, forKey: WireKey("op"))
        switch command {
        case let .packageProtection(action): try c.encode(action.rawValue, forKey: WireKey("action"))
        case let .scriptProtection(action, package, host):
            guard package.utf8.count <= 255, host.utf8.count <= 255 else { throw EngineFailure.invalidRequest }
            try c.encode(action.rawValue, forKey: WireKey("action"))
            try c.encode(package, forKey: WireKey("package")); try c.encode(host, forKey: WireKey("host"))
        case let .workflowContext(context): try c.encode(context, forKey: WireKey("context"))
        case let .evaluate(event): try c.encode(event, forKey: WireKey("event"))
        case let .recent(limit):
            guard (1...100).contains(limit) else { throw EngineFailure.invalidRequest }
            try c.encode(limit, forKey: WireKey("limit"))
        default: break
        }
    }
}

public struct SafeRecord: Decodable, Identifiable, Sendable {
    public let id: UUID
    public let createdAt: Date
    public let bundleID: String?
    public let kind: EventKind
    public let action: DecisionAction
    public let policyIDs: [String]
    public var reasons: [String] { policyIDs.isEmpty ? ["No enabled narrow rule matched. This is not a safety guarantee."] : policyIDs.map { PolicyReason.text($0) } }
    public init(from decoder: Decoder) throws {
        let c = try decoder.object(["id", "created_at", "synthetic", "event", "decision"])
        let identifier: String = try c.field("id")
        guard let id = UUID(uuidString: identifier), try c.field("synthetic", as: Bool.self) == false else { throw EngineFailure.protocolViolation }
        self.id = id
        let timestamp: String = try c.field("created_at")
        let formatter = ISO8601DateFormatter(); formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        guard timestamp.count <= 40, let date = formatter.date(from: timestamp) else { throw EngineFailure.protocolViolation }
        createdAt = date
        let event: SanitizedEvent = try c.field("event")
        bundleID = event.bundleID; kind = event.kind
        let decision: SanitizedDecision = try c.field("decision")
        action = decision.action; policyIDs = decision.policyIDs
    }
}
private struct SanitizedEvent: Decodable {
    let bundleID: String?
    let kind: EventKind
    init(from decoder: Decoder) throws {
        let c = try decoder.object(["session_id", "actor", "role", "action", "app", "source", "destination", "content", "declared_intent", "synthetic"])
        guard try c.field("content", as: String.self) == "[not retained]", try c.field("synthetic", as: Bool.self) == false,
              try c.field("actor", as: String.self) == "human" else { throw EngineFailure.protocolViolation }
        let _: Role = try c.field("role")
        let action: String = try c.field("action")
        guard ["copy", "paste"].contains(action) else { throw EngineFailure.protocolViolation }
        let intent: String = try c.field("declared_intent")
        kind = action == "copy" ? .clipboardCopy : (intent == "Prospective paste policy prepared; no shortcut or transfer observed." ? .pastePreparation : .pasteAttempt)
        let app: String = try c.field("app")
        guard IdentityValidation.bundle(app) || (app.count <= 1024 && app.contains("[not retained]")) || app == "[empty after sanitizing]" else { throw EngineFailure.protocolViolation }
        bundleID = IdentityValidation.bundle(app) ? app : nil
        // These fields are type-checked but intentionally not retained or presented.
        for field in ["session_id", "source", "destination", "declared_intent"] { let _: String = try c.field(field) }
    }
}
private struct SanitizedDecision: Decodable {
    let action: DecisionAction
    let policyIDs: [String]
    init(from decoder: Decoder) throws {
        let c = try decoder.object(["action", "risk_score", "summary", "reasons", "policy_ids", "labels", "redacted_content", "latency_ms", "context_event_ids", "engine"])
        guard try c.field("redacted_content", as: String.self) == "[not retained]", try c.field("engine", as: String.self) == "rules+sequence" else { throw EngineFailure.protocolViolation }
        action = try c.field("action"); policyIDs = try c.field("policy_ids")
        guard policyIDs.count <= 32, policyIDs.allSatisfy({ PolicyReason.known.contains($0) }) else { throw EngineFailure.protocolViolation }
        let risk: Double = try c.field("risk_score"); let latency: Double = try c.field("latency_ms")
        guard risk.isFinite, (0...100).contains(risk), latency.isFinite, latency >= 0 else { throw EngineFailure.protocolViolation }
        let _: String = try c.field("summary")
        for field in ["reasons", "labels", "context_event_ids"] { let _: [String] = try c.field(field) }
    }
}

public enum PolicyReason {
    public static func recovery(_ action: DecisionAction) -> String {
        switch action {
        case .allow: return "Return to the destination and press Command-V. If the decision expired, BoxCop evaluates again."
        case .warn, .block: return "Remove sensitive values in the source, copy the revised text, then return to the intended destination and press Command-V. Repeating unchanged text will stay held. No approval override is available."
        }
    }
    public static let known: Set<String> = ["skill-instruction-override", "skill-concealed-action", "skill-credential-egress", "skill-remote-execution", "known-malicious-package", "vulnerable-runtime", "unsupported-runtime", "unresolved-runtime-version", "native-sensitive-file", "secret-egress", "sensitive-egress", "high-risk-pii", "pii-egress", "sensitive-local", "ambiguous-command-text", "remote-shell", "download-then-exec", "command-sensitive-egress", "credential-file-egress", "credential-file-access", "destructive-command", "recursive-delete", "role-shell", "sensitive-lineage"]
    public static func text(_ id: String) -> String {
        switch id {
        case "skill-instruction-override": return "Agent input asks to override higher-priority instructions or disable safeguards. Review the source before use."
        case "skill-concealed-action": return "Agent input asks to conceal actions from the user. Review the source before use."
        case "skill-credential-egress": return "Agent input combines a credential-store reference and a network tool. Review the source before use."
        case "skill-remote-execution": return "Agent input contains a remote or decoded execution pattern. Review the source before use."
        case "known-malicious-package": return "This exact package release is known to contain malware. Use a reviewed release and investigate any previous execution."
        case "vulnerable-runtime": return "This upstream PHP version predates critical security fixes. Install a patched release before serving web requests."
        case "unsupported-runtime", "unresolved-runtime-version": return "Verify the exact PHP release and vendor patch status before installing this runtime."
        case "ambiguous-command-text": return "This executable input contains invisible formatting or terminal control characters. Remove them and review the visible command before retrying."
        case "remote-shell", "download-then-exec": return "This terminal paste contains a recognizable download or decode followed by execution. Inspect the script separately instead of running it from the clipboard."
        case "secret-egress": return "Recognizable credentials or private keys target an external or unknown destination."
        case "sensitive-egress": return "Recognizable medical, personnel or restricted business information targets an external or unknown destination."
        case "high-risk-pii": return "An SSN-like identifier targets an external or unknown destination."
        case "pii-egress": return "Recognizable contact information needs a destination and consent review."
        case "sensitive-local": return "Recognizable sensitive content was observed locally."
        case "sensitive-lineage": return "An ephemeral exact-content match links this attempt to a sensitive copy in this session."
        default: return "An enabled deterministic policy requires review."
        }
    }
}
public struct SafePolicy: Decodable, Identifiable, Sendable {
    public let id: String
    public let enabled: Bool
    public let action: DecisionAction
    public var reason: String { PolicyReason.text(id) }
    public init(from decoder: Decoder) throws {
        let c = try decoder.object(["id", "name", "description", "action", "enabled"])
        id = try c.field("id"); enabled = try c.field("enabled"); action = try c.field("action")
        guard PolicyReason.known.contains(id) else { throw EngineFailure.protocolViolation }
        let _: String = try c.field("name"); let _: String = try c.field("description")
    }
}
public struct ModelBackendUsage: Decodable, Sendable {
    public let attempts: Int, ready: Int, uncertain: Int, unsupported: Int, unavailable: Int, errors: Int
    public init(from decoder: Decoder) throws {
        let c = try decoder.object(["attempts", "ready", "uncertain", "unsupported", "unavailable", "error"])
        attempts = try c.field("attempts")
        guard attempts >= 0 else { throw EngineFailure.protocolViolation }
        var remaining = attempts
        for name in ["ready", "uncertain", "unsupported", "unavailable", "error"] {
            let count: Int = try c.field(name)
            guard count >= 0, count <= remaining else { throw EngineFailure.protocolViolation }
            remaining -= count
        }
        // Unfinished attempts can survive a terminated engine. Never claim that
        // attempts are successful classifications or observed transfers.
        ready = try c.field("ready"); uncertain = try c.field("uncertain")
        unsupported = try c.field("unsupported"); unavailable = try c.field("unavailable"); errors = try c.field("error")
    }
}
public struct ModelUsageStatus: Decodable, Sendable {
    public let persistenceOK: Bool
    public let minilm: ModelBackendUsage, qwen: ModelBackendUsage
    public init(from decoder: Decoder) throws {
        let c = try decoder.object(["persistence_ok", "backends"])
        persistenceOK = try c.field("persistence_ok")
        let backends = try c.superDecoder(forKey: WireKey("backends")).object(["minilm-head-v1", "qwen3.5-4b-workflow-v2"])
        minilm = try backends.field("minilm-head-v1"); qwen = try backends.field("qwen3.5-4b-workflow-v2")
    }
}
public struct ClassificationStatus: Decodable, Sendable {
    public let hits: Int, misses: Int, ready: Int, unavailable: Int, uncertain: Int, queued: Int
    public let modelUsage: ModelUsageStatus?
    public init(from decoder: Decoder) throws {
        let peek = try decoder.container(keyedBy: WireKey.self)
        var keys: Set<String> = ["hits", "misses", "coalesced", "dropped", "completed", "failures", "queued", "cached", "active", "shadow_only", "ready", "unavailable", "uncertain"]
        if peek.contains(WireKey("model_usage")) { keys.insert("model_usage") }
        let c = try decoder.object(keys)
        for name in ["hits", "misses", "coalesced", "dropped", "completed", "failures", "queued", "cached", "ready", "unavailable", "uncertain"] {
            guard try c.field(name, as: Int.self) >= 0 else { throw EngineFailure.protocolViolation }
        }
        guard try c.field("shadow_only", as: Bool.self) else { throw EngineFailure.protocolViolation }
        let _: Bool = try c.field("active")
        hits = try c.field("hits"); misses = try c.field("misses"); ready = try c.field("ready")
        unavailable = try c.field("unavailable"); uncertain = try c.field("uncertain"); queued = try c.field("queued")
        modelUsage = keys.contains("model_usage") ? try c.field("model_usage") : nil
    }
    public var summary: String {
        // Background model counters do not describe protection or require user action.
        return "Local checks are ready."
    }
}
public struct WorkflowAssessment: Decodable, Sendable {
    public struct Signal: Decodable, Sendable { public let eventID: UUID; public let kind: String }
    public let contextID: UUID
    public let eventCount: Int
    public let linkCount: Int
    public let incomplete: Bool
    public let classifiedFields: Int
    public let judgment: WorkflowJudgmentStatus?
    public let omittedTextFields: Int
    public let signals: [Signal]
    public let shadowOnly: Bool
}
public enum EngineResult: Sendable {
    case packageProtection(PackageProtectionStatus)
    case scriptProtection(ScriptProtectionStatus)
    case status(ClassificationStatus?), record(SafeRecord), recent([SafeRecord], total: Int), policies([SafePolicy]), stopped, workflow(WorkflowAssessment), workflowCleared
    func matches(_ operation: String) -> Bool {
        switch (self, operation) {
        case (.packageProtection, "package_protection"), (.scriptProtection, "script_protection"), (.workflow, "workflow_context"), (.workflowCleared, "workflow_clear"), (.status, "status"), (.record, "evaluate"), (.recent, "recent"), (.policies, "policies"), (.stopped, "shutdown"): return true
        default: return false
        }
    }
}
public struct EngineResponse: Decodable, Sendable {
    public let id: String?
    public let result: EngineResult?
    public let failure: EngineFailure?
    public init(from decoder: Decoder) throws {
        let initial = try decoder.container(keyedBy: WireKey.self)
        let ok: Bool = try initial.field("ok")
        let c = try decoder.object(ok ? ["version", "id", "ok", "result"] : ["version", "id", "ok", "error"])
        guard try c.field("version", as: Int.self) == 1 else { throw EngineFailure.protocolViolation }
        id = try c.decodeIfPresent(String.self, forKey: WireKey("id"))
        guard id.map(IdentityValidation.requestID) ?? !ok else { throw EngineFailure.protocolViolation }
        if !ok {
            let error: SafeError = try c.field("error"); failure = error.code; result = nil
        } else {
            failure = nil; result = try c.field("result", as: ResultPayload.self).result
        }
    }
}
private struct SafeError: Decodable {
    let code: EngineFailure
    init(from decoder: Decoder) throws {
        let c = try decoder.object(["code", "message"])
        let raw: String = try c.field("code"); let _: String = try c.field("message")
        switch raw { case "invalid_request": code = .invalidRequest; case "line_too_large": code = .lineTooLarge; case "internal_error": code = .internalError; default: throw EngineFailure.protocolViolation }
    }
}
private struct ResultPayload: Decodable {
    let result: EngineResult
    init(from decoder: Decoder) throws {
        let peek = try decoder.container(keyedBy: WireKey.self)
        if peek.contains(WireKey("packageProtection")) {
            let c = try decoder.object(["packageProtection"])
            result = .packageProtection(try c.field("packageProtection"))
        } else if peek.contains(WireKey("scriptProtection")) {
            let c = try decoder.object(["scriptProtection"])
            result = .scriptProtection(try c.field("scriptProtection"))
        } else if peek.contains(WireKey("ready")) {
            var keys: Set<String> = ["ready", "protocol", "engine", "monitoring", "network_listener"]
            if peek.contains(WireKey("classification")) { keys.insert("classification") }
            if peek.contains(WireKey("package_registry_listener")) { keys.insert("package_registry_listener") }
            if peek.contains(WireKey("install_script_listener")) { keys.insert("install_script_listener") }
            let c = try decoder.object(keys)
            let registry = try c.decodeIfPresent(Bool.self, forKey: WireKey("package_registry_listener")) ?? false
            let scripts = try c.decodeIfPresent(Bool.self, forKey: WireKey("install_script_listener")) ?? false
            guard try c.field("ready", as: Bool.self), try c.field("protocol", as: Int.self) == 1,
                  try c.field("engine", as: String.self) == "rules+sequence", try c.field("monitoring", as: Bool.self) == false,
                  try c.field("network_listener", as: Bool.self) == (registry || scripts) else { throw EngineFailure.notReady }
            result = .status(try c.decodeIfPresent(ClassificationStatus.self, forKey: WireKey("classification")))
        } else if peek.contains(WireKey("workflow")) {
            let c = try decoder.object(["workflow"])
            let assessment: WorkflowAssessment = try c.field("workflow")
            guard assessment.judgment?.isValid != false, assessment.shadowOnly, (0...64).contains(assessment.eventCount), (0...256).contains(assessment.linkCount),
                  (0...8).contains(assessment.classifiedFields), (0...384).contains(assessment.omittedTextFields), assessment.signals.count <= 16,
                  assessment.signals.allSatisfy({ ["observed_domain_block", "sensitive_content_label"].contains($0.kind) }) else { throw EngineFailure.protocolViolation }
            result = .workflow(assessment)
        } else if peek.contains(WireKey("workflowCleared")) {
            let c = try decoder.object(["workflowCleared"])
            guard try c.field("workflowCleared", as: Bool.self) else { throw EngineFailure.protocolViolation }
            result = .workflowCleared
        } else if peek.contains(WireKey("record")) {
            let c = try decoder.object(["record"]); result = .record(try c.field("record"))
        } else if peek.contains(WireKey("total")) {
            let c = try decoder.object(["items", "total"])
            let items: [SafeRecord] = try c.field("items"); let total: Int = try c.field("total")
            guard items.count <= 100, total >= items.count else { throw EngineFailure.protocolViolation }
            result = .recent(items, total: total)
        } else if peek.contains(WireKey("items")) {
            let c = try decoder.object(["items"]); let items: [SafePolicy] = try c.field("items")
            guard items.count <= 32 else { throw EngineFailure.protocolViolation }
            result = .policies(items)
        } else {
            let c = try decoder.object(["stopped"])
            guard try c.field("stopped", as: Bool.self) else { throw EngineFailure.protocolViolation }
            result = .stopped
        }
    }
}
public enum WireCodec {
    public static func encode(id: String, command: EngineCommand) throws -> Data {
        guard IdentityValidation.requestID(id) else { throw EngineFailure.invalidRequest }
        do {
            let encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601
            let data = try encoder.encode(Request(id: id, command: command))
            guard data.count < JSONLFramer.maximumLineBytes else { throw EngineFailure.lineTooLarge }
            return data
        } catch let failure as EngineFailure { throw failure } catch { throw EngineFailure.invalidRequest }
    }
    public static func decode(_ data: Data) throws -> EngineResponse {
        do { var validator = try StrictJSON(data); try validator.validate(); return try JSONDecoder().decode(EngineResponse.self, from: data) }
        catch let failure as EngineFailure { throw failure } catch { throw EngineFailure.protocolViolation }
    }
}
