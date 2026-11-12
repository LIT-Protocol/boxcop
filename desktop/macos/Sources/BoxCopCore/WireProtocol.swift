import Foundation

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

/// One protection decision reported by the engine for layers 1, 2 and 4. Never carries secrets or file content.
public struct SecurityEvent: Decodable, Identifiable, Equatable, Sendable {
    public enum Layer: String, Sendable { case installGate = "install_gate", containment, agentActions = "agent_actions" }
    public enum Outcome: String, Sendable { case blocked, held, approved, rejected, warned }
    public let id: String
    public let time: Date
    public let layer: Layer
    public let outcome: Outcome
    public let title: String
    public let reason: String
    public let subject: String
    public let agent: String?
    public let command: String?
    public let package: String?
    public let host: String?
    public let policyIDs: [String]
    public init(id: String, time: Date, layer: Layer, outcome: Outcome, title: String, reason: String, subject: String,
                agent: String? = nil, command: String? = nil, package: String? = nil, host: String? = nil, policyIDs: [String] = []) {
        self.id = id; self.time = time; self.layer = layer; self.outcome = outcome; self.title = title; self.reason = reason
        self.subject = subject; self.agent = agent; self.command = command; self.package = package; self.host = host; self.policyIDs = policyIDs
    }
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: WireKey.self)
        func text(_ name: String, limit: Int) throws -> String? {
            guard let value = try c.decodeIfPresent(String.self, forKey: WireKey(name)), !value.isEmpty else { return nil }
            return String(value.prefix(limit))
        }
        guard let id = try text("id", limit: 200), let stamp = try text("time", limit: 40), let date = Self.date(stamp),
              let layer = try text("layer", limit: 32).flatMap(Layer.init(rawValue:)),
              let outcome = try text("outcome", limit: 32).flatMap(Outcome.init(rawValue:)),
              let title = try text("title", limit: 300) else { throw EngineFailure.protocolViolation }
        self.id = id; time = date; self.layer = layer; self.outcome = outcome; self.title = title
        reason = try text("reason", limit: 1000) ?? ""
        subject = try text("subject", limit: 500) ?? ""
        agent = try text("agent", limit: 32); command = try text("command", limit: 4096)
        package = try text("package", limit: 255); host = try text("host", limit: 255)
        policyIDs = Array((try c.decodeIfPresent([String].self, forKey: WireKey("policy_ids")) ?? []).prefix(32))
    }
    /// ISO 8601 with or without fractional seconds.
    public static func date(_ text: String) -> Date? {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = formatter.date(from: text) { return date }
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.date(from: text)
    }
}
/// A newer engine may report a layer or outcome this build does not know; that row is skipped, not the whole list.
private struct LossySecurityEvent: Decodable {
    let event: SecurityEvent?
    init(from decoder: Decoder) throws { event = try? SecurityEvent(from: decoder) }
}

public enum EngineCommand: Sendable, CustomStringConvertible {
    case packageProtection(PackageProtectionAction)
    case scriptProtection(ScriptProtectionAction, package: String = "", host: String = "")
    case status, securityEvents(Int), shutdown, workflowContext(WorkflowContext), workflowClear
    public var operation: String {
        switch self {
        case .packageProtection: return "package_protection"
        case .scriptProtection: return "script_protection"
        case .workflowContext: return "workflow_context"
        case .workflowClear: return "workflow_clear"
        case .status: return "status"
        case .securityEvents: return "security_events"
        case .shutdown: return "shutdown"
        }
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
        case let .securityEvents(limit):
            guard (1...200).contains(limit) else { throw EngineFailure.invalidRequest }
            try c.encode(limit, forKey: WireKey("limit"))
        default: break
        }
    }
}

/// What the readiness handshake reports about the engine's local listeners.
public struct EngineStatus: Equatable, Sendable {
    public let packageRegistryListener: Bool
    public let installScriptListener: Bool
}
public struct WorkflowAssessment: Decodable, Sendable {
    public let contextID: UUID
    public let eventCount: Int
    public let linkCount: Int
    public let incomplete: Bool
    public let judgment: WorkflowJudgmentStatus?
    public let shadowOnly: Bool
    enum CodingKeys: String, CodingKey { case contextID, eventCount, linkCount, incomplete, judgment, shadowOnly }
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        contextID = try c.decode(UUID.self, forKey: .contextID)
        eventCount = try c.decode(Int.self, forKey: .eventCount)
        linkCount = try c.decode(Int.self, forKey: .linkCount)
        incomplete = try c.decodeIfPresent(Bool.self, forKey: .incomplete) ?? false
        judgment = try c.decodeIfPresent(WorkflowJudgmentStatus.self, forKey: .judgment)
        shadowOnly = try c.decodeIfPresent(Bool.self, forKey: .shadowOnly) ?? true
    }
}
public enum EngineResult: Sendable {
    case packageProtection(PackageProtectionStatus)
    case scriptProtection(ScriptProtectionStatus)
    case status(EngineStatus), securityEvents([SecurityEvent]), stopped, workflow(WorkflowAssessment), workflowCleared
    func matches(_ operation: String) -> Bool {
        switch (self, operation) {
        case (.packageProtection, "package_protection"), (.scriptProtection, "script_protection"), (.workflow, "workflow_context"),
             (.workflowCleared, "workflow_clear"), (.status, "status"), (.securityEvents, "security_events"), (.stopped, "shutdown"): return true
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
        // `security_events` may answer with the list at the top level instead of under `result`.
        let flatEvents = ok && initial.contains(WireKey("events")) && !initial.contains(WireKey("result"))
        var keys: Set<String> = ok ? (flatEvents ? ["id", "ok", "events"] : ["version", "id", "ok", "result"]) : ["version", "id", "ok", "error"]
        if flatEvents && initial.contains(WireKey("version")) { keys.insert("version") }
        let c = try decoder.object(keys)
        if keys.contains("version") { guard try c.field("version", as: Int.self) == 1 else { throw EngineFailure.protocolViolation } }
        id = try c.decodeIfPresent(String.self, forKey: WireKey("id"))
        guard id.map(IdentityValidation.requestID) ?? !ok else { throw EngineFailure.protocolViolation }
        if !ok {
            let error: SafeError = try c.field("error"); failure = error.code; result = nil
        } else if flatEvents {
            failure = nil; result = .securityEvents(try ResultPayload.events(c))
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
    static func events(_ c: KeyedDecodingContainer<WireKey>) throws -> [SecurityEvent] {
        let rows: [LossySecurityEvent] = try c.field("events")
        guard rows.count <= 200 else { throw EngineFailure.protocolViolation }
        return rows.compactMap(\.event)
    }
    init(from decoder: Decoder) throws {
        let peek = try decoder.container(keyedBy: WireKey.self)
        if peek.contains(WireKey("packageProtection")) {
            let c = try decoder.object(["packageProtection"])
            result = .packageProtection(try c.field("packageProtection"))
        } else if peek.contains(WireKey("scriptProtection")) {
            let c = try decoder.object(["scriptProtection"])
            result = .scriptProtection(try c.field("scriptProtection"))
        } else if peek.contains(WireKey("ready")) {
            // Required: ready, protocol, engine. The listener flags and `monitoring` are optional but checked when present.
            let optional: Set<String> = ["monitoring", "network_listener", "package_registry_listener", "install_script_listener"]
            let present = Set(peek.allKeys.map(\.stringValue))
            guard present.isSubset(of: optional.union(["ready", "protocol", "engine"])) else { throw EngineFailure.protocolViolation }
            let registry = try peek.decodeIfPresent(Bool.self, forKey: WireKey("package_registry_listener")) ?? false
            let scripts = try peek.decodeIfPresent(Bool.self, forKey: WireKey("install_script_listener")) ?? false
            guard try peek.field("ready", as: Bool.self), try peek.field("protocol", as: Int.self) == 1,
                  try peek.field("engine", as: String.self) == "rules",
                  try peek.decodeIfPresent(Bool.self, forKey: WireKey("monitoring")) ?? false == false,
                  try peek.decodeIfPresent(Bool.self, forKey: WireKey("network_listener")) ?? (registry || scripts) == (registry || scripts) else { throw EngineFailure.notReady }
            result = .status(EngineStatus(packageRegistryListener: registry, installScriptListener: scripts))
        } else if peek.contains(WireKey("events")) {
            let c = try decoder.object(["events"])
            result = .securityEvents(try Self.events(c))
        } else if peek.contains(WireKey("workflow")) {
            let c = try decoder.object(["workflow"])
            let assessment: WorkflowAssessment = try c.field("workflow")
            guard assessment.judgment?.isValid != false, assessment.shadowOnly, (0...64).contains(assessment.eventCount),
                  (0...256).contains(assessment.linkCount) else { throw EngineFailure.protocolViolation }
            result = .workflow(assessment)
        } else if peek.contains(WireKey("workflowCleared")) {
            let c = try decoder.object(["workflowCleared"])
            guard try c.field("workflowCleared", as: Bool.self) else { throw EngineFailure.protocolViolation }
            result = .workflowCleared
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
