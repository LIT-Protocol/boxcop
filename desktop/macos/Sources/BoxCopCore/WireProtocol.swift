import Foundation

public enum PackageProtectionAction: String, Sendable { case status, enable, disable, allow, revoke }
/// One exact release of one package. The install gate allows or blocks releases, never whole packages.
public struct PackageRelease: Decodable, Sendable, Hashable {
    public static let ecosystems: Set<String> = ["npm", "PyPI"]
    /// The request envelope already uses `version` for the protocol number, so a request names the release version with this key.
    static let versionKey = "package_version"
    public let ecosystem: String, package: String, version: String
    public init(ecosystem: String, package: String, version: String) {
        self.ecosystem = ecosystem; self.package = package; self.version = version
    }
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: WireKey.self)
        ecosystem = try c.field("ecosystem"); package = try c.field("package")
        version = try c.decodeIfPresent(String.self, forKey: WireKey("version")) ?? c.field(Self.versionKey)
    }
    /// What a person would type: `name@1.2.3` for npm, `name==1.2.3` for PyPI.
    public var display: String { package + (ecosystem == "PyPI" ? "==" : "@") + version }
    var isValid: Bool {
        Self.ecosystems.contains(ecosystem) && !package.isEmpty && package.count <= 214 && !version.isEmpty && version.count <= 128
    }
}
/// A release the person chose to allow although the feed reports it as malware. Confirmed malware can never be listed here.
public struct PackageException: Decodable, Sendable, Hashable, Identifiable {
    public let release: PackageRelease
    /// ISO 8601 time the exception was added, when the engine reports it.
    public let added: String?
    public var id: String { release.ecosystem + "|" + release.package + "|" + release.version }
    public init(release: PackageRelease, added: String? = nil) { self.release = release; self.added = added }
    public init(from decoder: Decoder) throws {
        let release = try PackageRelease(from: decoder)
        guard release.isValid else { throw EngineFailure.protocolViolation }
        self.release = release
        added = try decoder.container(keyedBy: WireKey.self).decodeIfPresent(String.self, forKey: WireKey("added")).map { String($0.prefix(40)) }
    }
}
/// An engine that predates exceptions omits the list; a malformed row is skipped, not the whole status.
private struct LossyPackageException: Decodable {
    let value: PackageException?
    init(from decoder: Decoder) throws { value = try? PackageException(from: decoder) }
}
public struct PackageProtectionStatus: Decodable, Sendable {
    public let configured: Bool, routed: Bool, active: Bool, busy: Bool, stale: Bool
    public let summary: String
    public let generatedAt: String?, updateError: String?
    public let exceptions: [PackageException]
    /// Why the last `allow` or `revoke` was refused, in the engine's words. Nil when it was accepted.
    public let exceptionError: String?
    enum CodingKeys: String, CodingKey {
        case configured, routed, active, busy, stale, summary, exceptions
        case generatedAt = "generated_at", updateError = "update_error", exceptionError = "exception_error"
    }
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        configured = try c.decode(Bool.self, forKey: .configured); routed = try c.decode(Bool.self, forKey: .routed)
        active = try c.decode(Bool.self, forKey: .active); busy = try c.decode(Bool.self, forKey: .busy)
        stale = try c.decode(Bool.self, forKey: .stale); summary = try c.decode(String.self, forKey: .summary)
        generatedAt = try c.decodeIfPresent(String.self, forKey: .generatedAt)
        updateError = try c.decodeIfPresent(String.self, forKey: .updateError)
        let rows = (try? c.decodeIfPresent([LossyPackageException].self, forKey: .exceptions)) ?? nil
        exceptions = Array((rows ?? []).compactMap(\.value).prefix(200))
        let refusal = ((try? c.decodeIfPresent(String.self, forKey: .exceptionError)) ?? nil)?.trimmingCharacters(in: .whitespacesAndNewlines)
        exceptionError = refusal.flatMap { $0.isEmpty ? nil : String($0.prefix(300)) }
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
    public enum Outcome: String, Sendable { case blocked, warned }
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
    /// Install gate only: `npm` or `PyPI`, and the exact version that was refused.
    public let ecosystem: String?
    public let version: String?
    /// True only for a release that is reported as malware but not confirmed, and is not already allowed.
    public let allowable: Bool
    public init(id: String, time: Date, layer: Layer, outcome: Outcome, title: String, reason: String, subject: String,
                agent: String? = nil, command: String? = nil, package: String? = nil, host: String? = nil, policyIDs: [String] = [],
                ecosystem: String? = nil, version: String? = nil, allowable: Bool = false) {
        self.id = id; self.time = time; self.layer = layer; self.outcome = outcome; self.title = title; self.reason = reason
        self.subject = subject; self.agent = agent; self.command = command; self.package = package; self.host = host; self.policyIDs = policyIDs
        self.ecosystem = ecosystem; self.version = version; self.allowable = allowable
    }
    /// The exact release an install-gate event is about, when the engine named all three parts.
    public var release: PackageRelease? {
        guard layer == .installGate, let ecosystem, let package, let version else { return nil }
        let release = PackageRelease(ecosystem: ecosystem, package: package, version: version)
        return release.isValid ? release : nil
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
        // Added with install gate exceptions; an older engine omits all three.
        ecosystem = (try? text("ecosystem", limit: 16)) ?? nil
        version = ((try? text("version", limit: 255)) ?? nil) ?? ((try? text(PackageRelease.versionKey, limit: 255)) ?? nil)
        allowable = ((try? c.decodeIfPresent(Bool.self, forKey: WireKey("allowable"))) ?? nil) ?? false
    }
    /// True for the feed's unconfirmed tier: the release is reported as malware but nobody has confirmed it.
    public var reportedOnly: Bool {
        layer == .installGate && (allowable || title.localizedCaseInsensitiveContains("reported as malware"))
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
    /// `allow` and `revoke` name one exact release; the other actions take none.
    case packageProtection(PackageProtectionAction, release: PackageRelease? = nil)
    case scriptProtection(ScriptProtectionAction, package: String = "", host: String = "")
    case status, securityEvents(Int), shutdown, workflowContext(WorkflowContext)
    /// Forgets the reviewer's context. With `removeModel` it also deletes the downloaded model, which the engine does only while the runtime is stopped.
    case workflowClear(removeModel: Bool = false)
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
        case let .packageProtection(action, release):
            try c.encode(action.rawValue, forKey: WireKey("action"))
            let names = action == .allow || action == .revoke
            guard names == (release != nil), release?.isValid != false else { throw EngineFailure.invalidRequest }
            if let release {
                try c.encode(release.ecosystem, forKey: WireKey("ecosystem")); try c.encode(release.package, forKey: WireKey("package"))
                try c.encode(release.version, forKey: WireKey(PackageRelease.versionKey))
            }
        case let .workflowClear(removeModel):
            if removeModel { try c.encode(true, forKey: WireKey("remove_model")) }
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

/// The answer to `workflow_clear` with `remove_model`. `removed` is false when a runtime elsewhere still holds the model; nothing was deleted then.
public struct ModelRemoval: Equatable, Sendable {
    public let removed: Bool
    public let freedBytes: Int64
    public init(removed: Bool, freedBytes: Int64) { self.removed = removed; self.freedBytes = freedBytes }
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
    case status(EngineStatus), securityEvents([SecurityEvent]), stopped, workflow(WorkflowAssessment)
    /// `removal` is reported only when the request asked for the model to be removed.
    case workflowCleared(removal: ModelRemoval?)
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
            // `modelRemoved` and `freedBytes` come only with a request to remove the model.
            guard Set(peek.allKeys.map(\.stringValue)).isSubset(of: ["workflowCleared", "modelRemoved", "freedBytes"]),
                  try peek.field("workflowCleared", as: Bool.self) else { throw EngineFailure.protocolViolation }
            let removed = try peek.decodeIfPresent(Bool.self, forKey: WireKey("modelRemoved"))
            let freed = try peek.decodeIfPresent(Int64.self, forKey: WireKey("freedBytes"))
            guard freed.map({ $0 >= 0 && $0 <= 100_000_000_000 }) ?? true else { throw EngineFailure.protocolViolation }
            result = .workflowCleared(removal: removed.map { ModelRemoval(removed: $0, freedBytes: freed ?? 0) })
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
