import Foundation

/// Display-only reading of a held agent action. Approval binding stays on the exact stored
/// arguments; this never changes what is approved, it only makes the arguments readable.
public struct AgentActionDetails: Equatable, Sendable {
    public struct Argument: Equatable, Sendable {
        public let name: String
        public let value: String
    }
    public let agent: String
    public let tool: String?
    public let command: String?
    /// Text the agent wrote about its own action. It is a claim, not verification.
    public let agentDescription: String?
    public let workingDirectory: String?
    public let sessionID: String?
    public let sandboxDisabled: Bool
    public let timeoutSeconds: Int?
    /// Remaining tool arguments, so nothing in the request is hidden from the formatted view.
    public let otherArguments: [Argument]
    /// The stored request, pretty-printed with sorted keys; falls back to the stored text.
    public let rawJSON: String

    public init(application: String, command fallbackCommand: String, input: String) {
        agent = Self.agentName(application)
        let object = (input.data(using: .utf8)).flatMap { try? JSONSerialization.jsonObject(with: $0) } as? [String: Any]
        let toolInput = object?["tool_input"] as? [String: Any] ?? [:]
        tool = object?["tool_name"] as? String
        let reported = toolInput["command"] as? String ?? object?["command"] as? String
        command = reported ?? (fallbackCommand.isEmpty ? nil : fallbackCommand)
        agentDescription = (toolInput["description"] as? String).flatMap { $0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? nil : $0 }
        workingDirectory = object?["cwd"] as? String
        sessionID = object?["session_id"] as? String ?? object?["conversation_id"] as? String
        sandboxDisabled = toolInput["dangerouslyDisableSandbox"] as? Bool == true
        timeoutSeconds = (toolInput["timeout"] as? NSNumber).map { $0.intValue / 1000 }
        let shown: Set<String> = ["command", "description", "dangerouslyDisableSandbox", "timeout"]
        otherArguments = toolInput.keys.filter { !shown.contains($0) }.sorted().map { key in
            Argument(name: key, value: Self.render(toolInput[key]))
        }
        if let object, let data = try? JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]),
           let text = String(data: data, encoding: .utf8) {
            rawJSON = text
        } else {
            rawJSON = input
        }
    }

    /// A short identifier for display; the full ID remains in the raw request.
    public var shortSessionID: String? { sessionID.map { String($0.prefix(8)) } }

    /// Abbreviates the home folder; the full path stays in the raw request.
    public func displayPath(home: String = NSHomeDirectory()) -> String? {
        guard let workingDirectory else { return nil }
        if !home.isEmpty, workingDirectory == home || workingDirectory.hasPrefix(home + "/") {
            return "~" + workingDirectory.dropFirst(home.count)
        }
        return workingDirectory
    }

    public static func agentName(_ application: String) -> String {
        switch application.lowercased() {
        case "claude": return "Claude Code"
        case "codex": return "Codex"
        case "cursor": return "Cursor"
        default: return application.capitalized
        }
    }

    /// Policy reasons as short labels, e.g. "Review destructive actions" → "Destructive action".
    public static func reasonLabel(_ reason: String) -> String {
        let lower = reason.lowercased()
        if lower.contains("destructive") { return "Destructive action" }
        if lower.contains("external") { return "External communication" }
        if lower.contains("spending") { return "Spending" }
        return reason
    }

    /// JSON booleans, not the integers 0 and 1. CoreFoundation type IDs exist only on Darwin;
    /// swift-corelibs Foundation returns native `Bool` or a char-typed NSNumber for JSON booleans.
    private static func isBoolean(_ value: Any?, _ number: NSNumber) -> Bool {
#if canImport(Darwin)
        return CFGetTypeID(number) == CFBooleanGetTypeID()
#else
        if let value, type(of: value) == Bool.self { return true }
        return String(cString: number.objCType) == "c"
#endif
    }

    private static func render(_ value: Any?) -> String {
        switch value {
        case let text as String: return text
        case let number as NSNumber:
            if isBoolean(value, number) { return number.boolValue ? "true" : "false" }
            return number.stringValue
        case nil, is NSNull: return "null"
        case let other?:
            if JSONSerialization.isValidJSONObject(other),
               let data = try? JSONSerialization.data(withJSONObject: other, options: [.sortedKeys, .withoutEscapingSlashes]),
               let text = String(data: data, encoding: .utf8) { return text }
            return String(describing: other)
        }
    }
}

/// Fixed notification copy. Command text, folders and agent descriptions are never included.
public enum AgentApprovalCopy {
    public static let notificationPrefix = "boxcop-approval-"
    public static func notificationIdentifier(_ id: String) -> String { notificationPrefix + id }
    public static func requestID(notificationIdentifier: String) -> String? {
        notificationIdentifier.hasPrefix(notificationPrefix) ? String(notificationIdentifier.dropFirst(notificationPrefix.count)) : nil
    }
    public static func title(application: String) -> String {
        "\(AgentActionDetails.agentName(application)) is waiting for your approval"
    }
    public static func body(reasons: [String]) -> String {
        let labels = reasons.map(AgentActionDetails.reasonLabel)
        let lead = labels.isEmpty ? "An agent action" : labels.joined(separator: ", ")
        return "\(lead) was held for review. Open Approvals in BoxCop to approve or reject it."
    }
}
