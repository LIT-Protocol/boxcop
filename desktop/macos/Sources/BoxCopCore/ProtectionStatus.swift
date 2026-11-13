import Foundation

/// The six protection layers, in the order they are shown everywhere.
public enum LayerID: String, CaseIterable, Codable, Sendable, Identifiable {
    case installGate = "install_gate"
    case containment
    case outboundControl = "outbound_control"
    case agentChecks = "agent_checks"
    case machineHealth = "machine_health"
    case smartTriage = "smart_triage"

    public var id: String { rawValue }
    public var name: String {
        switch self {
        case .installGate: return "Install gate"
        case .containment: return "Containment"
        case .outboundControl: return "Outbound control"
        case .agentChecks: return "Agent checks"
        case .machineHealth: return "Machine health"
        case .smartTriage: return "Smart triage"
        }
    }
    public var summary: String {
        switch self {
        case .installGate: return "Blocks known-malicious npm and PyPI packages before they install."
        case .containment: return "Runs npm install scripts in a sandbox with no network unless allowed."
        case .outboundControl: return "Records new connections from every app and blocks known malware hosts."
        case .agentChecks: return "Stops risky commands and credential access in Claude Code, Codex and Cursor."
        case .machineHealth: return "Finds outdated and vulnerable software on this Mac."
        case .smartTriage: return "A local AI model explains what was blocked and why. Nothing leaves your Mac."
        }
    }
    /// Layers 1 to 4 stop something. Machine health reports and smart triage explains.
    public var enforces: Bool { self != .machineHealth && self != .smartTriage }
}

public enum LayerState: String, Codable, Sendable {
    case on, off
    case needsSetup = "needs_setup"
    case unavailable
    public var label: String {
        switch self {
        case .on: return "On"
        case .off: return "Off"
        case .needsSetup: return "Needs setup"
        case .unavailable: return "Unavailable"
        }
    }
}

public struct LayerStatus: Codable, Equatable, Sendable, Identifiable {
    public let id: LayerID
    public let state: LayerState
    /// One sentence. For anything not on, it names the exact missing step.
    public let detail: String
    public init(_ id: LayerID, _ state: LayerState, _ detail: String) { self.id = id; self.state = state; self.detail = detail }
}

public enum OverallStatus: String, Codable, Sendable {
    case protected
    case partlyProtected = "partly_protected"
    case notProtected = "not_protected"
    case paused
    public var word: String {
        switch self {
        case .protected: return "Protected"
        case .partlyProtected: return "Partly protected"
        case .notProtected: return "Not protected"
        case .paused: return "Paused"
        }
    }
}

/// How one agent's hooks are doing, read from the engine's integration status.
public enum AgentHookHealth: Equatable, Sendable {
    case notDetected, notConnected, connected, needsRepair
    private static let failing: Set<String> = ["configuration conflict", "disabled by harness", "disable setting unverified",
                                               "unavailable", "callback error", "callback unavailable"]
    public init(state: String) {
        switch state.replacingOccurrences(of: "_", with: " ") {
        case "not detected": self = .notDetected
        case "not configured": self = .notConnected
        case let value where Self.failing.contains(value): self = .needsRepair
        default: self = .connected
        }
    }
    public static func displayName(_ id: String) -> String {
        ["claude": "Claude Code", "codex": "Codex", "cursor": "Cursor"][id] ?? id.capitalized
    }
}

/// What the engine's one-shot `--protection-status` prints.
public struct EngineProtectionStatus: Decodable, Equatable, Sendable {
    public struct Package: Decodable, Equatable, Sendable {
        public let configured: Bool, routed: Bool, listening: Bool
        public init(configured: Bool, routed: Bool, listening: Bool) { self.configured = configured; self.routed = routed; self.listening = listening }
    }
    public struct Scripts: Decodable, Equatable, Sendable {
        public let routed: Bool, listening: Bool
        public init(routed: Bool, listening: Bool) { self.routed = routed; self.listening = listening }
    }
    public let schema: String
    public let package: Package
    public let scripts: Scripts
    public static func decode(_ data: Data) -> EngineProtectionStatus? {
        guard let value = try? JSONDecoder().decode(EngineProtectionStatus.self, from: data),
              value.schema == "boxcop.protection-status.v1" else { return nil }
        return value
    }
}

/// Pure rules that turn observed facts into a layer state. A layer is `on` only when it is enforcing right now.
public enum LayerRules {
    public static let engineMissing = "This build does not include the BoxCop engine."

    public static func installGate(engineAvailable: Bool, engineRunning: Bool, wanted: Bool, configured: Bool?, routed: Bool, listening: Bool,
                                   stale: Bool = false, feedDate: String? = nil) -> LayerStatus {
        guard engineAvailable else { return .init(.installGate, .unavailable, engineMissing) }
        if configured == false { return .init(.installGate, .unavailable, "This build has no malware feed channel configured.") }
        if routed && listening {
            let dated = feedDate.map { "Feed dated \(String($0.prefix(10)))." } ?? "npm and pip installs go through the local check."
            return .init(.installGate, .on, stale ? "On, but the malware feed is out of date. BoxCop will retry the update." : dated)
        }
        if routed { return .init(.installGate, .needsSetup, engineRunning ? "npm and pip are routed to BoxCop but the local check is not answering. Choose Fix to restart it." : "npm and pip are routed to BoxCop but its engine is not running. Open BoxCop to start it.") }
        if wanted { return .init(.installGate, .needsSetup, engineRunning ? "Turning on. BoxCop is routing npm and pip through the local check." : "Waiting for the BoxCop engine to start.") }
        return .init(.installGate, .off, "Turn on the install gate in BoxCop.")
    }

    public static func containment(engineAvailable: Bool, engineRunning: Bool, wanted: Bool, routed: Bool, listening: Bool) -> LayerStatus {
        guard engineAvailable else { return .init(.containment, .unavailable, engineMissing) }
        if routed && listening { return .init(.containment, .on, "npm install scripts run sandboxed.") }
        if routed { return .init(.containment, .needsSetup, engineRunning ? "npm scripts are routed to BoxCop but the sandbox proxy is not answering. Choose Fix to restart it." : "npm scripts are routed to BoxCop but its engine is not running. Open BoxCop to start it.") }
        if wanted { return .init(.containment, .needsSetup, engineRunning ? "Turning on. BoxCop is routing npm install scripts through the sandbox." : "Waiting for the BoxCop engine to start.") }
        return .init(.containment, .off, "Turn on containment in BoxCop.")
    }

    public enum ExtensionState: Sendable { case unknown, missing, awaitingApproval, installed, upgradeRequired }

    public static func outboundControl(bundled: Bool, placementIssue: String? = nil, wanted: Bool, extensionState: ExtensionState, filterEnabled: Bool?,
                                       reachable: Bool, threatBlocking: Bool, threatError: String? = nil, hosts: Int? = nil) -> LayerStatus {
        guard bundled else { return .init(.outboundControl, .unavailable, "This build does not include the network extension.") }
        if let placementIssue { return .init(.outboundControl, .needsSetup, placementIssue) }
        if reachable {
            if let threatError { return .init(.outboundControl, .needsSetup, "The threat list could not be loaded: \(threatError)") }
            if threatBlocking { return .init(.outboundControl, .on, hosts.map { "Recording connections and blocking \($0.formatted()) listed hosts." } ?? "Recording connections and blocking listed hosts.") }
            return .init(.outboundControl, .needsSetup, "Connections are recorded but threat blocking is off. Turn on threat blocking.")
        }
        if extensionState == .awaitingApproval { return .init(.outboundControl, .needsSetup, "Approve BoxCop in System Settings, under Login Items & Extensions, Network Extensions.") }
        if filterEnabled == true { return .init(.outboundControl, .needsSetup, "The network filter is enabled but not answering. Turn outbound control off and on again, or restart your Mac.") }
        if wanted { return .init(.outboundControl, .needsSetup, extensionState == .installed ? "Allow BoxCop to filter network content when macOS asks." : "Install the network extension and approve it when macOS asks.") }
        return .init(.outboundControl, .off, "Turn on outbound control in BoxCop and approve the network extension.")
    }

    public static func agentChecks(engineAvailable: Bool, wanted: Bool, agents: [(id: String, health: AgentHookHealth)]?) -> LayerStatus {
        guard engineAvailable else { return .init(.agentChecks, .unavailable, engineMissing) }
        guard let agents else { return .init(.agentChecks, wanted ? .needsSetup : .off, "Hook status could not be read. Open BoxCop and choose Fix.") }
        func names(_ health: AgentHookHealth) -> [String] { agents.filter { $0.health == health }.map { AgentHookHealth.displayName($0.id) } }
        let connected = names(.connected), broken = names(.needsRepair), missing = names(.notConnected)
        if connected.isEmpty && broken.isEmpty && missing.isEmpty {
            return .init(.agentChecks, .unavailable, "No supported agent found. Open Claude Code, Codex or Cursor once, then try again.")
        }
        if !broken.isEmpty { return .init(.agentChecks, .needsSetup, "\(list(broken)) hooks need repair. Choose Fix.") }
        if connected.isEmpty { return .init(.agentChecks, wanted ? .needsSetup : .off, "Connect \(list(missing)) to check agent actions.") }
        if !missing.isEmpty { return .init(.agentChecks, .needsSetup, "\(list(missing)) \(missing.count == 1 ? "is" : "are") not connected. Choose Fix to connect.") }
        return .init(.agentChecks, .on, "Checking actions in \(list(connected)).")
    }

    public static func machineHealth(engineAvailable: Bool, wanted: Bool, hasReport: Bool, findings: Int? = nil) -> LayerStatus {
        guard engineAvailable else { return .init(.machineHealth, .unavailable, engineMissing) }
        guard wanted else { return .init(.machineHealth, .off, "Turn on machine health in BoxCop.") }
        guard hasReport else { return .init(.machineHealth, .needsSetup, "The first software check has not finished. Open BoxCop and choose Check now.") }
        guard let findings else { return .init(.machineHealth, .on, "Software on this Mac has been checked.") }
        return .init(.machineHealth, .on, findings == 0 ? "No findings need your attention." : "\(findings) finding\(findings == 1 ? "" : "s") to review.")
    }

    /// `setupMessage` is the engine's own sentence for a failed setup and is shown as written.
    /// `modelDownloaded` is nil when nobody looked on disk.
    public static func smartTriage(engineAvailable: Bool, runtimeAvailable: Bool, wanted: Bool, setupState: String? = nil, fraction: Double = 0,
                                   setupMessage: String? = nil, modelDownloaded: Bool? = nil, live: Bool = true) -> LayerStatus {
        guard engineAvailable else { return .init(.smartTriage, .unavailable, engineMissing) }
        guard runtimeAvailable else { return .init(.smartTriage, .unavailable, "This build does not include the local model runtime.") }
        guard wanted else {
            return .init(.smartTriage, .off, modelDownloaded == true ? "Turn on smart triage in BoxCop. The model is already downloaded."
                         : "Turn on smart triage in BoxCop. The model is a 2.7 GB download on first use.")
        }
        guard live else {
            switch modelDownloaded {
            case true?: return .init(.smartTriage, .on, "Turned on. The model is downloaded. It runs while BoxCop is open.")
            case false?: return .init(.smartTriage, .needsSetup, "Turned on, but the model is not downloaded yet. Open BoxCop to download it (2.7 GB).")
            case nil: return .init(.smartTriage, .on, "Turned on. Model status is shown in BoxCop while it is running.")
            }
        }
        switch setupState {
        case "ready": return .init(.smartTriage, .on, "The local model is ready.")
        case "downloading", "waiting_for_download": return .init(.smartTriage, .needsSetup, "Downloading the model: \(Int(fraction * 100))% of 2.7 GB.")
        case "verifying", "loading": return .init(.smartTriage, .needsSetup, "Loading the model.")
        case "error":
            return .init(.smartTriage, .needsSetup, setupMessage ?? "The model could not be downloaded or loaded. Check your connection, then turn smart triage off and on.")
        default: return .init(.smartTriage, .needsSetup, "Waiting for the first event to start the model.")
        }
    }

    static func list(_ names: [String]) -> String {
        guard let last = names.last else { return "" }
        return names.count == 1 ? last : names.dropLast().joined(separator: ", ") + " and " + last
    }
}

/// One word and one sentence for the whole Mac.
public struct ProtectionSummary: Equatable, Sendable {
    public let overall: OverallStatus
    public let sentence: String
    public let layers: [LayerStatus]

    public init(layers: [LayerStatus], paused: Bool) {
        self.layers = layers
        let enforcing = layers.filter { $0.id.enforces }
        let enforcingOn = enforcing.filter { $0.state == .on }
        if paused {
            overall = .paused
            sentence = "Package checks, containment and threat blocking are off until you resume."
        } else if enforcingOn.isEmpty {
            overall = .notProtected
            sentence = "Nothing is enforcing yet. Turn on a layer below."
        } else if enforcingOn.count == enforcing.count && !layers.contains(where: { $0.state == .needsSetup }) {
            // Layers 1 to 4 are all enforcing and nothing that was turned on is waiting.
            overall = .protected
            sentence = "Installs, scripts, connections and agent actions are being checked."
        } else {
            overall = .partlyProtected
            sentence = Self.gaps(layers)
        }
    }

    /// True when at least one of layers 1 to 4 is enforcing.
    public var anyEnforcing: Bool { layers.contains { $0.id.enforces && $0.state == .on } }

    static func gaps(_ layers: [LayerStatus]) -> String {
        func count(_ state: LayerState) -> Int { layers.filter { $0.state == state }.count }
        let off = count(.off), setup = count(.needsSetup), unavailable = count(.unavailable)
        var parts: [String] = []
        if setup > 0 { parts.append("\(setup) need\(setup == 1 ? "s" : "") setup") }
        if off > 0 { parts.append("\(off) \(off == 1 ? "is" : "are") off") }
        if unavailable > 0 { parts.append("\(unavailable) \(unavailable == 1 ? "is" : "are") unavailable") }
        guard !parts.isEmpty else { return "Some layers are not enforcing." }
        return "Of 6 layers, " + LayerRules.list(parts) + "."
    }
}

/// `BoxCop --status` output.
public struct StatusReport: Encodable, Equatable, Sendable {
    public let schema = "boxcop.status.v1"
    public let overall: OverallStatus
    public let layers: [LayerStatus]
    public init(_ summary: ProtectionSummary) { overall = summary.overall; layers = summary.layers }

    public func json() -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return (try? encoder.encode(self)).map { String(decoding: $0, as: UTF8.self) } ?? "{}"
    }
    /// A short checklist. Anything not on names its missing step.
    public func text() -> String {
        var lines = ["BoxCop: \(overall.word)"]
        for layer in layers {
            lines.append("[\(layer.state == .on ? "x" : " ")] \(layer.id.name): \(layer.state.label.lowercased()). \(layer.detail)")
        }
        return lines.joined(separator: "\n")
    }
    /// 0 when at least one of layers 1 to 4 is enforcing, otherwise 1.
    public var exitCode: Int32 { layers.contains { $0.id.enforces && $0.state == .on } ? 0 : 1 }
}
