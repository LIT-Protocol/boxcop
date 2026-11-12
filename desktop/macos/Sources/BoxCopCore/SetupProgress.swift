import Foundation

/// The persisted page of first-run setup. Permission gates stay independent of the page.
public enum SetupPage: Int, CaseIterable {
    // Older builds stored one wizard step per permission under the same key.
    case welcome = 0, protections = 1, finish = 5

    public init(storedStep: Int) {
        switch storedStep {
        case Self.welcome.rawValue: self = .welcome
        case Self.finish.rawValue: self = .finish
        default: self = .protections
        }
    }
}

public enum SetupPermission: Equatable, Sendable { case network, accessibility, screenRecording }

public enum SetupRequirements {
    /// The approval to bring back when one a chosen protection relies on goes missing.
    /// Earlier installs were never asked for Accessibility on behalf of screen warnings.
    public static func missing(wantsNetwork: Bool, wantsPaste: Bool, wantsScreen: Bool, screenNeedsAccessibility: Bool = false,
                               network: Bool, accessibility: Bool, screenRecording: Bool) -> SetupPermission? {
        if wantsNetwork && !network { return .network }
        if wantsPaste && !accessibility { return .accessibility }
        if wantsScreen && !screenRecording { return .screenRecording }
        if wantsScreen && screenNeedsAccessibility && !accessibility { return .accessibility }
        return nil
    }
    /// Screen protection reads the macOS sharing indicator, so it needs Accessibility too.
    public static func nextForScreen(accessibility: Bool, screenRecording: Bool) -> SetupPermission? {
        if !screenRecording { return .screenRecording }
        return accessibility ? nil : .accessibility
    }
}

public enum AgentSetupStatus: Equatable, Sendable { case available([String]), failed, added([String], codexAsks: Bool), on([String]) }

public enum AgentSetupCopy {
    private static let failing: Set<String> = ["configuration conflict", "disabled by harness", "disable setting unverified",
                                               "unavailable", "callback error", "callback unavailable"]
    /// A failing check outranks the summary, which can still read configured after a first timeout.
    public static func effectiveState(summary: String, actions: [String]) -> String {
        actions.first(where: failing.contains) ?? summary
    }
    /// A tool counts only for itself. One connected tool must not speak for the others.
    public static func status(of tools: [(id: String, state: String)], attempted: Bool) -> AgentSetupStatus? {
        let found = tools.filter { $0.state != "not detected" }
        guard !found.isEmpty else { return nil }
        let healthy = found.filter { !failing.contains($0.state) }
        if healthy.isEmpty || healthy.contains(where: { $0.state == "not configured" }) {
            return attempted ? .failed : .available(found.map { displayName($0.id) })
        }
        let connected = healthy.map { displayName($0.id) }
        if healthy.allSatisfy({ $0.state == "callback observed" }) { return .on(connected) }
        // Codex prompts only until its hook has run once.
        return .added(connected, codexAsks: healthy.contains { $0.id == "codex" && $0.state == "configured not observed" })
    }
    public static func displayName(_ id: String) -> String {
        ["claude": "Claude Code", "codex": "Codex", "cursor": "Cursor"][id] ?? id.capitalized
    }
    public static func join(_ names: [String]) -> String {
        guard let last = names.last else { return "" }
        return names.count == 1 ? last : names.dropLast().joined(separator: ", ") + " and " + last
    }
    public static func availableLine(tools: [String]) -> String {
        "Blocks dangerous commands in " + join(tools) + "."
    }
    /// Codex asks for approval itself at its next launch. The other tools need nothing further.
    public static func addedLine(tools: [String], codexAsks: Bool = true) -> String {
        let codex = displayName("codex")
        let asks = codexAsks && tools.contains(codex)
        let ready = asks ? tools.filter { $0 != codex } : tools
        guard !ready.isEmpty else { return "Codex will ask for approval." }
        let readiness = join(ready) + (ready.count == 1 ? " is ready" : " are ready")
        return readiness + (asks ? ", and Codex will ask for approval." : ".")
    }
}

public enum PackageManagerDetection {
    /// Checks known install locations. Setup must not run the person's shell startup files to find npm.
    public static func isPresent(home: String, exists: (String) -> Bool) -> Bool {
        let system = ["/opt/homebrew/bin", "/usr/local/bin"].flatMap { [$0 + "/npm", $0 + "/pnpm"] }
        let personal = [".npm", ".npmrc", ".nvm/versions/node", ".volta/bin/npm", ".asdf/shims/npm", ".fnm",
                        ".local/share/fnm", ".local/share/pnpm/pnpm", "Library/pnpm/pnpm"].map { home + "/" + $0 }
        return (system + personal).contains(where: exists)
    }
}
