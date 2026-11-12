#if os(macOS)
import Foundation
import Darwin
import BoxCopCore

/// User-level agent hooks use the same app and bundled engine.
/// These are cooperative vendor hooks, not a system-wide sandbox.
enum HostAgents {
    static func engineArguments(_ arguments: [String]) -> [String] {
        let directory = EngineTools.dataDirectory.path
        if arguments.first == "--host-agent-hook" { return arguments + ["--data-dir", directory] }
        return arguments + ["--home", FileManager.default.homeDirectoryForCurrentUser.path, "--data-dir", directory, "--executable", EngineTools.selfExecutable]
    }
    /// `BoxCop --host-agent-hook <harness>` and `BoxCop --host-agent-integrations <mode>`.
    static func run(_ arguments: [String]) -> Never {
        let hook = arguments.first == "--host-agent-hook"
        let harness = arguments.count > 1 ? arguments[1] : ""
        if arguments.count == 2, HostHookSupervisor.launchModes(arguments[0])?.contains(harness) == true,
           let configuration = EngineTools.configuration() {
            let engineArguments = configuration.arguments + engineArguments(arguments)
            let environment = EngineConfiguration.cleanEnvironment(ProcessInfo.processInfo.environment)
            if hook {
                if let response = HostHookSupervisor.run(executable: configuration.executableURL, arguments: engineArguments, harness: harness, environment: environment) {
                    FileHandle.standardOutput.write(response)
                    FileHandle.standardOutput.write(Data("\n".utf8))
                    exit(0)
                }
                HostHookSupervisor.recordFailure(harness: harness, directory: EngineTools.dataDirectory)
            } else {
                let engine = configuration.executableURL.path
                let argv = ([engine] + engineArguments).map { strdup($0) } + [nil]
                let strings = environment.map { "\($0.key)=\($0.value)" }
                let env: [UnsafeMutablePointer<CChar>?] = strings.map { strdup($0) } + [nil]
                argv.withUnsafeBufferPointer { args in
                    env.withUnsafeBufferPointer { _ = execve(engine, args.baseAddress!, $0.baseAddress!) }
                }
            }
        }
        // The engine could not answer: a hook denies, a status request reports the failure.
        if hook {
            if harness == "cursor" { print("{\"permission\":\"deny\",\"agent_message\":\"BoxCop engine unavailable.\"}") }
            else { print("{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"deny\",\"permissionDecisionReason\":\"BoxCop engine unavailable.\"}}") }
        } else { print("{\"summary\":\"Agent hooks: BoxCop engine unavailable.\"}") }
        exit(hook ? 0 : 1)
    }
    struct Action: Identifiable {
        let id: String
        let state: String
        let lastCallback: String
        let nextStep: String
        var title: String {
            ["Bash": "Shell commands", "Read": "File reads", "Write": "File writes", "Edit": "File edits",
             "beforeShellExecution": "Shell commands", "beforeReadFile": "Agent file reads",
             "beforeTabFileRead": "Tab file reads"][id] ?? id
        }
    }
    struct Connection: Identifiable {
        let id: String
        let state: String
        let coverage: String
        let nextStep: String
        let lastCallback: String
        let actions: [Action]
        var name: String { AgentHookHealth.displayName(id) }
        /// A failing check on one action outranks the summary state.
        var health: AgentHookHealth {
            let failing = actions.map { AgentHookHealth(state: $0.state) }.contains(.needsRepair)
            return failing ? .needsRepair : AgentHookHealth(state: state)
        }
    }
    struct Snapshot {
        let summary: String
        var connections: [Connection] = []
    }
    enum Mode: String { case status, auto, install, remove }
    static func parse(_ bytes: Data) -> Snapshot? {
        guard let row = try? JSONSerialization.jsonObject(with: bytes) as? [String: Any] else { return nil }
        let harnesses = row["harnesses"] as? [String: [String: Any]] ?? [:]
        let connections = harnesses.keys.sorted().map { key -> Connection in
            let detail = harnesses[key] ?? [:]
            let receipt = detail["last_callback"] as? [String: Any]
            return Connection(id: key,
                state: (detail["state"] as? String ?? "unavailable").replacingOccurrences(of: "_", with: " "),
                coverage: detail["coverage"] as? String ?? "",
                nextStep: detail["next_step"] as? String ?? "",
                lastCallback: receipt?["at"] as? String ?? "",
                actions: (detail["actions"] as? [String: [String: Any]] ?? [:]).sorted { $0.key < $1.key }.map { key, action in
                    Action(id: key,
                        state: (action["state"] as? String ?? "unavailable").replacingOccurrences(of: "_", with: " "),
                        lastCallback: (action["last_callback"] as? [String: Any])?["at"] as? String ?? "",
                        nextStep: action["next_step"] as? String ?? "")
                })
        }
        return Snapshot(summary: row["summary"] as? String ?? "", connections: connections)
    }
    /// Reads or changes the hooks through the engine. Nil when the engine is missing or did not answer.
    static func refresh(_ mode: Mode) async -> Snapshot? {
        await EngineTools.runAsync(engineArguments(["--host-agent-integrations", mode.rawValue]), timeout: 10, requireSuccess: false).flatMap(parse)
    }
}
#endif
