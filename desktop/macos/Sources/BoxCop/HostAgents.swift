#if os(macOS)
import Foundation
import Darwin
import BoxCopCore

/// User-level integrations use the same installed app and bundled engine, independently of clipboard monitoring.
/// These are cooperative vendor hooks, not Endpoint Security or a system-wide sandbox.
enum HostAgents {
    static func run(_ arguments: [String]) -> Never {
        let hook = arguments.first == "--host-agent-hook"
        // Opt-in advisory end-of-turn entry: hook-shaped, but every failure prints {} and exits 0.
        let correction = arguments.first == "--host-agent-correction"
        let corrections = arguments.first == "--agent-corrections"
        let transfer = arguments.first == "--reviewed-transfer"
        let provider = arguments.first == "--provider-integrations" || transfer
        let harness = arguments.count > 1 ? arguments[1] : ""
        do {
            let valid = provider
                ? (arguments.count == 3 && arguments[1] == "--config" && arguments[2].hasPrefix("/") && !arguments[2].contains("\0"))
                : (arguments.count == 2 && HostHookSupervisor.launchModes(arguments[0])?.contains(harness) == true)
            guard valid,
                  Bundle.main.bundleURL.pathExtension == "app" else { throw EngineFailure.invalidConfiguration }
            let home = FileManager.default.homeDirectoryForCurrentUser
            let directory = home.appendingPathComponent("Library/Application Support/BoxCop")
            let engine = Bundle.main.bundleURL.appendingPathComponent("Contents/Resources/engine/boxcop-engine").path
            let executable = Bundle.main.bundleURL.appendingPathComponent("Contents/MacOS/BoxCop").path
            var argvStrings: [String] = [engine]
            argvStrings.append(contentsOf: arguments)
            if transfer {
                argvStrings.append(contentsOf: ["--executable", executable, "--data-dir", directory.appendingPathComponent("reviewed-transfers").path])
            } else if hook || correction {
                argvStrings.append(contentsOf: ["--data-dir", directory.path])
            } else if !provider {
                argvStrings.append(contentsOf: ["--home", home.path, "--data-dir", directory.path, "--executable", executable])
            }
            if correction {
                // Never HostHookSupervisor.recordFailure: that receipt marks protection hooks as failing.
                FileHandle.standardOutput.write(HostHookSupervisor.correction(executable: URL(fileURLWithPath: engine),
                    arguments: Array(argvStrings.dropFirst()), harness: harness,
                    environment: EngineConfiguration.cleanEnvironment(ProcessInfo.processInfo.environment)))
                FileHandle.standardOutput.write(Data("\n".utf8))
                exit(0)
            }
            if hook {
                let environment = EngineConfiguration.cleanEnvironment(ProcessInfo.processInfo.environment)
                if let response = HostHookSupervisor.run(executable: URL(fileURLWithPath: engine),
                    arguments: Array(argvStrings.dropFirst()), harness: harness, environment: environment) {
                    FileHandle.standardOutput.write(response)
                    FileHandle.standardOutput.write(Data("\n".utf8))
                    exit(0)
                }
                HostHookSupervisor.recordFailure(harness: harness, directory: directory)
                throw EngineFailure.invalidConfiguration
            }
            let argv = argvStrings.map { strdup($0) } + [nil]
            let strings = EngineConfiguration.cleanEnvironment(ProcessInfo.processInfo.environment).map { "\($0.key)=\($0.value)" }
            let environment: [UnsafeMutablePointer<CChar>?] = strings.map { strdup($0) } + [nil]
            argv.withUnsafeBufferPointer { args in
                environment.withUnsafeBufferPointer { _ = execve(engine, args.baseAddress!, $0.baseAddress!) }
            }
        } catch { }
        if correction { print("{}"); exit(0) }
        if hook {
            if harness == "cursor" { print("{\"permission\":\"deny\",\"agent_message\":\"BoxCop engine unavailable.\"}") }
            else { print("{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"deny\",\"permissionDecisionReason\":\"BoxCop engine unavailable.\"}}") }
        } else if provider { print("{\"schema\":\"boxcop.provider-observation.v1\",\"ok\":false,\"result\":{\"status\":\"unverified\",\"reason\":\"engine_unavailable\"}}") }
        else if corrections { print("{\"summary\":\"Agent corrections: installed app unavailable.\"}") }
        else { print("{\"summary\":\"Agent hooks: installed app unavailable.\"}") }
        exit(hook ? 0 : 1)
    }
    struct Action: Identifiable {
        let id: String
        let state: String
        let lastCallback: String
        let nextStep: String
        let verification: String
        var title: String {
            ["Bash": "Shell commands", "Read": "File reads", "Write": "File writes", "Edit": "File edits",
             "beforeShellExecution": "Shell commands", "beforeReadFile": "Agent file reads",
             "beforeTabFileRead": "Tab file reads"][id] ?? id
        }
    }
    static func verificationText(_ evidence: [String: Any]?) -> String {
        let state = evidence?["state"] as? String ?? "unverified"
        let scope = evidence?["scope"] as? String ?? "No bound effect test recorded."
        switch state {
        case "effect_verified":
            let version = evidence?["vendor_version"] as? String ?? "unknown version"
            let installation = evidence?["vendor_kind"] as? String == "cursor_desktop" ? "Recorded desktop installation" : "Recorded CLI"
            return "Effect verified: " + scope + " · " + version + ". " + installation + " only; valid for 24 hours while build and hook configuration match."
        case "invalidated": return "Effect evidence invalidated: installation, hooks or callback health changed. Run a fresh effect test."
        case "expired": return "Effect evidence expired. Run a fresh effect test."
        case "failed": return "Last effect test failed. Repair and retest."
        case "unavailable": return "Effect evidence unavailable. Recheck and retest."
        default: return "Effect unverified. Callback delivery alone is not an effect test."
        }
    }
    struct Connection: Identifiable {
        let id: String
        let state: String
        let coverage: String
        let nextStep: String
        let lastCallback: String
        let actions: [Action]
    }
    struct Snapshot {
        let summary: String
        var connections: [Connection] = []
    }
    static func refresh(install: Bool, remove: Bool = false, explicit: Bool = false) async -> Snapshot {
        await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .utility).async {
                let process = Process(), output = Pipe()
                process.executableURL = Bundle.main.bundleURL.appendingPathComponent("Contents/MacOS/BoxCop")
                process.arguments = ["--host-agent-integrations", remove ? "remove" : (install ? (explicit ? "install" : "auto") : "status")]
                process.standardOutput = output; process.standardError = FileHandle.nullDevice
                process.standardInput = FileHandle.nullDevice
                do {
                    try process.run()
                    DispatchQueue.global().asyncAfter(deadline: .now() + 10) { if process.isRunning { process.terminate() } }
                    let bytes = output.fileHandleForReading.readDataToEndOfFile()
                    let row = try JSONSerialization.jsonObject(with: bytes) as? [String: Any]
                    let harnesses = row?["harnesses"] as? [String: [String: Any]] ?? [:]
                    let connections = harnesses.keys.sorted().map { key in
                        let detail = harnesses[key] ?? [:]
                        let receipt = detail["last_callback"] as? [String: Any]
                        return Connection(id: key,
                            state: (detail["state"] as? String ?? "unavailable").replacingOccurrences(of: "_", with: " "),
                            coverage: detail["coverage"] as? String ?? "Coverage unavailable",
                            nextStep: detail["next_step"] as? String ?? "Recheck the integration.",
                            lastCallback: receipt?["at"] as? String ?? "None recorded",
                            actions: (detail["actions"] as? [String: [String: Any]] ?? [:]).sorted { $0.key < $1.key }.map { key, action in
                                Action(id: key,
                                    state: (action["state"] as? String ?? "unavailable").replacingOccurrences(of: "_", with: " "),
                                    lastCallback: (action["last_callback"] as? [String: Any])?["at"] as? String ?? "None recorded",
                                    nextStep: action["next_step"] as? String ?? "Recheck the integration.",
                                    verification: verificationText(action["verification"] as? [String: Any]))
                            })
                    }
                    continuation.resume(returning: Snapshot(summary: row?["summary"] as? String ?? "Agent hooks: status unavailable", connections: connections))
                } catch { continuation.resume(returning: Snapshot(summary: "Agent hooks: installed app required")) }
            }
        }
    }
}
#endif
