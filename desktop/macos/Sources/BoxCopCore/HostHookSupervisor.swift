import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

/// Keeps a native parent alive to deny when the policy engine cannot answer.
/// Vendor termination of this parent remains outside this cooperative boundary.
public enum HostHookSupervisor {
    public static func run(executable: URL, arguments: [String], harness: String,
                           environment: [String: String], input: FileHandle = .standardInput,
                           timeout: TimeInterval = 3.5,
                           validate: (Data, String) -> Data? = HostHookSupervisor.validatedResponse(_:harness:)) -> Data? {
        let process = Process(), output = Pipe(), exited = DispatchSemaphore(value: 0)
        process.executableURL = executable
        process.arguments = arguments
        process.environment = environment
        process.standardInput = input
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        process.terminationHandler = { _ in exited.signal() }
        let reader = output.fileHandleForReading
        let fd = reader.fileDescriptor
        let flags = fcntl(fd, F_GETFL)
        guard flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 else { return nil }
        defer { try? reader.close(); try? output.fileHandleForWriting.close() }
        do { try process.run() } catch { return nil }
        try? output.fileHandleForWriting.close()
        var finished = false
        defer {
            if !finished {
                if process.isRunning { _ = kill(process.processIdentifier, SIGKILL) }
                _ = exited.wait(timeout: .now() + 0.2)
            }
        }
        let deadline = ProcessInfo.processInfo.systemUptime + timeout
        var bytes = Data(), chunk = [UInt8](repeating: 0, count: 8192)
        while ProcessInfo.processInfo.systemUptime < deadline {
            let count = chunk.withUnsafeMutableBytes { read(fd, $0.baseAddress, $0.count) }
            if count > 0 {
                guard bytes.count + count <= 65536 else { return nil }
                bytes.append(contentsOf: chunk.prefix(count))
                continue
            }
            if count < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR { return nil }
            if !finished { finished = exited.wait(timeout: .now()) == .success }
            if finished {
                guard process.terminationReason == .exit, process.terminationStatus == 0 else { return nil }
                return validate(bytes, harness)
            }
            Thread.sleep(forTimeInterval: 0.005)
        }
        return nil
    }

    public static func validatedResponse(_ bytes: Data, harness: String) -> Data? {
        guard ["claude", "codex", "cursor"].contains(harness), bytes.count <= 65536,
              let object = try? JSONSerialization.jsonObject(with: bytes) as? [String: Any] else { return nil }
        if harness == "cursor" {
            guard let permission = object["permission"] as? String, ["allow", "deny"].contains(permission) else { return nil }
        } else if !object.isEmpty {
            guard let response = object["hookSpecificOutput"] as? [String: Any],
                  response["hookEventName"] as? String == "PreToolUse",
                  response["permissionDecision"] as? String == "deny" else { return nil }
        }
        return bytes
    }

    /// Accepted second argument for each agent-hook launcher flag; nil for other flags.
    public static func launchModes(_ flag: String) -> [String]? {
        switch flag {
        case "--host-agent-hook": return ["claude", "codex", "cursor"]
        case "--host-agent-integrations": return ["auto", "install", "status", "remove"]
        case "--host-agent-correction": return ["claude", "codex"]
        case "--agent-corrections": return ["status", "enable", "disable", "send", "record"]
        default: return nil
        }
    }

    /// Advisory end-of-turn correction entry. Same deadline as the preflight, but it
    /// fails open: any engine failure or unexpected output becomes `{}`. It can never
    /// yield a PreToolUse denial and never writes a supervisor failure receipt.
    public static func correction(executable: URL, arguments: [String], harness: String,
                                  environment: [String: String], input: FileHandle = .standardInput,
                                  timeout: TimeInterval = 3.5) -> Data {
        run(executable: executable, arguments: arguments, harness: harness, environment: environment,
            input: input, timeout: timeout, validate: validatedCorrection(_:harness:)) ?? Data("{}".utf8)
    }

    /// Exactly `{}`, a Stop continuation, or a person-visible notice; nothing else passes.
    public static func validatedCorrection(_ bytes: Data, harness: String) -> Data? {
        guard ["claude", "codex"].contains(harness), bytes.count <= 65536,
              let object = try? JSONSerialization.jsonObject(with: bytes) as? [String: Any] else { return nil }
        if object.isEmpty { return bytes }
        if Set(object.keys) == ["decision", "reason"], object["decision"] as? String == "block",
           let reason = object["reason"] as? String, !reason.isEmpty { return bytes }
        if Set(object.keys) == ["systemMessage"], let message = object["systemMessage"] as? String, !message.isEmpty { return bytes }
        return nil
    }

    public static func recordFailure(harness: String, directory: URL) {
        guard ["claude", "codex", "cursor"].contains(harness) else { return }
        var info = stat()
        guard lstat(directory.path, &info) == 0, info.st_mode & S_IFMT == S_IFDIR,
              info.st_uid == getuid(), info.st_mode & 0o077 == 0 else { return }
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let record: [String: Any] = ["schema_version": 1, "harness": harness, "state": "error",
                                     "at": formatter.string(from: Date()), "source": "native_supervisor"]
        let path = directory.appendingPathComponent(harness + "-supervisor-receipt.json")
        guard let bytes = try? JSONSerialization.data(withJSONObject: record) else { return }
        do {
            try bytes.write(to: path, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path.path)
        } catch { /* Failure to write diagnostics must never change the denial. */ }
    }
}
