#if os(macOS)
import Foundation
import Darwin
import BoxCopCore

/// Where the engine and its data live, and one-shot engine runs outside the pipe service.
enum EngineTools {
    /// True inside an installed or built `.app`. Development overrides are ignored there.
    static var packaged: Bool {
        var url = Bundle.main.bundleURL.standardizedFileURL
        while url.path != "/" {
            if url.pathExtension.lowercased() == "app" { return true }
            url.deleteLastPathComponent()
        }
        return false
    }
    /// One directory for everything. `BOXCOP_DATA_DIR` moves it for development runs outside an app bundle.
    static var dataDirectory: URL {
        if !packaged, let path = ProcessInfo.processInfo.environment["BOXCOP_DATA_DIR"], path.hasPrefix("/"), !path.contains("\0") {
            return URL(fileURLWithPath: path, isDirectory: true)
        }
        return FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/BoxCop", isDirectory: true)
    }
    static func configuration(dataDirectory: URL? = nil) -> EngineConfiguration? {
        try? EngineConfiguration.resolve(bundleURL: Bundle.main.bundleURL, environment: ProcessInfo.processInfo.environment,
                                         dataDirectory: dataDirectory ?? self.dataDirectory)
    }
    static var available: Bool {
        configuration().map { FileManager.default.isExecutableFile(atPath: $0.executableURL.path) } ?? false
    }
    /// The local model runtime sits next to the frozen engine. Source runs find their own copy.
    static var inferenceAvailable: Bool {
        guard let configuration = configuration() else { return false }
        guard packaged else { return true }
        let runtime = configuration.executableURL.deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("inference/llama-server")
        return FileManager.default.isExecutableFile(atPath: runtime.path)
    }
    static var selfExecutable: String { Bundle.main.executablePath ?? CommandLine.arguments[0] }

    /// Runs the engine once and returns its standard output. Blocks the calling thread; never call it on the main thread from the app.
    static func run(_ arguments: [String], input: Data? = nil, timeout: TimeInterval? = 15, limit: Int = 2 * 1024 * 1024, requireSuccess: Bool = true) -> Data? {
        guard let configuration = configuration() else { return nil }
        let process = Process(), output = Pipe(), stdin = Pipe()
        process.executableURL = configuration.executableURL
        process.arguments = configuration.arguments + arguments
        process.environment = EngineConfiguration.cleanEnvironment(ProcessInfo.processInfo.environment)
        if configuration.arguments.isEmpty { process.currentDirectoryURL = configuration.executableURL.deletingLastPathComponent() }
        process.standardInput = input == nil ? FileHandle.nullDevice : stdin
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        do { try process.run() } catch { return nil }
        let pid = process.processIdentifier
        let killer = DispatchWorkItem { if process.isRunning { kill(pid, SIGKILL) } }
        if let timeout { DispatchQueue.global().asyncAfter(deadline: .now() + timeout, execute: killer) }
        defer { killer.cancel(); try? output.fileHandleForReading.close() }
        if let input {
            try? stdin.fileHandleForWriting.write(contentsOf: input)
            try? stdin.fileHandleForWriting.close()
        }
        var bytes = Data(), oversized = false
        while let chunk = try? output.fileHandleForReading.read(upToCount: 65536), !chunk.isEmpty {
            if bytes.count + chunk.count <= limit { bytes.append(chunk) } else { oversized = true }
        }
        process.waitUntilExit()
        guard !oversized, !requireSuccess || process.terminationStatus == 0 else { return nil }
        return bytes
    }
    static func runAsync(_ arguments: [String], input: Data? = nil, timeout: TimeInterval? = 15, requireSuccess: Bool = true,
                         priority: DispatchQoS.QoSClass = .utility) async -> Data? {
        await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: priority).async {
                continuation.resume(returning: run(arguments, input: input, timeout: timeout, requireSuccess: requireSuccess))
            }
        }
    }
}
#endif
