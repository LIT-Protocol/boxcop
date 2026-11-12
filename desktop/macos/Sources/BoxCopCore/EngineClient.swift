import Foundation
#if os(Linux)
import Glibc
#else
import Darwin
#endif

public struct EngineConfiguration: Sendable {
    public let executableURL: URL
    public let arguments: [String]
    public let dataDirectory: URL
    public init(executableURL: URL, arguments: [String] = [], dataDirectory: URL) {
        self.executableURL = executableURL; self.arguments = arguments; self.dataDirectory = dataDirectory
    }
    /// Interpreter, dynamic-loader and development-override variables never reach the helper.
    public static func cleanEnvironment(_ environment: [String: String]) -> [String: String] {
        let blocked = ["PYTHON", "DYLD_", "LD_", "BOXCOP_ENGINE_"]
        return environment.filter { entry in !blocked.contains { entry.key.hasPrefix($0) } }
    }
    public static func resolve(bundleURL: URL, environment: [String: String], dataDirectory: URL) throws -> EngineConfiguration {
        // Also reject overrides when invoked from a nested executable in an .app.
        var ancestor = bundleURL.standardizedFileURL
        while ancestor.path != "/" {
            if ancestor.pathExtension.lowercased() == "app" {
                return EngineConfiguration(executableURL: ancestor.appendingPathComponent("Contents/Resources/engine/boxcop-engine"), dataDirectory: dataDirectory)
            }
            ancestor.deleteLastPathComponent()
        }
        guard let path = environment["BOXCOP_ENGINE_EXECUTABLE"], path.hasPrefix("/"), !path.contains("\0") else { throw EngineFailure.invalidConfiguration }
        var args: [String] = []
        if let encoded = environment["BOXCOP_ENGINE_ARGUMENTS"] {
            guard encoded.utf8.count <= 16384, let data = encoded.data(using: .utf8), let decoded = try? JSONDecoder().decode([String].self, from: data), decoded.count <= 64,
                  decoded.allSatisfy({ !$0.contains("\0") }) else { throw EngineFailure.invalidConfiguration }
            args = decoded
        }
        return EngineConfiguration(executableURL: URL(fileURLWithPath: path), arguments: args, dataDirectory: dataDirectory)
    }
}

public struct EngineSnapshot: Sendable {
    public let ready: Bool
    public let pid: Int32?
}

/// Serialized state, a single stdout reader per owned process, and bounded asynchronous writers.
/// Neither caller/MainActor nor event taps wait on a pipe or process launch, and no thread ever
/// blocks waiting for a child to exit: reaping is signalled by `terminationHandler`.
public final class EngineClient: @unchecked Sendable {
    private struct Pending {
        let operation: String
        let continuation: CheckedContinuation<EngineResult, Error>
    }
    private struct OwnedChild {
        let process: Process
        let exit: ChildExit
    }
    private final class Session {
        let id = UUID()
        let child: OwnedChild
        let writer: PipeWriter
        var ready = false
        var startup: StartupCancellation?
        var pending: [String: Pending] = [:]
        init(child: OwnedChild, writer: PipeWriter) { self.child = child; self.writer = writer }
    }
    private let queue = DispatchQueue(label: "app.boxcop.engine-state")
    private let writes = DispatchQueue(label: "app.boxcop.engine-writes", qos: .utility)
    private var session: Session?
    private var retired: [OwnedChild] = []
    private let timeout: TimeInterval
    /// The readiness handshake may include a slow first launch while macOS validates bundled code.
    private let startupTimeout: TimeInterval
    private let capacity: Int
    private let admission: RequestAdmission
    private let onFailure: (@Sendable (EngineFailure) -> Void)?
    public init(requestTimeout: TimeInterval = 3, startupTimeout: TimeInterval = 20, maximumPending: Int = 8, onFailure: (@Sendable (EngineFailure) -> Void)? = nil) {
        self.onFailure = onFailure
        timeout = requestTimeout.isFinite && requestTimeout > 0 ? requestTimeout : 3
        self.startupTimeout = startupTimeout.isFinite && startupTimeout > 0 ? startupTimeout : 20
        let limit = max(1, min(maximumPending, 32))
        capacity = limit
        admission = RequestAdmission(limit: limit)
        // Pipe closure is an error, never a process-wide SIGPIPE crash.
        signal(SIGPIPE, SIG_IGN)
    }
    public func snapshot() async -> EngineSnapshot {
        await withCheckedContinuation { continuation in
            queue.async { continuation.resume(returning: EngineSnapshot(ready: self.session?.ready == true, pid: self.session?.child.process.processIdentifier)) }
        }
    }
    public func start(configuration: EngineConfiguration) async throws {
        let cancellation = StartupCancellation()
        try await withTaskCancellationHandler(operation: {
            await stop()
            if Task.isCancelled || cancellation.cancelled { throw EngineFailure.cancelled }
            let _: EngineResult = try await withCheckedThrowingContinuation { continuation in
                queue.async {
                    guard !cancellation.cancelled else { continuation.resume(throwing: EngineFailure.cancelled); return }
                    do {
                        // A concurrent start is a new generation, never a second live session.
                        self.disconnect(.cancelled)
                        let session = try self.launch(configuration)
                        session.startup = cancellation
                        self.session = session
                        if cancellation.cancelled { self.disconnect(.cancelled); continuation.resume(throwing: EngineFailure.cancelled); return }
                        self.enqueue(.status, continuation: continuation, session: session, deadline: self.startupTimeout)
                    } catch {
                        continuation.resume(throwing: EngineFailure.launchFailed)
                    }
                }
            }
        }, onCancel: {
            cancellation.cancel()
            self.queue.async { if self.session?.startup === cancellation { self.disconnect(.cancelled) } }
        })
    }
    public func request(_ command: EngineCommand) async throws -> EngineResult {
        if Task.isCancelled { throw EngineFailure.cancelled }
        guard admission.acquire() else { throw EngineFailure.backpressure }
        defer { admission.release() }
        return try await withCheckedThrowingContinuation { continuation in
            queue.async {
                guard let session = self.session, session.ready else { continuation.resume(throwing: EngineFailure.notReady); return }
                self.enqueue(command, continuation: continuation, session: session)
            }
        }
    }
    /// Pause/quit: close input, terminate (then force-kill if necessary), and reap owned children.
    public func stop() async {
        let children: [OwnedChild] = await withCheckedContinuation { continuation in
            queue.async {
                self.disconnect(.cancelled)
                let children = self.retired
                self.retired = []
                continuation.resume(returning: children)
            }
        }
        // Not Process.waitUntilExit(): off the main thread it sleeps in a run loop and was
        // observed on GitHub-hosted Macs to miss its wake-up after the child had already been reaped.
        for child in children { await child.exit.wait() }
    }
    private func launch(_ config: EngineConfiguration) throws -> Session {
        guard config.executableURL.isFileURL, config.dataDirectory.isFileURL else { throw EngineFailure.invalidConfiguration }
        let process = Process(); let input = Pipe(); let output = Pipe()
        process.executableURL = config.executableURL
        process.arguments = config.arguments + ["--data-dir", config.dataDirectory.path]
        process.environment = EngineConfiguration.cleanEnvironment(ProcessInfo.processInfo.environment)
        // No inherited working directory or network listener is used by the protocol.
        process.currentDirectoryURL = config.executableURL.deletingLastPathComponent()
        process.standardInput = input; process.standardOutput = output
        process.standardError = FileHandle.nullDevice // no raw traceback/diagnostic persistence or console echo
        let exit = ChildExit()
        // Installed before launch, so even an immediate exit is observed. Foundation reaps the child first.
        process.terminationHandler = { _ in exit.markExited() }
        let writer = try PipeWriter(input.fileHandleForWriting)
        try process.run()
        try? input.fileHandleForReading.close(); try? output.fileHandleForWriting.close()
        let session = Session(child: OwnedChild(process: process, exit: exit), writer: writer)
        let id = session.id
        let reader = output.fileHandleForReading
        // Exactly one reader. Synchronous handoff bounds queued response memory even for a noisy peer.
        DispatchQueue.global(qos: .utility).async { [weak self] in
            var framer = JSONLFramer()
            defer { try? reader.close() }
            do {
                var bytes = [UInt8](repeating: 0, count: 8192)
                while true {
                    // POSIX read returns an available short read. Foundation read(upToCount:)
                    // can wait to fill the requested count on Linux pipes, deadlocking JSONL handshakes.
                    let count = bytes.withUnsafeMutableBytes { read(reader.fileDescriptor, $0.baseAddress, $0.count) }
                    if count < 0 { if errno == EINTR { continue }; throw EngineFailure.disconnected }
                    if count == 0 { try framer.finish(); break }
                    let frames = try framer.feed(Data(bytes.prefix(count)))
                    guard let self else { break }
                    let keepReading: Bool = self.queue.sync {
                        guard self.session?.id == id else { return false }
                        for frame in frames {
                            do { try self.receive(frame, sessionID: id) }
                            catch { self.disconnect((error as? EngineFailure) ?? .protocolViolation); return false }
                        }
                        return self.session?.id == id
                    }
                    if !keepReading { break }
                }
                self?.queue.async { [weak self] in if self?.session?.id == id { self?.disconnect(.disconnected) } }
            } catch {
                let failure = (error as? EngineFailure) ?? .disconnected
                self?.queue.async { [weak self] in if self?.session?.id == id { self?.disconnect(failure) } }
            }
        }
        return session
    }
    private func enqueue(_ command: EngineCommand, continuation: CheckedContinuation<EngineResult, Error>, session: Session, deadline limit: TimeInterval? = nil) {
        let timeout = limit ?? self.timeout
        guard session.pending.count < capacity else { continuation.resume(throwing: EngineFailure.backpressure); return }
        let id = UUID().uuidString
        let bytes: Data
        do { bytes = try WireCodec.encode(id: id, command: command) + Data([10]) }
        catch { continuation.resume(throwing: (error as? EngineFailure) ?? EngineFailure.invalidRequest); return }
        session.pending[id] = Pending(operation: command.operation, continuation: continuation)
        let sessionID = session.id
        let deadline = ProcessInfo.processInfo.systemUptime + timeout
        let writer = session.writer
        writes.async { [weak self] in
            do { try writer.send(bytes, deadline: deadline) }
            catch {
                let failure = (error as? EngineFailure) ?? .disconnected
                self?.queue.async { [weak self] in if self?.session?.id == sessionID { self?.disconnect(failure) } }
            }
        }
        queue.asyncAfter(deadline: .now() + timeout) { [weak self] in
            guard let self, self.session?.id == sessionID, self.session?.pending[id] != nil else { return }
            self.disconnect(.timedOut)
        }
    }
    private func receive(_ data: Data, sessionID: UUID) throws {
        guard let session, session.id == sessionID else { return }
        let response = try WireCodec.decode(data)
        guard let id = response.id, let request = session.pending[id] else { throw EngineFailure.protocolViolation }
        if let failure = response.failure {
            session.pending.removeValue(forKey: id)
            request.continuation.resume(throwing: failure)
            if request.operation == "status" { disconnect(failure) }
            return
        }
        guard let result = response.result, result.matches(request.operation) else { throw EngineFailure.protocolViolation }
        if request.operation == "status" { session.ready = true }
        session.pending.removeValue(forKey: id)
        request.continuation.resume(returning: result)
    }
    private func disconnect(_ failure: EngineFailure) {
        guard let previous = session else { return }
        session = nil
        previous.writer.close()
        for pending in previous.pending.values { pending.continuation.resume(throwing: failure) }
        previous.pending.removeAll()
        if failure != .cancelled { onFailure?(failure) }
        let child = previous.child
        retired.removeAll { $0.exit.hasExited }
        retired.append(child)
        let process = child.process
        if process.isRunning {
            process.terminate()
            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 0.3) {
                if !child.exit.hasExited && process.isRunning { _ = kill(process.processIdentifier, SIGKILL) }
            }
        }
    }
    deinit {
        // Usually stop() owns cleanup. This also prevents an accidentally dropped client orphaning its helper.
        if let session {
            session.writer.close()
            for pending in session.pending.values { pending.continuation.resume(throwing: EngineFailure.cancelled) }
            if session.child.process.isRunning { _ = kill(session.child.process.processIdentifier, SIGKILL) }
        }
    }
}

/// Exit signal for one owned child, set from `Process.terminationHandler` (after Foundation
/// reaps it). Waiters suspend instead of blocking a thread, so stop() cannot strand a
/// cooperative-pool thread or depend on any thread's run loop.
private final class ChildExit: @unchecked Sendable {
    private let lock = NSLock()
    private var exited = false
    private var waiters: [CheckedContinuation<Void, Never>] = []
    var hasExited: Bool { lock.lock(); defer { lock.unlock() }; return exited }
    func markExited() {
        lock.lock()
        exited = true
        let ready = waiters
        waiters.removeAll()
        lock.unlock()
        for waiter in ready { waiter.resume() }
    }
    func wait() async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            lock.lock()
            if exited { lock.unlock(); continuation.resume(); return }
            waiters.append(continuation)
            lock.unlock()
        }
    }
}

/// Admission occurs BEFORE scheduling a closure containing a transient payload.
/// Thus even a busy state queue cannot accumulate an unbounded queue of raw requests.
private final class RequestAdmission: @unchecked Sendable {
    private let lock = NSLock()
    private let limit: Int
    private var pending = 0
    init(limit: Int) { self.limit = limit }
    func acquire() -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard pending < limit else { return false }
        pending += 1; return true
    }
    func release() { lock.lock(); pending -= 1; lock.unlock() }
}

private final class StartupCancellation: @unchecked Sendable {
    private let lock = NSLock()
    private var value = false
    var cancelled: Bool { lock.lock(); defer { lock.unlock() }; return value }
    func cancel() { lock.lock(); value = true; lock.unlock() }
}

private final class PipeWriter: @unchecked Sendable {
    private let handle: FileHandle
    private let lock = NSLock()
    private var active = true
    init(_ handle: FileHandle) throws {
        self.handle = handle
        let flags = fcntl(handle.fileDescriptor, F_GETFL)
        guard flags >= 0, fcntl(handle.fileDescriptor, F_SETFL, flags | O_NONBLOCK) >= 0 else { throw EngineFailure.launchFailed }
    }
    func close() { lock.lock(); defer { lock.unlock() }; if active { active = false; try? handle.close() } }
    func send(_ data: Data, deadline: TimeInterval) throws {
        var offset = 0
        while offset < data.count {
            guard ProcessInfo.processInfo.systemUptime < deadline else { throw EngineFailure.timedOut }
            lock.lock()
            guard active else { lock.unlock(); throw EngineFailure.cancelled }
            let written = data.withUnsafeBytes { bytes -> Int in
                guard let address = bytes.baseAddress else { return 0 }
                return write(handle.fileDescriptor, address.advanced(by: offset), bytes.count - offset)
            }
            let code = errno
            lock.unlock()
            if written > 0 { offset += written }
            else if written < 0 && (code == EAGAIN || code == EWOULDBLOCK || code == EINTR) {
                // Only the dedicated writer waits; state queue deadlines, UI and event tap remain responsive.
                usleep(10_000)
            } else { throw EngineFailure.disconnected }
        }
    }
}
