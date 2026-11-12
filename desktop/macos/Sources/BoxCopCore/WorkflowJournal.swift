import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

/// Append-only, bounded encrypted record segments. The queue keeps filesystem IO off collector callbacks.
/// Each process opens a new segment, so a crash-truncated tail is never appended to.
public final class WorkflowJournal: @unchecked Sendable {
    public struct State: Codable, Sendable {
        public var written = 0
        public var dropped = 0
        public var failed = false
        public var evictedSegments = 0
    }
    private struct Row: Encodable {
        let schemaVersion = "boxcop.workflow.journal.v1"
        let synthetic: Bool
        let droppedBefore: Int
        let event: WorkflowEvent
    }
    private let queue = DispatchQueue(label: "boxcop.workflow-journal", qos: .utility)
    private let lock = NSLock()
    private var status = State()
    private var pending = 0
    private var buffered: [WorkflowEvent] = []
    private var draining = false
    private let maximumPending: Int
    private let batchSize: Int
    private let directory: URL
    private let segmentBytes: Int
    private let maximumSegments: Int
    private let synthetic: Bool
    private var fd: Int32 = -1
    private var size = 0
    private let encoder: JSONEncoder
    private let encryption: JournalEncryption

    public init(directory: URL, segmentBytes: Int = 8 * 1024 * 1024, maximumSegments: Int = 8, synthetic: Bool = false, maximumPending: Int = 256, batchSize: Int = 1, encryption: JournalEncryption? = nil) throws {
        self.encryption = encryption ?? JournalEncryption(purpose: "workflow")
        self.maximumPending = max(1, min(maximumPending, 8192)); self.batchSize = max(1, min(batchSize, 64))
        self.directory = directory; self.segmentBytes = max(1024, segmentBytes)
        self.maximumSegments = max(1, maximumSegments); self.synthetic = synthetic
        encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        var info = stat()
        guard lstat(directory.path, &info) == 0, info.st_uid == getuid(),
              info.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR), info.st_mode & 0o777 == 0o700 else {
            throw CocoaError(.fileWriteNoPermission)
        }
        // Existing plaintext is replaced before accepting any new events. Migration may
        // expand old segments up to 2x; normal rotation restores the configured cap.
        for file in try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
            where Self.isSegment(file.lastPathComponent) {
            try self.encryption.migrate(file, maximumBytes: self.segmentBytes * 2)
        }
        let healthPath = directory.appendingPathComponent("health.json").path
        let healthFD = open(healthPath, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        if healthFD >= 0 {
            let file = FileHandle(fileDescriptor: healthFD, closeOnDealloc: true)
            let bytes = try file.read(upToCount: 4097) ?? Data()
            guard bytes.count <= 4096 else { throw CocoaError(.fileReadCorruptFile) }
            status = try JSONDecoder().decode(State.self, from: bytes)
            guard status.written >= 0, status.dropped >= 0, status.evictedSegments >= 0 else { throw CocoaError(.fileReadCorruptFile) }
        } else if errno != ENOENT { throw CocoaError(.fileReadNoPermission) }
    }
    deinit { if fd >= 0 { close(fd) } }
    public func state() -> State { lock.lock(); defer { lock.unlock() }; return status }
    public func append(_ event: WorkflowEvent) {
        lock.lock()
        guard pending < maximumPending else { status.dropped += 1; lock.unlock(); return }
        pending += 1; buffered.append(event)
        let schedule = !draining; draining = true
        lock.unlock()
        if schedule { queue.async { [self] in drain() } }
    }
    private func drain() {
        while true {
            lock.lock()
            guard !buffered.isEmpty else { draining = false; lock.unlock(); return }
            let batch = Array(buffered.prefix(batchSize)); buffered.removeFirst(batch.count)
            lock.unlock()
            var written = 0
            do {
                for event in batch {
                    var bytes = try encryption.seal(encoder.encode(Row(synthetic: synthetic, droppedBefore: state().dropped, event: event)))
                    bytes.append(10)
                    guard bytes.count <= segmentBytes else { throw CocoaError(.fileWriteOutOfSpace) }
                    if fd < 0 || size + bytes.count > segmentBytes { try rotate() }
                    try bytes.withUnsafeBytes { buffer in
                        var offset = 0
                        while offset < buffer.count {
                            let count = write(fd, buffer.baseAddress!.advanced(by: offset), buffer.count - offset)
                            if count < 0 && errno == EINTR { continue }
                            guard count > 0 else { throw CocoaError(.fileWriteUnknown) }
                            offset += count
                        }
                    }
                    size += bytes.count; written += 1
                }
                // Batches are acknowledged in health only after reaching durable storage.
                guard fd >= 0, fsync(fd) == 0 else { throw CocoaError(.fileWriteUnknown) }
                lock.lock(); status.written += written; lock.unlock()
            } catch {
                if fd >= 0 { close(fd); fd = -1 }; size = 0
                // Conservatively count the whole batch as potentially lost after an IO failure.
                lock.lock(); status.failed = true; status.dropped += batch.count; lock.unlock()
            }
            lock.lock(); pending -= batch.count; lock.unlock()
            do {
                let health = directory.appendingPathComponent("health.json")
                try encoder.encode(state()).write(to: health, options: [.atomic])
                try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: health.path)
            } catch { lock.lock(); status.failed = true; lock.unlock() }
        }
    }
    private func rotate() throws {
        if fd >= 0 {
            guard fsync(fd) == 0 else { throw CocoaError(.fileWriteUnknown) }
            close(fd); fd = -1
        }
        // Keep segment order monotonic even if the wall clock moves backwards.
        let previous = try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
            .filter { Self.isSegment($0.lastPathComponent) }.sorted { $0.lastPathComponent < $1.lastPathComponent }
        let previousTime = previous.last.flatMap { Double($0.lastPathComponent.split(separator: "-")[0]) } ?? 0
        let timestamp = max(Date().timeIntervalSince1970, previousTime + 0.00001)
        let name = String(format: "%.6f", timestamp) + "-" + UUID().uuidString + ".jsonl"
        let path = directory.appendingPathComponent(name)
        fd = open(path.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
        guard fd >= 0 else { throw CocoaError(.fileWriteUnknown) }
        size = 0
        // Only journal-owned filenames; never remove arbitrary contents of the directory.
        let files = previous + [path]
        for old in files.prefix(max(0, files.count - maximumSegments)) {
            try FileManager.default.removeItem(at: old)
            lock.lock(); status.evictedSegments += 1; lock.unlock()
        }
    }
    static func isSegment(_ name: String) -> Bool {
        name.range(of: #"^[0-9]+\.[0-9]{6}-[0-9A-Fa-f-]{36}\.jsonl$"#, options: .regularExpression) != nil
    }
    public func flush() async {
        await withCheckedContinuation { continuation in
            queue.async { continuation.resume() }
        }
    }
}
