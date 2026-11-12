import Foundation
#if os(macOS)
import Darwin
#else
import Glibc
#endif

/// Serial caller only. Two size-bounded, owner-only encrypted record files; no payloads.
public final class NetworkActivityJournal {
    public let limit: Int
    private let directory: URL
    private let encryption: JournalEncryption
    private var current: URL { directory.appendingPathComponent("connections.jsonl") }
    private var previous: URL { directory.appendingPathComponent("connections.previous.jsonl") }
    public init(directory: URL, limit: Int = 4 * 1024 * 1024, encryption: JournalEncryption? = nil) throws {
        self.encryption = encryption ?? JournalEncryption(purpose: "network")
        self.directory = directory; self.limit = max(1024, limit)
        var info = stat()
        guard lstat(directory.path, &info) == 0, info.st_mode & S_IFMT == S_IFDIR,
              info.st_uid == geteuid(), info.st_mode & 0o077 == 0 else { throw CocoaError(.fileReadNoPermission) }
        try self.encryption.migrate(current, maximumBytes: self.limit * 2)
        try self.encryption.migrate(previous, maximumBytes: self.limit * 2)
        _ = try read(current); _ = try read(previous)
    }
    private func read(_ url: URL) throws -> Data {
        let fd = open(url.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        if fd < 0 { if errno == ENOENT { return Data() }; throw CocoaError(.fileReadNoPermission) }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_uid == geteuid(),
              info.st_mode & 0o077 == 0, info.st_size <= limit * 2 else { throw CocoaError(.fileReadNoPermission) }
        return try FileHandle(fileDescriptor: fd, closeOnDealloc: false).readToEnd() ?? Data()
    }
    public func events() throws -> [NetworkActivityEvent] {
        let decoder = JSONDecoder()
        return try [previous, current].flatMap { url in
            try read(url).split(separator: 10).map { try decoder.decode(NetworkActivityEvent.self, from: encryption.open(Data($0))) }
        }
    }
    public func append(_ event: NetworkActivityEvent) throws {
        var data = try encryption.seal(JSONEncoder().encode(event)); data.append(10)
        guard data.count <= limit else { throw CocoaError(.fileWriteOutOfSpace) }
        var info = stat()
        if lstat(current.path, &info) == 0, info.st_size > off_t(limit - data.count) {
            _ = try read(current)
            guard rename(current.path, previous.path) == 0 else { throw CocoaError(.fileWriteUnknown) }
        }
        let fd = open(current.path, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw CocoaError(.fileWriteNoPermission) }
        defer { close(fd) }
        guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_uid == geteuid(), info.st_mode & 0o077 == 0 else { throw CocoaError(.fileWriteNoPermission) }
        try FileHandle(fileDescriptor: fd, closeOnDealloc: false).write(contentsOf: data)
    }
}
