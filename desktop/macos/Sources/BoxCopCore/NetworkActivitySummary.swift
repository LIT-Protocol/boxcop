import Foundation
#if os(macOS)
import Darwin
#else
import Glibc
#endif

public struct NetworkSummaryRow: Codable, Identifiable, Sendable {
    public var id: String { [String(day.timeIntervalSince1970), app, process, destination, isDomain.description].joined(separator: "\n") }
    public let day: Date
    public let app: String
    public let process: String
    public let destination: String
    public let isDomain: Bool
    public var attempts: Int
    public var blocked: Int
    public var blockedReason: String?
    public var firstSeen: Date
    public var lastSeen: Date
    // Conservative JSON bound, including escaping, to bound checkpoints and socket replies.
    fileprivate var storageBound: Int { 1024 + 6 * (app.utf8.count + process.utf8.count + destination.utf8.count) }
    public var appName: String { URL(fileURLWithPath: app).lastPathComponent }
    public var processName: String { URL(fileURLWithPath: process).lastPathComponent }
}

/// Daily app/process/destination counters, independent of raw journal rotation.
public struct NetworkActivitySummary: Codable, Sendable {
    public var rows: [NetworkSummaryRow] = []
    public var since: Date
    public var omitted = 0
    public static let capacity = 4000
    public init(since: Date = Date()) { self.since = since }
    public mutating func prune(now: Date = Date(), calendar: Calendar = .current) {
        let cutoff = calendar.date(byAdding: .day, value: -6, to: calendar.startOfDay(for: now))!
        rows.removeAll { $0.lastSeen < cutoff }
    }
    public mutating func record(_ event: NetworkActivityEvent, now: Date = Date(), calendar: Calendar = .current) {
        prune(now: now, calendar: calendar)
        let day = calendar.startOfDay(for: event.timestamp)
        guard day >= calendar.date(byAdding: .day, value: -6, to: calendar.startOfDay(for: now))! else { return }
        let process = event.process.executable ?? event.process.name ?? "Unknown process"
        let app = event.responsibleApp.executable ?? event.responsibleApp.name ?? process
        let host = (event.threat?.hostname ?? event.hostname).map { $0.lowercased().hasSuffix(".") ? String($0.lowercased().dropLast()) : $0.lowercased() }
        let row = NetworkSummaryRow(day: day, app: app, process: process,
            destination: host ?? event.remoteAddress ?? "Unknown destination", isDomain: host != nil,
            attempts: 1, blocked: event.threat == nil ? 0 : 1, blockedReason: event.threat?.reason, firstSeen: event.timestamp, lastSeen: event.timestamp)
        if let index = rows.firstIndex(where: { $0.day == day && $0.app == app && $0.process == process && $0.destination == row.destination && $0.isDomain == row.isDomain }) {
            rows[index].attempts += 1; rows[index].blocked += row.blocked
            if let reason = row.blockedReason { rows[index].blockedReason = reason }
            rows[index].firstSeen = min(rows[index].firstSeen, event.timestamp)
            rows[index].lastSeen = max(rows[index].lastSeen, event.timestamp)
        } else if rows.count < Self.capacity && rows.reduce(row.storageBound, { $0 + $1.storageBound }) <= 12 * 1024 * 1024 {
            rows.append(row)
        } else { omitted += 1 }
    }
}

/// Private, bounded, atomic checkpoints. Serial caller only.
public final class NetworkSummaryStore {
    private let directory: URL
    private let encryption: JournalEncryption
    private var file: URL { directory.appendingPathComponent("network-summary.json") }
    private let limit = 24 * 1024 * 1024
    public init(directory: URL, encryption: JournalEncryption? = nil) throws {
        self.encryption = encryption ?? JournalEncryption(purpose: "network-summary")
        self.directory = directory
        var info = stat()
        guard lstat(directory.path, &info) == 0, info.st_mode & S_IFMT == S_IFDIR,
              info.st_uid == geteuid(), info.st_mode & 0o077 == 0 else { throw CocoaError(.fileReadNoPermission) }
    }
    public func load() throws -> NetworkActivitySummary? {
        try encryption.migrate(file, maximumBytes: limit * 2, lines: false)
        let fd = open(file.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        if fd < 0 { if errno == ENOENT { return nil }; throw CocoaError(.fileReadNoPermission) }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_uid == geteuid(),
              info.st_mode & 0o077 == 0, info.st_size <= limit * 2 else { throw CocoaError(.fileReadNoPermission) }
        let data = try FileHandle(fileDescriptor: fd, closeOnDealloc: false).readToEnd() ?? Data()
        var summary = try JSONDecoder().decode(NetworkActivitySummary.self, from: encryption.open(data))
        guard summary.rows.count <= NetworkActivitySummary.capacity else { throw CocoaError(.fileReadCorruptFile) }
        summary.prune()
        return summary
    }
    public func save(_ summary: NetworkActivitySummary) throws {
        let data = try encryption.seal(JSONEncoder().encode(summary))
        guard data.count <= limit else { throw CocoaError(.fileWriteOutOfSpace) }
        let temporary = directory.appendingPathComponent("summary-\(UUID().uuidString).tmp")
        let fd = open(temporary.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw CocoaError(.fileWriteNoPermission) }
        defer { close(fd); unlink(temporary.path) }
        try FileHandle(fileDescriptor: fd, closeOnDealloc: false).write(contentsOf: data)
        guard rename(temporary.path, file.path) == 0 else { throw CocoaError(.fileWriteUnknown) }
    }
}
