import Foundation
import Darwin
import SystemConfiguration
import BoxCopCore

/// Machine-wide, observation-only service. Flow callbacks never wait for this queue.
final class NetworkActivityService: @unchecked Sendable {
    static let socketPath = "/var/run/local.boxcop.network.sock"
    static let root = URL(fileURLWithPath: "/Library/Application Support/BoxCopNetwork.noindex")
    private let lock = NSLock()
    private let queue = DispatchQueue(label: "boxcop.network.activity-control")
    private let writer = DispatchQueue(label: "boxcop.network.activity-writer", qos: .utility)
    private let slots = DispatchSemaphore(value: 256)
    private let ownerUID: uid_t
    private var journal: NetworkActivityJournal
    private var summary = NetworkActivitySummary()
    private var summaryStore: NetworkSummaryStore?
    private var summaryError: String?
    private var checkpointPending = false
    private var recent: [NetworkActivityEvent] = []
    private var observed: UInt64 = 0, dropped: UInt64 = 0, failures: UInt64 = 0
    private var blocked: UInt64 = 0
    private var lastFlow: Date?
    private let startedAt = Date()
    private var socketFD: Int32 = -1, lockFD: Int32 = -1
    private var source: DispatchSourceRead?
    init() throws {
        guard geteuid() == 0 else { throw CocoaError(.fileReadNoPermission) }
        for path in ["/Library", "/Library/Application Support"] {
            var info = stat()
            guard lstat(path, &info) == 0, info.st_mode & S_IFMT == S_IFDIR, info.st_uid == 0, info.st_mode & 0o022 == 0 else { throw CocoaError(.fileReadNoPermission) }
        }
        if mkdir(Self.root.path, 0o700) != 0 && errno != EEXIST { throw CocoaError(.fileWriteNoPermission) }
        // One service per machine.
        lockFD = open(Self.root.appendingPathComponent("service.lock").path, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard lockFD >= 0 else { throw CocoaError(.fileLocking) }
        guard flock(lockFD, LOCK_EX | LOCK_NB) == 0 else { close(lockFD); lockFD = -1; throw CocoaError(.fileLocking) }
        journal = try NetworkActivityJournal(directory: Self.root)
        let ownerFile = Self.root.appendingPathComponent("activity-owner.txt")
        let fd = open(ownerFile.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        if fd >= 0 {
            defer { close(fd) }
            var info = stat()
            guard fstat(fd, &info) == 0, info.st_uid == 0, info.st_mode & S_IFMT == S_IFREG, info.st_mode & 0o077 == 0, info.st_size <= 32,
                  let data = try FileHandle(fileDescriptor: fd, closeOnDealloc: false).read(upToCount: 32),
                  let text = String(data: data, encoding: .utf8), let uid = UInt32(text), uid >= 501 else { throw CocoaError(.fileReadNoPermission) }
            ownerUID = uid
        } else {
            guard errno == ENOENT else { throw CocoaError(.fileReadNoPermission) }
            var uid: uid_t = 0, gid: gid_t = 0
            _ = SCDynamicStoreCopyConsoleUser(nil, &uid, &gid)
            guard uid >= 501 && uid < 60000 else { throw CocoaError(.fileReadNoPermission) }
            ownerUID = uid
            let data = Data(String(uid).utf8)
            guard FileManager.default.createFile(atPath: ownerFile.path, contents: data, attributes: [.posixPermissions: 0o600]) else { throw CocoaError(.fileWriteNoPermission) }
        }
        recent = Array(try journal.events().suffix(100))
        do {
            summaryStore = try NetworkSummaryStore(directory: Self.root)
            summary = try summaryStore?.load() ?? NetworkActivitySummary()
        } catch { summaryError = "Previous summaries could not be loaded. Statistics start with this session." }
        if summaryError == nil {
            do { try summaryStore?.save(summary) }
            catch { summaryError = "Statistics could not be saved. They may be lost on restart." }
        }

    }
    deinit {
        source?.cancel()
        if socketFD >= 0 { close(socketFD); unlink(Self.socketPath) }
        if lockFD >= 0 { close(lockFD) }
    }
    func observe(_ event: NetworkActivityEvent, processToken: Data?, appToken: Data?) {
        lock.lock(); observed &+= 1; if event.threat != nil { blocked &+= 1 }; lastFlow = event.timestamp; lock.unlock()
        guard slots.wait(timeout: .now()) == .success else {
            lock.lock(); dropped &+= 1; lock.unlock(); return
        }
        writer.async { [self] in
            defer { slots.signal() }
            var enriched = event
            enriched.process = NetworkProcessInspection.inspect(processToken)
            enriched.responsibleApp = appToken == processToken ? enriched.process : NetworkProcessInspection.inspect(appToken)
            do { try journal.append(enriched) } catch { lock.lock(); failures &+= 1; lock.unlock() }
            summary.record(enriched)
            if !checkpointPending {
                checkpointPending = true
                writer.asyncAfter(deadline: .now() + 5) { [self] in
                    checkpointPending = false
                    do {
                        guard let summaryStore else { throw CocoaError(.fileWriteUnknown) }
                        try summaryStore.save(summary)
                    } catch { summaryError = "Statistics could not be saved. They may be lost on restart." }
                }
            }
            lock.lock(); recent.append(enriched)
            if recent.count > 100 { recent.removeFirst(recent.count - 100) }; lock.unlock()
        }
    }
    func start() throws {
        socketFD = socket(AF_UNIX, SOCK_STREAM, 0)
        guard socketFD >= 0 else { throw CocoaError(.fileWriteUnknown) }
        _ = fcntl(socketFD, F_SETFL, O_NONBLOCK); _ = fcntl(socketFD, F_SETFD, FD_CLOEXEC)
        unlink(Self.socketPath)
        var address = sockaddr_un(); address.sun_family = sa_family_t(AF_UNIX); address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: Array(Self.socketPath.utf8) + [0]) }
        let result = withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(socketFD, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) } }
        guard result == 0, chmod(Self.socketPath, 0o666) == 0, listen(socketFD, 8) == 0 else { throw CocoaError(.fileWriteNoPermission) }
        source = DispatchSource.makeReadSource(fileDescriptor: socketFD, queue: queue)
        source?.setEventHandler { [weak self] in self?.serve() }; source?.resume()
    }
    private func serve() {
        let fd = accept(socketFD, nil, nil)
        guard fd >= 0 else { return }
        defer { close(fd) }; _ = fcntl(fd, F_SETFL, 0)
        var timeout = timeval(tv_sec: 2, tv_usec: 0), yes: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &yes, socklen_t(MemoryLayout<Int32>.size))
        var uid: uid_t = 0, gid: gid_t = 0
        lock.lock(); let owner = ownerUID; lock.unlock()
        guard getpeereid(fd, &uid, &gid) == 0, uid == 0 || uid == owner else { return }
        var bytes: [UInt8] = []
        let deadline = ProcessInfo.processInfo.systemUptime + 2
        while bytes.count < 1024, !bytes.contains(10), ProcessInfo.processInfo.systemUptime < deadline {
            var byte: UInt8 = 0
            guard read(fd, &byte, 1) == 1 else { return }; bytes.append(byte)
        }
        guard bytes.last == 10 else { return }
        let command = String(decoding: bytes.dropLast(), as: UTF8.self)
        let reply = handle(command)
        let output = Array((reply + "\n").utf8)
        output.withUnsafeBytes { data in
            var sent = 0
            while sent < data.count {
                let count = write(fd, data.baseAddress!.advanced(by: sent), data.count - sent)
                if count <= 0 { break }; sent += count
            }
        }
    }
    private func handle(_ command: String) -> String {
        let encoder = JSONEncoder()
        if command == "network-activity" {
            let statistics = writer.sync {
                let count = summary.rows.count
                summary.prune()
                if summary.rows.count != count {
                    do { try summaryStore?.save(summary) }
                    catch { summaryError = "Expired statistics could not be removed from the saved checkpoint." }
                }
                return (summary, summaryError)
            }
            lock.lock()
            var report = NetworkActivitySnapshot(events: recent.reversed(), observed: observed, dropped: dropped,
                writeFailures: failures, lastFlow: lastFlow, startedAt: startedAt, retentionBytes: journal.limit * 2,
                threatProtection: threatProtection.status(), blocked: blocked)
            lock.unlock()
            report.summary = statistics.0; report.summaryError = statistics.1
            return (try? String(decoding: encoder.encode(report), as: UTF8.self)) ?? "Activity unavailable"
        }
        if command.hasPrefix("network-workflow ") {
            let token = String(command.dropFirst("network-workflow ".count))
            guard token == "start" || UUID(uuidString: token) != nil else { return "Invalid workflow cursor" }
            lock.lock(); let lost = dropped, failed = failures; lock.unlock()
            return writer.sync {
                do {
                    let page = NetworkWorkflowPage(retained: try journal.events(), after: UUID(uuidString: token),
                        loggingDropped: lost, writeFailures: failed, providerStartedAt: startedAt)
                    return String(decoding: try encoder.encode(page), as: UTF8.self)
                } catch { return "Network workflow history unavailable" }
            }
        }
        if command == "network-activity-export" {
            return writer.sync {
                do { return String(decoding: try encoder.encode(journal.events()), as: UTF8.self) }
                catch { return "Could not read connection history." }
            }
        }
        if command == "network-threat-blocking-on" { return threatProtection.setEnabled(true) }
        if command == "network-threat-blocking-off" { return threatProtection.setEnabled(false) }
        return "Unsupported command"
    }
}
