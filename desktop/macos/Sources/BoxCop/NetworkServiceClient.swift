#if os(macOS)
import Foundation
import Darwin

/// Talks to the network extension's root-owned control socket. Read-mostly: history, status and the threat-blocking switch.
enum NetworkServiceClient {
    static let socketPath = "/var/run/local.boxcop.network.sock"
    private static let queue = DispatchQueue(label: "boxcop.network.client")

    static func allowed(_ command: String) -> Bool {
        guard command.utf8.count < 1024, !command.contains("\n") else { return false }
        if ["credential-protection-status", "credential-protection-on", "credential-protection-off", "network-activity", "network-activity-export", "network-threat-blocking-on", "network-threat-blocking-off"].contains(command) { return true }
        if command.hasPrefix("credential-allow ") { return UUID(uuidString: String(command.dropFirst("credential-allow ".count))) != nil }
        guard command.hasPrefix("network-workflow ") else { return false }
        let cursor = String(command.dropFirst("network-workflow ".count))
        return cursor == "start" || UUID(uuidString: cursor) != nil
    }
    /// The reply line, or nil when the extension is not installed, not answering, or not root-owned.
    static func send(_ command: String) async -> String? {
        await withCheckedContinuation { continuation in
            queue.async { continuation.resume(returning: request(command)) }
        }
    }
    static func request(_ command: String, path: String = socketPath) -> String? {
        guard allowed(command) else { return nil }
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var timeout = timeval(tv_sec: 2, tv_usec: 0), yes: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &yes, socklen_t(MemoryLayout<Int32>.size))
        var address = sockaddr_un(); address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        guard path.utf8.count < MemoryLayout.size(ofValue: address.sun_path) else { return nil }
        withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: Array(path.utf8) + [0]) }
        let connected = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard connected == 0 else { return nil }
        // Only the system extension, which runs as root, may answer.
        var uid: uid_t = 0, gid: gid_t = 0
        guard getpeereid(fd, &uid, &gid) == 0, uid == 0 else { return nil }
        let bytes = Array((command + "\n").utf8)
        guard bytes.withUnsafeBytes({ write(fd, $0.baseAddress!, $0.count) }) == bytes.count else { return nil }
        let limit = command.hasPrefix("network-threat") ? 8192 : command.hasPrefix("network-workflow ") ? 4 * 1024 * 1024 : 24 * 1024 * 1024
        var reply: [UInt8] = []
        var chunk = [UInt8](repeating: 0, count: 65536)
        while reply.count < limit {
            let count = read(fd, &chunk, min(chunk.count, limit - reply.count))
            guard count > 0 else { return nil }
            reply.append(contentsOf: chunk.prefix(count))
            if chunk.prefix(count).contains(10) { return String(decoding: reply, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines) }
        }
        return nil
    }
}
#endif
