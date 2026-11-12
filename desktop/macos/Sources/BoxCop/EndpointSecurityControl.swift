#if os(macOS)
import Foundation
import BoxCopCore
import Darwin

enum EndpointSecurityControl {
    private static let queue = DispatchQueue(label: "boxcop.es.app-control")
    static func submit(_ command: String, completion: @escaping @Sendable (String) -> Void) {
        queue.async { completion(request(command)) }
    }
    static func send(_ command: String) async -> String {
        await withCheckedContinuation { continuation in
            queue.async { continuation.resume(returning: request(command)) }
        }
    }
    static func summary(_ reply: String) -> String {
        guard let bytes = reply.data(using: .utf8), let row = (try? JSONSerialization.jsonObject(with: bytes)) as? [String: Any] else { return reply }
        return "Endpoint Security: \(row["state"] ?? "unknown") · \(row["written"] ?? 0) saved · \(row["kernelMissing"] ?? 0) kernel events missing · \(row["writerDropped"] ?? 0) journal events lost" + ((row["writerFailed"] as? Bool == true) ? " · write failure" : "") + (row["agentEnforcement"] as? String == "active" ? " · agent file guard active (UID \(row["agentUID"] ?? "unknown")) · \(row["agentDenied"] ?? 0) denied" : "") + (row["hostProtection"] as? String == "active" ? " · local process guard active · \(row["hostDenied"] ?? 0) denied · \(row["inventoryFiles"] ?? 0) inventoried files" : "")
    }
    static let path = "/var/run/local.boxcop.es.sock"
    static func address(path: String = path) -> sockaddr_un {
        var address = sockaddr_un(); address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        withUnsafeMutableBytes(of: &address.sun_path) { buffer in
            buffer.copyBytes(from: Array(path.utf8) + [0])
        }
        return address
    }
    static func deadline(_ fd: Int32) {
        var timeout = timeval(tv_sec: 2, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        var yes: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &yes, socklen_t(MemoryLayout<Int32>.size))
    }
    static func request(_ command: String) -> String {
        guard command.utf8.count < 1024, !command.contains("\n"), ["status", "pause", "resume", "network-review", "network-activity", "network-activity-export", "network-threat-blocking-on", "network-threat-blocking-off"].contains(command) || (command.hasPrefix("network-workflow ") || command.hasPrefix("network-decide ") || command.hasPrefix("network-enroll ") || command.hasPrefix("network-unenroll ")) else { return "Invalid command" }
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return "Endpoint Security service unavailable" }
        defer { close(fd) }; deadline(fd)
        let standalone = ReleaseProfile.resolve(bundleProfile: Bundle.main.object(forInfoDictionaryKey: "BoxCopReleaseProfile") as? String, arguments: []).usesStandaloneNetworkProtection && command.hasPrefix("network-")
        var address = address(path: standalone ? "/var/run/local.boxcop.network.sock" : path)
        let connected = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard connected == 0 else { return "Endpoint Security service not installed or unavailable" }
        var uid: uid_t = 0, gid: gid_t = 0
        guard getpeereid(fd, &uid, &gid) == 0, uid == 0 else { return "Endpoint Security service identity rejected" }
        let bytes = Array((command + "\n").utf8)
        guard bytes.withUnsafeBytes({ write(fd, $0.baseAddress!, $0.count) }) == bytes.count else { return "Endpoint Security control failed" }
        var reply: [UInt8] = []
        let limit = (command == "network-activity-export" || command == "network-activity") ? 24 * 1024 * 1024 : (command == "network-activity" || command.hasPrefix("network-workflow ")) ? 4 * 1024 * 1024 : command == "network-review" ? 1048576 : 8192
        while reply.count < limit {
            var chunk = [UInt8](repeating: 0, count: 1024)
            let count = read(fd, &chunk, min(chunk.count, limit - reply.count))
            guard count > 0 else { return "Endpoint Security control timed out" }
            reply.append(contentsOf: chunk.prefix(count))
            if chunk.prefix(count).contains(10) { return String(decoding: reply, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines) }
        }
        return "Endpoint Security control response too large"
    }
}
#endif
