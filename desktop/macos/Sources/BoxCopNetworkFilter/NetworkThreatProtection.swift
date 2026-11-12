import Foundation
import CryptoKit
import BoxCopCore
import Darwin

/// Policy evaluation is independent of the logging service and its bounded queue.
final class NetworkThreatProtection: @unchecked Sendable {
    private let policy: NetworkThreatPolicy?
    private let loadError: String?
    private let lock = NSLock()
    private var enabled = true
    private var settingsError: String?
    private let settingsURL = NetworkActivityService.root.appendingPathComponent("threat-blocking.txt")
    init() {
        do {
            guard let root = Bundle.main.resourceURL?.appendingPathComponent("ThreatDomains") else { throw CocoaError(.fileNoSuchFile) }
            struct Manifest: Decodable { let source: String; let revision: String; let publishedAt: String; let sha256: String; let count: Int }
            let manifest = try JSONDecoder().decode(Manifest.self, from: Data(contentsOf: root.appendingPathComponent("manifest.json")))
            let data = try Data(contentsOf: root.appendingPathComponent("domains.txt"))
            guard data.count <= 8 * 1024 * 1024,
                  SHA256.hash(data: data).map({ String(format: "%02x", $0) }).joined() == manifest.sha256,
                  let text = String(data: data, encoding: .utf8) else { throw CocoaError(.fileReadCorruptFile) }
            let loaded = try NetworkThreatPolicy(text: text, source: manifest.source, revision: manifest.revision, publishedAt: manifest.publishedAt)
            guard loaded.domains.count == manifest.count else { throw CocoaError(.fileReadCorruptFile) }
            policy = loaded; loadError = nil
        } catch { policy = nil; loadError = "Bundled threat list unavailable. Connections are only observed." }
        do {
            for path in ["/Library", "/Library/Application Support", NetworkActivityService.root.path] {
                var info = stat()
                if lstat(path, &info) != 0 {
                    if errno == ENOENT && path == NetworkActivityService.root.path { return }
                    throw CocoaError(.fileReadNoPermission)
                }
                guard info.st_mode & S_IFMT == S_IFDIR, info.st_uid == 0, info.st_mode & 0o022 == 0 else { throw CocoaError(.fileReadNoPermission) }
            }
            let fd = open(settingsURL.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
            if fd < 0 { if errno == ENOENT { return }; throw CocoaError(.fileReadNoPermission) }
            defer { close(fd) }
            var info = stat()
            guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_uid == 0, info.st_mode & 0o077 == 0, info.st_size <= 16 else { throw CocoaError(.fileReadNoPermission) }
            let data = try FileHandle(fileDescriptor: fd, closeOnDealloc: false).readToEnd() ?? Data()
            guard let setting = String(data: data, encoding: .utf8), ["enabled", "disabled"].contains(setting) else { throw CocoaError(.fileReadCorruptFile) }
            enabled = setting == "enabled"
        } catch { enabled = false; settingsError = "Cannot read blocking preference. Re-enable threat blocking to retry." }
    }
    func match(urlHost: String?, remoteHostname: String?) -> NetworkThreatMatch? {
        lock.lock(); let active = enabled; lock.unlock()
        return policy?.match(urlHost: urlHost, remoteHostname: remoteHostname, enabled: active)
    }
    func status() -> NetworkThreatStatus {
        lock.lock(); defer { lock.unlock() }
        return .init(enabled: enabled, domainCount: policy?.domains.count ?? 0,
            source: policy?.source ?? "Unavailable", revision: policy?.revision ?? "unavailable",
            publishedAt: policy?.publishedAt ?? "unavailable", error: loadError ?? settingsError)
    }
    /// Invoked only through the root/configuring-user authenticated control socket.
    func setEnabled(_ value: Bool) -> String {
        do {
            // Parent directory has already been validated and created by NetworkActivityService.
            try Data((value ? "enabled" : "disabled").utf8).write(to: settingsURL, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: settingsURL.path)
            lock.lock(); enabled = value; settingsError = nil; lock.unlock()
            return value ? "Threat-domain blocking enabled." : "Threat-domain blocking off. Connections are still logged."
        } catch { return "Could not save the blocking preference; no change was applied." }
    }
}
