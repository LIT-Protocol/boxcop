import Foundation

public struct NetworkThreatMatch: Codable, Sendable {
    public let hostname: String
    public let source: String
    public let revision: String
    public let reason: String
}

public struct NetworkThreatStatus: Codable, Sendable {
    public let enabled: Bool
    public let domainCount: Int
    public let source: String
    public let revision: String
    public let publishedAt: String
    public let error: String?
    public init(enabled: Bool, domainCount: Int, source: String, revision: String, publishedAt: String, error: String?) {
        self.enabled = enabled; self.domainCount = domainCount; self.source = source
        self.revision = revision; self.publishedAt = publishedAt; self.error = error
    }
}

/// Immutable in-memory exact-host matches. No network, DNS lookup, payload inspection or suffix inference.
public struct NetworkThreatPolicy: Sendable {
    public static let testHostname = "malware-test.boxcop.test"
    public let domains: Set<String>
    public let source: String
    public let revision: String
    public let publishedAt: String
    public init(text: String, source: String, revision: String, publishedAt: String) throws {
        guard text.utf8.count <= 8 * 1024 * 1024 else { throw CocoaError(.fileReadCorruptFile) }
        var domains = Set<String>()
        for raw in text.split(whereSeparator: \.isNewline) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            guard let domain = Self.normalize(line) else { throw CocoaError(.fileReadCorruptFile) }
            domains.insert(domain)
        }
        guard !domains.isEmpty, domains.count <= 500_000 else { throw CocoaError(.fileReadCorruptFile) }
        self.domains = domains; self.source = source; self.revision = revision; self.publishedAt = publishedAt
    }
    public static func normalize(_ value: String?) -> String? {
        guard var host = value, host.utf8.count <= 254, host.utf8.allSatisfy({ $0 < 128 }) else { return nil }
        if host.hasSuffix(".") { host.removeLast() }
        host = host.lowercased()
        let labels = host.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.count >= 2, host.utf8.count <= 253,
              labels.last!.utf8.contains(where: { (97...122).contains($0) }),
              labels.allSatisfy({ label in
                  !label.isEmpty && label.utf8.count <= 63 && label.first != "-" && label.last != "-" &&
                  label.utf8.allSatisfy { (97...122).contains($0) || (48...57).contains($0) || $0 == 45 }
              }) else { return nil }
        return host
    }
    public func match(urlHost: String?, remoteHostname: String?, enabled: Bool) -> NetworkThreatMatch? {
        guard enabled else { return nil }
        // Check both independent macOS fields: a benign URL must not mask a listed socket hostname.
        for candidate in [urlHost, remoteHostname] {
            guard let host = Self.normalize(candidate) else { continue }
            if host == Self.testHostname {
                return .init(hostname: host, source: "BoxCop harmless test", revision: "1", reason: "Reserved test hostname; no malware involved")
            }
            if domains.contains(host) {
                return .init(hostname: host, source: source, revision: revision, reason: "Exact hostname appears in the bundled threat list")
            }
        }
        return nil
    }
}
