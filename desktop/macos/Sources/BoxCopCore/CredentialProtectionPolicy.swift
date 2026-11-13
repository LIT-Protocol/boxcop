import Foundation

/// A small, deterministic policy for AUTH_OPEN. No file contents, I/O or inference.
/// Paths must come from ES, homes from trusted account discovery, and scope from
/// an authenticated process tracker (never an executable basename alone).
public struct CredentialProtectionPolicy {
    public enum Scope { case agent, installer, other, unknown }
    public enum Decision: Equatable {
        case allow
        case deny(String)
        case unresolvedPath
    }
    private let homes: [String]

    public init(homeDirectories: [String]) {
        homes = homeDirectories.filter { Self.valid($0) && $0 != "/" }
    }

    private static func valid(_ path: String) -> Bool {
        if path == "/" { return true }
        return path.hasPrefix("/") && !path.contains("\0") &&
        !path.split(separator: "/", omittingEmptySubsequences: false).dropFirst().contains(where: {
            $0.isEmpty || $0 == "." || $0 == ".."
        })
    }

    /// Only read opens are denied; write protection belongs to a separate policy.
    /// An unresolved path is an explicit coverage gap, not a match or safe verdict.
    public func evaluate(path: String, truncated: Bool = false, reads: Bool, scope: Scope) -> Decision {
        guard reads, scope == .agent || scope == .installer else { return .allow }
        guard !truncated, Self.valid(path) else { return .unresolvedPath }
        for home in homes {
            guard path.hasPrefix(home + "/") else { continue }
            let relative = String(path.dropFirst(home.count + 1))
            switch relative {
            case ".aws/credentials": return .deny("AWS credentials")
            case ".config/gcloud/application_default_credentials.json": return .deny("Google Cloud credentials")
            case ".npmrc", ".pypirc", ".netrc": return .deny("Registry or service credentials")
            default: break
            }
            // Conventional key names only. Custom key locations require explicit rules.
            let sshKeys = ["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_ecdsa_sk", "id_ed25519_sk"]
            if sshKeys.contains(where: { relative == ".ssh/" + $0 }) {
                return .deny("SSH private key")
            }
            if relative.hasPrefix(".aws/sso/cache/"), relative.hasSuffix(".json") {
                return .deny("AWS SSO credentials")
            }
        }
        return .allow
    }
}
