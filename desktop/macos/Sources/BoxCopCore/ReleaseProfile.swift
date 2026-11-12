import Foundation

/// Capability is independent of release channel. Packaged builds reject development-only flags.
public enum ReleaseProfile: String, Sendable {
    case development, distribution, productionPreview
    case limitedDevelopment = "limited-development"

    public static func resolve(bundleProfile: String?, arguments: [String]) -> ReleaseProfile {
        // Preserve the capability of historical bundles without treating beta as a capability.
        if bundleProfile == "protected" { return .distribution }
        if bundleProfile == "beta" { return .limitedDevelopment }
        if let value = bundleProfile.flatMap(ReleaseProfile.init(rawValue:)) { return value }
        if arguments.contains("--limited-development-mode") { return .limitedDevelopment }
        return arguments.contains("--production-mode") ? .productionPreview : .development
    }

    /// Only the signed distribution build embeds the network system extension.
    public var usesNetworkProtection: Bool { self == .distribution }
    public var packaged: Bool { self == .limitedDevelopment || self == .distribution }

    public func rejects(arguments: [String]) -> Bool {
        packaged && arguments.contains { $0.hasPrefix("--dev-network-filter-") }
    }
}

public enum ReleaseChannel: String, Sendable {
    case beta, stable
    public static func resolve(bundleChannel: String?) -> ReleaseChannel {
        bundleChannel.flatMap(ReleaseChannel.init(rawValue:)) ?? .beta
    }
}
