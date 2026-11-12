import Foundation

/// Capability is independent of release channel. Packaged builds cannot enable lab paths.
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

    public var usesEndpointSecurity: Bool { self == .development || self == .productionPreview }
    public var usesNetworkProtection: Bool { self != .limitedDevelopment }
    public var usesStandaloneNetworkProtection: Bool { self == .distribution }
    public var requiresMonitoringConsent: Bool { self == .limitedDevelopment || self == .distribution }
    public var automaticDevelopmentCollection: Bool { self == .development }
    // Preserve existing opt-in choices across upgrades and channel changes.
    public var consentKey: String { requiresMonitoringConsent ? "beta-consent-choices-v1" : "consent-choices-v1" }

    public func rejects(arguments: [String]) -> Bool {
        requiresMonitoringConsent && arguments.contains {
            $0.hasPrefix("--dev-endpoint-security-") || $0.hasPrefix("--dev-network-filter-") ||
            $0 == "--dev-agent-run" || $0 == "--dev-es-lifecycle-test"
        }
    }
}

public enum ReleaseChannel: String, Sendable {
    case beta, stable
    public static func resolve(bundleChannel: String?) -> ReleaseChannel {
        bundleChannel.flatMap(ReleaseChannel.init(rawValue:)) ?? .beta
    }
}
