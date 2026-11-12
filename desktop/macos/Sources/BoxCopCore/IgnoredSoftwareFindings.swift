import Foundation

/// A dismissal applies to one advisory on one installed version, never an entire app.
public struct SoftwareFindingIdentity: Codable, Hashable {
    public let name: String
    public let version: String
    public let path: String
    public let kind: String
    public let advisoryID: String
    public let state: String
    public let fixedVersions: String

    public init(name: String, version: String, path: String, kind: String,
                advisoryID: String, state: String, fixedVersions: String) {
        self.name = name; self.version = version; self.path = path; self.kind = kind
        self.advisoryID = advisoryID; self.state = state; self.fixedVersions = fixedVersions
    }
}

public enum IgnoredSoftwareFindings {
    private static let key = "boxcop.software.ignoredFindings.v1"

    public static func load(from defaults: UserDefaults) -> Set<SoftwareFindingIdentity> {
        guard let data = defaults.data(forKey: key),
              let findings = try? JSONDecoder().decode(Set<SoftwareFindingIdentity>.self, from: data) else { return [] }
        return findings
    }

    public static func save(_ findings: Set<SoftwareFindingIdentity>, to defaults: UserDefaults) {
        guard let data = try? JSONEncoder().encode(findings) else { return }
        defaults.set(data, forKey: key)
    }
}
