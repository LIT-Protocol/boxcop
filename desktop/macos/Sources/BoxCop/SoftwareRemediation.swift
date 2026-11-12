#if os(macOS)
import Foundation
import BoxCopCore

struct SoftwareFixItem: Decodable, Identifiable {
    let id: String
    let name: String
    let versions: String
    let location: String
    let adapter: String
    let detail: String
    let observationIds: [String]
    var state: String? = nil
    var automatic: Bool { adapter != "review" }
}
struct SoftwareFixPlan: Decodable, Identifiable {
    let id: String
    let name: String
    let versions: String
    let location: String
    let ready: Bool
    let target: String
    let impact: String
    let fingerprint: String
    var diagnostics: String? = nil
}
struct SoftwareFixResult: Decodable, Identifiable {
    let id: String
    let status: String
    let detail: String
    var diagnostics: String? = nil
    var name: String? = nil
    var versions: String? = nil
    var attemptedAt: String? = nil
    var title: String {
        switch status {
        case "restart_needed": return "Restart needed"
        case "failed": return "Update failed"
        case "cleanup_needed": return "Old-version cleanup needed"
        case "migration_needed": return "Migration or manual review needed"
        case "in_progress": return "Completion not recorded"
        case "unverified": return "Couldn’t verify"
        default: return "Needs your decision"
        }
    }
}
struct SoftwareFixResponse: Decodable {
    let schema: String
    let plans: [SoftwareFixPlan]
    let results: [SoftwareFixResult]
    let error: String?
}

enum SoftwareRemediation {
    /// Preparation is bounded by the engine; installation has no time cap, so a package manager is never killed mid-change.
    static func request(_ operation: String, payload: [String: Any]) async -> SoftwareFixResponse? {
        guard let input = try? JSONSerialization.data(withJSONObject: payload),
              let bytes = await EngineTools.runAsync(["--software-remediation", operation], input: input, timeout: nil, requireSuccess: false) else { return nil }
        let decoder = JSONDecoder(); decoder.keyDecodingStrategy = .convertFromSnakeCase
        let response = try? decoder.decode(SoftwareFixResponse.self, from: bytes)
        return response?.schema == "boxcop.software-remediation.v1" ? response : nil
    }
}
#endif
