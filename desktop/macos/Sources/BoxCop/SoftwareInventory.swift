#if os(macOS)
import Foundation
import BoxCopCore
import Darwin

struct ExposureAdvisory: Decodable, Identifiable {
    let id: String
    let state: String
    let source: String
    let verification: String
    let prerequisites: String
    let remediation: String
    let affectedRange: String
    let fixedVersions: String
    var needsReview: Bool { !["fixed_for_advisory", "not_applicable_architecture"].contains(state) }
}
struct SoftwareObservation: Decodable, Identifiable {
    let id: String
    let name: String
    let version: String
    let path: String
    let kind: String
    var advisories: [ExposureAdvisory]
}
extension SoftwareObservation {
    func identity(for advisory: ExposureAdvisory) -> SoftwareFindingIdentity {
        SoftwareFindingIdentity(name: name, version: version, path: path, kind: kind,
            advisoryID: advisory.id, state: advisory.state, fixedVersions: advisory.fixedVersions)
    }
}
struct SoftwareScanIssue: Decodable {
    let reason: String
    let path: String
    var explanation: String {
        switch reason {
        case "unreadable_or_invalid_metadata": return "Could not read or parse software metadata. Updating or reinstalling this app through its vendor may restore it."
        case "root_unavailable": return "This location could not be opened. Check that it exists and is readable."
        case "root_entry_limit", "scan_limit_reached", "depth_limit": return "The scanner reached a resource limit. Rechecking unchanged software may give the same result."
        default: return reason.replacingOccurrences(of: "_", with: " ")
        }
    }
}
struct SoftwareScanRoot: Decodable {
    let path: String
    let state: String
}
struct SoftwareInventoryReport: Decodable {
    let schema: String
    let generatedAt: String
    let reviewedAt: String
    let incomplete: Bool
    let issues: [String]
    let limitations: [String]?
    let issueDetails: [SoftwareScanIssue]?
    let roots: [SoftwareScanRoot]?
    let coverage: String
    let elapsedMs: Double
    let cacheStatus: String?
    var remediationResults: [SoftwareFixResult]? = nil
    var remediationItems: [SoftwareFixItem]? = nil
    let records: [SoftwareObservation]
    var findings: [SoftwareObservation] { records.filter { $0.advisories.contains(where: \.needsReview) } }
}

enum SoftwareInventory {
    /// A dedicated engine run. Output and runtime are bounded; inspected binaries are never started.
    static func scan(roots: [String] = [], cache: Bool = false) -> Data? {
        EngineTools.run(["--software-inventory"] + (cache ? ["--cache"] : []) + roots.flatMap { ["--root", $0] }, timeout: 15)
    }
    static func decode(_ bytes: Data) -> SoftwareInventoryReport? {
        let decoder = JSONDecoder(); decoder.keyDecodingStrategy = .convertFromSnakeCase
        guard let report = try? decoder.decode(SoftwareInventoryReport.self, from: bytes),
              report.schema == "boxcop.software-inventory.v2" else { return nil }
        return report
    }
    static func run() {
        let args = Array(CommandLine.arguments.dropFirst(2))
        guard let data = EngineTools.run(["--software-inventory"] + args, timeout: 15) else {
            fputs("Inventory unavailable or invalid arguments. Use --root PATH and --format inventory|findings|agent.\n", stderr)
            exit(1)
        }
        FileHandle.standardOutput.write(data)
    }
    static func refresh() async -> SoftwareInventoryReport? {
        await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .utility).async { continuation.resume(returning: scan(cache: true).flatMap(decode)) }
        }
    }
    /// The report the last check saved, so findings show before the first check of this launch finishes.
    static var cacheURL: URL { EngineTools.dataDirectory.appendingPathComponent("software-inventory.json") }
    static func cached() -> SoftwareInventoryReport? {
        guard let data = try? Data(contentsOf: cacheURL), data.count <= 2 * 1024 * 1024 else { return nil }
        return decode(data)
    }
}
#endif
