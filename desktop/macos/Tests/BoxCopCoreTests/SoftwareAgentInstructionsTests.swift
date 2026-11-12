import XCTest
@testable import BoxCopCore

final class SoftwareAgentInstructionsTests: XCTestCase {
    func testEveryNodePathAndAdvisorySurvivesHandoffWithoutLosingUncertainty() throws {
        let advisory = SoftwareAgentInstructions.Advisory(id: "node-test", state: "unresolved", affectedRange: "unknown", fixedVersions: "Verify vendor", source: "https://nodejs.org/", prerequisites: "Configuration unknown", remediation: "Review")
        let rows = (0..<14).map { SoftwareAgentInstructions.Installation(name: "node", versions: "20.\($0).0", path: "/Users/test/.nvm/versions/node/v20.\($0).0", advisories: [advisory]) }
        let text = try XCTUnwrap(SoftwareAgentInstructions.make(installations: rows, scannedAt: "fixture-date", incomplete: true, coverage: "Selected roots"))
        let json = try XCTUnwrap(text.components(separatedBy: "BoxCop scan evidence (JSON):\n").last?.data(using: .utf8))
        let evidence = try XCTUnwrap(JSONSerialization.jsonObject(with: json) as? [String: Any])
        let installs = try XCTUnwrap(evidence["installations"] as? [[String: Any]])
        XCTAssertEqual(installs.count, 14)
        XCTAssertEqual(evidence["incomplete"] as? Bool, true)
        XCTAssertEqual(installs.last?["path"] as? String, rows.last?.path)
        XCTAssertTrue(text.contains("Confirm my choices before removing runtimes"))
        XCTAssertTrue(text.contains("Removing a runtime does not prevent a later nvm install"))
        XCTAssertTrue(text.contains("moving/renaming a directory"))
    }
    func testAppHandoffIncludesRelevantLimitsAndEscapesMetadata() throws {
        let path = "/Applications/odd\n\"name.app"
        let rows = [SoftwareAgentInstructions.Installation(name: "claude-browser", versions: "unknown", path: path, advisories: []),
                    .init(name: "lm-studio", versions: "0.4", path: "/Applications/LM Studio.app", advisories: [])]
        let text = try XCTUnwrap(SoftwareAgentInstructions.make(installations: rows, scannedAt: "fixture", incomplete: false, coverage: "Metadata"))
        XCTAssertTrue(text.contains("Do not invent a fixed desktop-version cutoff"))
        XCTAssertTrue(text.contains("Updating does not remove persistence"))
        XCTAssertFalse(text.contains("For the Node/nvm installations:"))
        let data = try XCTUnwrap(text.components(separatedBy: "BoxCop scan evidence (JSON):\n").last?.data(using: .utf8))
        let value = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual((value["installations"] as? [[String: Any]])?.first?["path"] as? String, path)
    }
    func testEmptySelectionDoesNotProduceInstructions() {
        XCTAssertNil(SoftwareAgentInstructions.make(installations: [], scannedAt: "", incomplete: false, coverage: ""))
    }
}
