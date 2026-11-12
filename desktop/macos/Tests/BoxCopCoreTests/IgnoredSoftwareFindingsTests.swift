import XCTest
@testable import BoxCopCore

final class IgnoredSoftwareFindingsTests: XCTestCase {
    private func finding(version: String = "1", path: String = "/Applications/Example.app",
                         advisory: String = "CVE-test", state: String = "unresolved",
                         fixed: String = "2") -> SoftwareFindingIdentity {
        .init(name: "example-browser", version: version, path: path, kind: "app",
              advisoryID: advisory, state: state, fixedVersions: fixed)
    }

    func testIgnoreSurvivesReloadAndUndoPersists() throws {
        let suite = "IgnoredSoftwareFindingsTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        XCTAssertTrue(IgnoredSoftwareFindings.load(from: defaults).isEmpty)
        IgnoredSoftwareFindings.save([finding()], to: defaults)
        let reopened = try XCTUnwrap(UserDefaults(suiteName: suite))
        var ignored = IgnoredSoftwareFindings.load(from: reopened)
        XCTAssertEqual(ignored, [finding()])
        ignored.remove(finding())
        IgnoredSoftwareFindings.save(ignored, to: reopened)
        XCTAssertTrue(IgnoredSoftwareFindings.load(from: defaults).isEmpty)
    }

    func testNewAdvisoryVersionInstallationOrAssessmentIsNotIgnored() {
        let ignored: Set = [finding()]
        XCTAssertTrue(ignored.contains(finding()))
        XCTAssertFalse(ignored.contains(finding(version: "1.1")))
        XCTAssertFalse(ignored.contains(finding(path: "/other/Example.app")))
        XCTAssertFalse(ignored.contains(finding(advisory: "CVE-new")))
        XCTAssertFalse(ignored.contains(finding(state: "affected")))
        XCTAssertFalse(ignored.contains(finding(fixed: "2.1")))
    }

    func testCorruptPreferencesDoNotHideFindings() throws {
        let suite = "IgnoredSoftwareFindingsTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        defaults.set(Data("invalid".utf8), forKey: "boxcop.software.ignoredFindings.v1")
        XCTAssertTrue(IgnoredSoftwareFindings.load(from: defaults).isEmpty)
    }
}
