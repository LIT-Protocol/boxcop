import XCTest
@testable import BoxCopCore

final class ReleaseProfileTests: XCTestCase {
    func testPackagedBuildsRejectDevelopmentNetworkFlags() {
        let profile = ReleaseProfile.resolve(bundleProfile: "beta", arguments: ["--production-mode"])
        XCTAssertEqual(profile, .limitedDevelopment)
        for option in ["--dev-network-filter-enable", "--dev-network-filter-disable"] {
            XCTAssertTrue(profile.rejects(arguments: ["BoxCop", option]), option)
        }
        for option in ["--host-agent-hook", "--status", "--dev-interface-preview", "--dev-software-inventory"] {
            XCTAssertFalse(profile.rejects(arguments: ["BoxCop", option]), option)
        }
    }
    func testResolutionFromArgumentsAndBundle() {
        XCTAssertEqual(ReleaseProfile.resolve(bundleProfile: nil, arguments: ["--limited-development-mode"]), .limitedDevelopment)
        XCTAssertEqual(ReleaseProfile.resolve(bundleProfile: nil, arguments: []), .development)
        XCTAssertEqual(ReleaseProfile.resolve(bundleProfile: nil, arguments: ["--production-mode"]), .productionPreview)
        XCTAssertFalse(ReleaseProfile.development.rejects(arguments: ["--dev-network-filter-enable"]))
        XCTAssertFalse(ReleaseProfile.development.usesNetworkProtection)
    }
}

final class DistributionChannelTests: XCTestCase {
    func testBothChannelsUseFullDistributionCapabilities() {
        for channel in ["beta", "stable"] {
            XCTAssertEqual(ReleaseChannel.resolve(bundleChannel: channel).rawValue, channel)
            let profile = ReleaseProfile.resolve(bundleProfile: "distribution", arguments: ["--beta-mode", "--production-mode"])
            XCTAssertEqual(profile, .distribution)
            XCTAssertTrue(profile.usesNetworkProtection)
            XCTAssertTrue(profile.packaged)
            XCTAssertTrue(profile.rejects(arguments: ["--dev-network-filter-enable"]))
        }
    }
    func testLimitedDevelopmentCannotEnableNetworkWithFlags() {
        let profile = ReleaseProfile.resolve(bundleProfile: "limited-development", arguments: ["--production-mode"])
        XCTAssertFalse(profile.usesNetworkProtection)
        XCTAssertTrue(profile.packaged)
    }
}
