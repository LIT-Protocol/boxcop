import XCTest
@testable import BoxCopCore

final class ReleaseProfileTests: XCTestCase {
    func testPackagedBetaCannotEnablePrivilegedDevelopmentPaths() {
        let profile = ReleaseProfile.resolve(bundleProfile: "beta", arguments: ["--production-mode"])
        XCTAssertEqual(profile, .limitedDevelopment)
        XCTAssertFalse(profile.usesEndpointSecurity)
        XCTAssertFalse(profile.automaticDevelopmentCollection)
        for option in ["--dev-endpoint-security-probe", "--dev-endpoint-security-service", "--dev-endpoint-security-control", "--dev-network-filter-enable", "--dev-network-filter-disable", "--dev-agent-run", "--dev-es-lifecycle-test"] {
            XCTAssertTrue(profile.rejects(arguments: ["BoxCop", option]), option)
        }
        for option in ["--host-agent-hook", "--provider-integrations", "--collect-event", "--native-messaging", "--dev-visual-test"] {
            XCTAssertFalse(profile.rejects(arguments: ["BoxCop", option]), option)
        }
    }
    func testBetaDoesNotReuseDevelopmentConsent() {
        XCTAssertNotEqual(ReleaseProfile.limitedDevelopment.consentKey, ReleaseProfile.development.consentKey)
        XCTAssertEqual(ReleaseProfile.resolve(bundleProfile: nil, arguments: ["--limited-development-mode"]), .limitedDevelopment)
        XCTAssertEqual(ReleaseProfile.resolve(bundleProfile: nil, arguments: []), .development)
        XCTAssertEqual(ReleaseProfile.resolve(bundleProfile: nil, arguments: ["--production-mode"]), .productionPreview)
        XCTAssertFalse(ReleaseProfile.development.rejects(arguments: ["--dev-endpoint-security-service"]))
    }
}

final class DistributionChannelTests: XCTestCase {
    func testBothChannelsUseFullDistributionCapabilities() {
        for channel in ["beta", "stable"] {
            XCTAssertEqual(ReleaseChannel.resolve(bundleChannel: channel).rawValue, channel)
            let profile = ReleaseProfile.resolve(bundleProfile: "distribution", arguments: ["--beta-mode", "--production-mode"])
            XCTAssertEqual(profile, .distribution)
            XCTAssertTrue(profile.usesNetworkProtection)
            XCTAssertTrue(profile.usesStandaloneNetworkProtection)
            XCTAssertTrue(profile.requiresMonitoringConsent)
            XCTAssertFalse(profile.usesEndpointSecurity)
            XCTAssertFalse(profile.automaticDevelopmentCollection)
            XCTAssertTrue(profile.rejects(arguments: ["--dev-network-filter-enable"]))
            XCTAssertEqual(profile.consentKey, "beta-consent-choices-v1")
        }
    }
    func testLimitedDevelopmentCannotEnableNetworkWithFlags() {
        let profile = ReleaseProfile.resolve(bundleProfile: "limited-development", arguments: ["--production-mode"])
        XCTAssertFalse(profile.usesNetworkProtection)
        XCTAssertFalse(profile.usesStandaloneNetworkProtection)
        XCTAssertTrue(profile.requiresMonitoringConsent)
        XCTAssertFalse(profile.automaticDevelopmentCollection)
    }
}
