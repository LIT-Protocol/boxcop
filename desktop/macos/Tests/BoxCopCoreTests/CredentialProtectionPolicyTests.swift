import XCTest
@testable import BoxCopCore

final class CredentialProtectionPolicyTests: XCTestCase {
    let policy = CredentialProtectionPolicy(homeDirectories: ["/Users/alice", "/Volumes/Homes/bob"])

    func testCredentialReadsDeniedForBothScopesAndAllConfiguredHomes() {
        for home in ["/Users/alice", "/Volumes/Homes/bob"] {
            for file in [".aws/credentials", ".aws/sso/cache/session.json", ".ssh/id_ed25519",
                         ".config/gcloud/application_default_credentials.json", ".npmrc", ".pypirc", ".netrc"] {
                for scope in [CredentialProtectionPolicy.Scope.agent, .installer] {
                    guard case .deny = policy.evaluate(path: home + "/" + file, reads: true, scope: scope) else {
                        return XCTFail("Expected credential denial: \(file)")
                    }
                }
            }
        }
    }

    func testRootDirectoryIsNotAnUnresolvedCredentialPath() {
        XCTAssertEqual(policy.evaluate(path: "/", reads: true, scope: .agent), .allow)
    }
    func testDoesNotBlockUnrelatedFilesOrPublicKeys() {
        for path in ["/Users/alice2/.aws/credentials", "/Users/alice/.aws/credentials.backup",
                     "/Users/alice/.ssh/id_ed25519.pub", "/Users/alice/.ssh/known_hosts",
                     "/Users/alice/project/.npmrc", "/Users/alice/.aws/config"] {
            XCTAssertEqual(policy.evaluate(path: path, reads: true, scope: .agent), .allow)
        }
    }

    func testScopeAndAccessModeAreRequired() {
        let path = "/Users/alice/.aws/credentials"
        for scope in [CredentialProtectionPolicy.Scope.other, .unknown] {
            XCTAssertEqual(policy.evaluate(path: path, reads: true, scope: scope), .allow)
        }
        XCTAssertEqual(policy.evaluate(path: path, reads: false, scope: .agent), .allow)
    }

    func testAmbiguousPathsAreReportedAsGaps() {
        for path in ["relative", "/Users/alice/../alice/.netrc", "/Users//alice/.netrc", "/Users/alice/.netrc\0suffix"] {
            XCTAssertEqual(policy.evaluate(path: path, reads: true, scope: .agent), .unresolvedPath)
        }
        XCTAssertEqual(policy.evaluate(path: "/Users/alice/.netrc", truncated: true, reads: true, scope: .agent), .unresolvedPath)
    }

    func testInvalidHomeCannotBecomeBroadRule() {
        let invalid = CredentialProtectionPolicy(homeDirectories: ["/", "", "Users/alice", "/Users/alice/.."])
        XCTAssertEqual(invalid.evaluate(path: "/.netrc", reads: true, scope: .installer), .allow)
    }
}
