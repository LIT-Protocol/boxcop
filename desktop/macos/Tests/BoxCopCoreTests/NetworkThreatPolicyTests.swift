import XCTest
@testable import BoxCopCore

final class NetworkThreatPolicyTests: XCTestCase {
    private func policy(_ text: String = "# fixture\nevil.example\nxn--bcher-kva.example\n") throws -> NetworkThreatPolicy {
        try .init(text: text, source: "Synthetic fixture", revision: "test-v1", publishedAt: "2026-11-02T00:00:00Z")
    }
    func testExactCaseInsensitiveMatchesAndNoSuffixOverreach() throws {
        let p = try policy()
        for host in ["evil.example", "EVIL.EXAMPLE."] {
            let match = p.match(urlHost: nil, remoteHostname: host, enabled: true)
            XCTAssertEqual(match?.hostname, "evil.example")
            XCTAssertEqual(match?.revision, "test-v1")
        }
        for host in ["notevil.example", "evil.example.safe.example", "cdn.evil.example", "safe.example"] {
            XCTAssertNil(p.match(urlHost: host, remoteHostname: nil, enabled: true))
        }
        XCTAssertNotNil(p.match(urlHost: "xn--bcher-kva.example", remoteHostname: nil, enabled: true))
    }
    func testBothHostnameSourcesAreCheckedButUnknownsAndIPsAreAllowed() throws {
        let p = try policy()
        XCTAssertNotNil(p.match(urlHost: "safe.example", remoteHostname: "evil.example", enabled: true))
        XCTAssertNotNil(p.match(urlHost: "evil.example", remoteHostname: "safe.example", enabled: true))
        for invalid in [nil, "", "192.0.2.1", "::1", "evil.example:443", "https://evil.example/", "evil.example..", "evil.example\n", "*.evil.example", "evil..example", "-evil.example", "evil-.example", "bücher.example"] as [String?] {
            XCTAssertNil(p.match(urlHost: invalid, remoteHostname: nil, enabled: true))
        }
    }
    func testDisabledPolicyAndHarmlessTestDomain() throws {
        let p = try policy()
        XCTAssertNil(p.match(urlHost: "evil.example", remoteHostname: nil, enabled: false))
        XCTAssertNil(p.match(urlHost: NetworkThreatPolicy.testHostname, remoteHostname: nil, enabled: false))
        XCTAssertEqual(p.match(urlHost: NetworkThreatPolicy.testHostname, remoteHostname: nil, enabled: true)?.source, "BoxCop harmless test")
    }
    func testMalformedFeedIsRejectedAsAWhole() {
        for text in ["", "# only comments", "evil.example\n*\n", "evil.example\ncom\n", "evil.example\n0.0.0.0 other.example", "evil.example\nhttps://other.example/", String(repeating: "x", count: 8 * 1024 * 1024 + 1)] {
            XCTAssertThrowsError(try policy(text))
        }
    }
    func testBundledFeedParsesAndHasNoCommonServiceRoots() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Resources/ThreatDomains")
        let p = try policy(String(contentsOf: root.appendingPathComponent("domains.txt"), encoding: .utf8))
        let manifest = try JSONSerialization.jsonObject(with: Data(contentsOf: root.appendingPathComponent("manifest.json"))) as! [String: Any]
        XCTAssertEqual(p.domains.count, manifest["count"] as? Int)
        XCTAssertGreaterThan(p.domains.count, 1000)
        for host in ["apple.com", "google.com", "github.com", "cloudflare.com", "anthropic.com", "openai.com", "example.com"] {
            XCTAssertNil(p.match(urlHost: host, remoteHostname: nil, enabled: true))
        }
    }
    func testBlockedEventRoundTripAndLegacyHistoryCompatibility() throws {
        let threat = try policy().match(urlHost: "evil.example", remoteHostname: nil, enabled: true)
        let event = NetworkActivityEvent(remoteAddress: "192.0.2.1", remotePort: "443", localAddress: nil, localPort: nil,
            hostname: "evil.example", hostnameSource: "flow_remote_hostname", url: nil, transport: "tcp",
            socketFamily: 2, socketType: 1, socketProtocol: 6, flowType: "socket", threat: threat)
        let data = try JSONEncoder().encode(event)
        let decoded = try JSONDecoder().decode(NetworkActivityEvent.self, from: data)
        XCTAssertEqual(decoded.decision, "blocked_threat_domain")
        XCTAssertEqual(decoded.threat?.hostname, "evil.example")
        var old = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        old.removeValue(forKey: "threat"); old["decision"] = "observed_allowed"
        let legacy = try JSONDecoder().decode(NetworkActivityEvent.self, from: JSONSerialization.data(withJSONObject: old))
        XCTAssertNil(legacy.threat)
        XCTAssertEqual(legacy.decision, "observed_allowed")
    }
}
