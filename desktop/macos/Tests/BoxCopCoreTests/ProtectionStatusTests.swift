import XCTest
@testable import BoxCopCore

final class ProtectionStatusTests: XCTestCase {
    private func layers(_ states: [LayerState]) -> [LayerStatus] {
        zip(LayerID.allCases, states).map { LayerStatus($0, $1, "detail") }
    }

    func testProtectedNeedsLayersOneToFourOnAndNothingWaiting() {
        let all = ProtectionSummary(layers: layers([.on, .on, .on, .on, .on, .on]), paused: false)
        XCTAssertEqual(all.overall, .protected)
        // Machine health and smart triage may be off: they do not enforce.
        XCTAssertEqual(ProtectionSummary(layers: layers([.on, .on, .on, .on, .off, .off]), paused: false).overall, .protected)
        XCTAssertEqual(ProtectionSummary(layers: layers([.on, .on, .on, .on, .unavailable, .unavailable]), paused: false).overall, .protected)
        // A layer that was turned on but is not working yet removes the claim, even a non-enforcing one.
        XCTAssertEqual(ProtectionSummary(layers: layers([.on, .on, .on, .on, .on, .needsSetup]), paused: false).overall, .partlyProtected)
    }

    func testAnyEnforcingLayerMissingIsPartlyProtected() {
        for index in 0..<4 {
            for gap in [LayerState.off, .needsSetup, .unavailable] {
                var states: [LayerState] = [.on, .on, .on, .on, .on, .on]
                states[index] = gap
                let summary = ProtectionSummary(layers: layers(states), paused: false)
                XCTAssertEqual(summary.overall, .partlyProtected, "\(index) \(gap)")
                XCTAssertTrue(summary.anyEnforcing)
            }
        }
    }

    func testNothingEnforcingIsNotProtectedEvenWithHealthAndTriageOn() {
        let summary = ProtectionSummary(layers: layers([.off, .needsSetup, .unavailable, .off, .on, .on]), paused: false)
        XCTAssertEqual(summary.overall, .notProtected)
        XCTAssertFalse(summary.anyEnforcing)
        XCTAssertEqual(StatusReport(summary).exitCode, 1)
    }

    func testPausedWinsOverEverything() {
        XCTAssertEqual(ProtectionSummary(layers: layers([.on, .on, .on, .on, .on, .on]), paused: true).overall, .paused)
        XCTAssertEqual(ProtectionSummary(layers: layers([.off, .off, .off, .off, .off, .off]), paused: true).overall, .paused)
    }

    func testPartlySentenceCountsEachKindOfGap() {
        let summary = ProtectionSummary(layers: layers([.on, .needsSetup, .unavailable, .on, .off, .off]), paused: false)
        XCTAssertEqual(summary.sentence, "Of 6 layers, 1 needs setup, 2 are off and 1 is unavailable.")
        let one = ProtectionSummary(layers: layers([.on, .on, .on, .on, .on, .needsSetup]), paused: false)
        XCTAssertEqual(one.sentence, "Of 6 layers, 1 needs setup.")
    }

    func testStatusJSONShape() throws {
        let summary = ProtectionSummary(layers: [
            LayerRules.installGate(engineAvailable: true, engineRunning: true, wanted: true, configured: true, routed: true, listening: true, feedDate: "2026-11-10T08:00:00Z"),
            LayerRules.containment(engineAvailable: true, engineRunning: true, wanted: true, routed: true, listening: true),
            LayerRules.outboundControl(bundled: false, wanted: false, extensionState: .unknown, filterEnabled: nil, reachable: false, threatBlocking: false),
            LayerRules.agentChecks(engineAvailable: true, wanted: true, agents: [("claude", .connected), ("codex", .notDetected), ("cursor", .needsRepair)]),
            LayerRules.machineHealth(engineAvailable: true, wanted: true, hasReport: false),
            LayerRules.smartTriage(engineAvailable: true, runtimeAvailable: true, wanted: false)
        ], paused: false)
        let report = StatusReport(summary)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(report.json().utf8)) as? [String: Any])
        XCTAssertEqual(Set(object.keys), ["schema", "overall", "layers"])
        XCTAssertEqual(object["schema"] as? String, "boxcop.status.v1")
        XCTAssertEqual(object["overall"] as? String, "partly_protected")
        let rows = try XCTUnwrap(object["layers"] as? [[String: String]])
        XCTAssertEqual(rows.map { $0["id"] }, ["install_gate", "containment", "outbound_control", "agent_checks", "machine_health", "smart_triage"])
        XCTAssertEqual(rows.map { $0["state"] }, ["on", "on", "unavailable", "needs_setup", "needs_setup", "off"])
        XCTAssertTrue(rows.allSatisfy { Set($0.keys) == ["id", "state", "detail"] && $0["detail"]?.isEmpty == false })
        XCTAssertFalse(report.json().contains("\n"))
        XCTAssertEqual(report.exitCode, 0)
        let text = report.text().split(separator: "\n").map(String.init)
        XCTAssertEqual(text.first, "BoxCop: Partly protected")
        XCTAssertEqual(text.count, 7)
        XCTAssertTrue(text[1].hasPrefix("[x] Install gate: on. Feed dated 2026-11-10."))
        XCTAssertTrue(text[3].hasPrefix("[ ] Outbound control: unavailable. This build does not include the network extension."))
        XCTAssertTrue(text[4].contains("Cursor hooks need repair"))
    }

    func testLayerRulesNameTheMissingStep() {
        XCTAssertEqual(LayerRules.installGate(engineAvailable: false, engineRunning: false, wanted: true, configured: nil, routed: false, listening: false).state, .unavailable)
        XCTAssertEqual(LayerRules.installGate(engineAvailable: true, engineRunning: true, wanted: true, configured: false, routed: false, listening: false).state, .unavailable)
        XCTAssertEqual(LayerRules.installGate(engineAvailable: true, engineRunning: true, wanted: false, configured: true, routed: false, listening: false).state, .off)
        // Routed without a listener is not enforcing.
        XCTAssertEqual(LayerRules.installGate(engineAvailable: true, engineRunning: false, wanted: true, configured: true, routed: true, listening: false).state, .needsSetup)
        XCTAssertEqual(LayerRules.containment(engineAvailable: true, engineRunning: true, wanted: true, routed: true, listening: false).state, .needsSetup)
        XCTAssertEqual(LayerRules.containment(engineAvailable: true, engineRunning: true, wanted: false, routed: false, listening: false).state, .off)

        let recordingOnly = LayerRules.outboundControl(bundled: true, wanted: true, extensionState: .installed, filterEnabled: true, reachable: true, threatBlocking: false)
        XCTAssertEqual(recordingOnly.state, .needsSetup, "Recording without blocking is not enforcement")
        XCTAssertEqual(LayerRules.outboundControl(bundled: true, wanted: true, extensionState: .installed, filterEnabled: true, reachable: true, threatBlocking: true, hosts: 187113).state, .on)
        let approval = LayerRules.outboundControl(bundled: true, wanted: true, extensionState: .awaitingApproval, filterEnabled: false, reachable: false, threatBlocking: false)
        XCTAssertEqual(approval.state, .needsSetup); XCTAssertTrue(approval.detail.contains("System Settings"))
        XCTAssertEqual(LayerRules.outboundControl(bundled: true, wanted: false, extensionState: .missing, filterEnabled: false, reachable: false, threatBlocking: false).state, .off)

        XCTAssertEqual(LayerRules.agentChecks(engineAvailable: true, wanted: true, agents: [("claude", .notDetected), ("codex", .notDetected)]).state, .unavailable)
        XCTAssertEqual(LayerRules.agentChecks(engineAvailable: true, wanted: false, agents: [("claude", .notConnected)]).state, .off)
        XCTAssertEqual(LayerRules.agentChecks(engineAvailable: true, wanted: true, agents: [("claude", .connected), ("codex", .notConnected)]).state, .needsSetup)
        let agents = LayerRules.agentChecks(engineAvailable: true, wanted: true, agents: [("claude", .connected), ("codex", .connected), ("cursor", .notDetected)])
        XCTAssertEqual(agents, LayerStatus(.agentChecks, .on, "Checking actions in Claude Code and Codex."))

        XCTAssertEqual(LayerRules.machineHealth(engineAvailable: true, wanted: true, hasReport: true, findings: 2).detail, "2 findings to review.")
        XCTAssertEqual(LayerRules.smartTriage(engineAvailable: true, runtimeAvailable: false, wanted: true).state, .unavailable)
        let download = LayerRules.smartTriage(engineAvailable: true, runtimeAvailable: true, wanted: true, setupState: "downloading", fraction: 0.416)
        XCTAssertEqual(download, LayerStatus(.smartTriage, .needsSetup, "Downloading the model: 41% of 2.7 GB."))
        XCTAssertEqual(LayerRules.smartTriage(engineAvailable: true, runtimeAvailable: true, wanted: true, setupState: "ready").state, .on)
    }

    func testAgentHookHealthFromEngineStates() {
        XCTAssertEqual(AgentHookHealth(state: "not_detected"), .notDetected)
        XCTAssertEqual(AgentHookHealth(state: "not configured"), .notConnected)
        XCTAssertEqual(AgentHookHealth(state: "configured_not_observed"), .connected)
        XCTAssertEqual(AgentHookHealth(state: "callback observed"), .connected)
        for failing in ["configuration_conflict", "disabled_by_harness", "disable_setting_unverified", "callback_error", "unavailable"] {
            XCTAssertEqual(AgentHookHealth(state: failing), .needsRepair, failing)
        }
    }

    func testEngineProtectionStatusDecoding() {
        let wire = #"{"schema":"boxcop.protection-status.v1","package":{"configured":true,"routed":true,"listening":false},"scripts":{"routed":false,"listening":false}}"#
        let status = EngineProtectionStatus.decode(Data(wire.utf8))
        XCTAssertEqual(status?.package, .init(configured: true, routed: true, listening: false))
        XCTAssertEqual(status?.scripts, .init(routed: false, listening: false))
        XCTAssertNil(EngineProtectionStatus.decode(Data(wire.replacingOccurrences(of: ".v1", with: ".v2").utf8)))
        XCTAssertNil(EngineProtectionStatus.decode(Data("{}".utf8)))
    }
}
