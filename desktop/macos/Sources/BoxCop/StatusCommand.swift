#if os(macOS)
import Foundation
import BoxCopCore

/// `BoxCop --status [--json]`: every layer's state without the GUI. Reads only; changes nothing.
enum StatusCommand {
    static func run(arguments: [String]) -> Never {
        let report = StatusReport(collect())
        print(arguments.contains("--json") ? report.json() : report.text())
        exit(report.exitCode)
    }

    static func collect(defaults: UserDefaults = .standard) -> ProtectionSummary {
        func wants(_ layer: LayerID) -> Bool { defaults.bool(forKey: AppModel.key(layer)) }
        let engine = EngineTools.available
        let directory = EngineTools.dataDirectory.path
        let protection = engine ? EngineTools.run(["--protection-status", "--data-dir", directory], timeout: 10).flatMap(EngineProtectionStatus.decode) : nil
        // A listener exists only while the app's engine is running.
        let running = protection.map { $0.package.listening || $0.scripts.listening } ?? false
        let hooks = engine ? EngineTools.run(HostAgents.engineArguments(["--host-agent-integrations", "status"]), timeout: 10, requireSuccess: false).flatMap(HostAgents.parse) : nil
        let snapshot = NetworkServiceClient.request("network-activity").flatMap { try? JSONDecoder().decode(NetworkActivitySnapshot.self, from: Data($0.utf8)) }
        let threat = snapshot?.threatProtection
        let bundled = NetworkFilterControl.bundled
        let layers = [
            LayerRules.installGate(engineAvailable: engine, engineRunning: running, wanted: wants(.installGate), configured: protection?.package.configured,
                                   routed: protection?.package.routed ?? false, listening: protection?.package.listening ?? false),
            LayerRules.containment(engineAvailable: engine, engineRunning: running, wanted: wants(.containment),
                                   routed: protection?.scripts.routed ?? false, listening: protection?.scripts.listening ?? false),
            LayerRules.outboundControl(bundled: bundled || snapshot != nil, wanted: wants(.outboundControl), extensionState: .unknown, filterEnabled: nil,
                                       reachable: snapshot != nil, threatBlocking: threat?.enabled ?? false, threatError: threat?.error, hosts: threat?.domainCount),
            LayerRules.agentChecks(engineAvailable: engine, wanted: wants(.agentChecks), agents: hooks?.connections.map { ($0.id, $0.health) }),
            LayerRules.machineHealth(engineAvailable: engine, wanted: wants(.machineHealth),
                                     hasReport: FileManager.default.fileExists(atPath: SoftwareInventory.cacheURL.path)),
            LayerRules.smartTriage(engineAvailable: engine, runtimeAvailable: EngineTools.inferenceAvailable, wanted: wants(.smartTriage), live: false)
        ]
        return ProtectionSummary(layers: layers, paused: defaults.bool(forKey: "boxcop.paused"))
    }
}
#endif
