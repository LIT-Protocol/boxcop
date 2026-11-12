import Foundation
import BoxCopCore
#if os(Linux)
import Glibc
#else
import Darwin
#endif

/// GUI-free client -> engine smoke over the real pipe protocol. Use a disposable data directory.
@main struct BoxCopProbe {
    static func main() async {
        let options: ProbeOptions
        do { options = try ProbeOptions(arguments: Array(CommandLine.arguments.dropFirst())) }
        catch {
            print("Usage: BoxCopProbe --executable /absolute/engine [--arguments '[\"arg\"]'] --data-dir /private/disposable/directory")
            exit(64)
        }
        let engine = EngineClient(requestTimeout: 5)
        do {
            try await engine.start(configuration: options.configuration)
            print("READY: pipe protocol v1 status, rules engine")
            guard case let .packageProtection(package) = try await engine.request(.packageProtection(.status)) else { throw EngineFailure.protocolViolation }
            guard case let .scriptProtection(scripts) = try await engine.request(.scriptProtection(.status)) else { throw EngineFailure.protocolViolation }
            print("PROTECTION_PASS: package routed=\(package.routed) active=\(package.active); scripts routed=\(scripts.routed) active=\(scripts.active)")
            guard case let .securityEvents(events) = try await engine.request(.securityEvents(50)) else { throw EngineFailure.protocolViolation }
            guard events == events.sorted(by: { $0.time > $1.time }) || Set(events.map(\.time)).count < events.count else { throw EngineFailure.protocolViolation }
            print("EVENTS_PASS: \(events.count) security events, newest first")
            var timeline = WorkflowTimeline()
            let blocked = timeline.append(kind: "security_event", collector: "engine", provenance: "reported",
                fields: ["layer": WorkflowField("install_gate"), "outcome": WorkflowField("blocked"), "host": WorkflowField("synthetic.example.test")])
            timeline.append(kind: "network_connection", collector: "NetworkExtension", fields: [
                "hostname": WorkflowField("synthetic.example.test"), "decision": WorkflowField("blocked_threat_domain")], relatedEventIDs: [blocked])
            let context = WorkflowContext.build(from: timeline, sources: [.init("network", "active", "synthetic probe")])
            guard case let .workflow(review) = try await engine.request(.workflowContext(context)),
                  review.eventCount == 2, review.shadowOnly,
                  case .workflowCleared = try await engine.request(.workflowClear) else { throw EngineFailure.protocolViolation }
            print("WORKFLOW_PASS: linked context accepted and cleared")
            guard case .stopped = try await engine.request(.shutdown) else { throw EngineFailure.protocolViolation }
            await engine.stop()
            print("STOPPED: owned child terminated and reaped")
        } catch {
            await engine.stop()
            // Never print arbitrary error descriptions, CLI arguments or responses.
            print("PROBE_FAILED: \((error as? EngineFailure)?.description ?? "Unexpected probe failure.")")
            exit(1)
        }
    }
}
