import Foundation
import BoxCopCore
#if os(Linux)
import Glibc
#else
import Darwin
#endif

/// Real GUI-free client -> child -> policy/store smoke. Use a disposable data directory.
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
            print("READY: actual IPC v1 status, rules+sequence, no network listener")
            var identifiers: [UUID] = []
            let benign = "BoxCop portable smoke greeting"
            let fakeSensitive = "aws_access_key_id = AKIA" + String(repeating: "X", count: 16)
            for (kind, content, expected) in [
                (EventKind.clipboardCopy, benign, DecisionAction.allow),
                (.pasteAttempt, benign, .allow),
                (.clipboardCopy, fakeSensitive, .warn),
                (.pasteAttempt, fakeSensitive, .block)
            ] {
                let event = try DesktopEvent(kind: kind, content: content, bundleID: "com.apple.TextEdit", pid: 123, role: .engineering)
                guard case let .record(record) = try await engine.request(.evaluate(event)), record.action == expected else { throw EngineFailure.protocolViolation }
                identifiers.append(record.id)
                print("\(kind.rawValue): \(record.action.rawValue)")
            }
            guard case let .policies(policies) = try await engine.request(.policies), !policies.isEmpty else { throw EngineFailure.protocolViolation }
            guard case let .recent(items, total) = try await engine.request(.recent(30)), total >= identifiers.count,
                  identifiers.allSatisfy({ id in items.contains { $0.id == id } }) else { throw EngineFailure.protocolViolation }
            print("SMOKE_PASS: \(identifiers.count) evaluated records; \(policies.count) policies; recent_total=\(total)")
            var timeline = WorkflowTimeline()
            let instruction = timeline.append(kind: "agent_instruction", collector: "agent.hook", provenance: "reported",
                fields: ["instruction": WorkflowField(fakeSensitive, provenance: "reported")])
            timeline.append(kind: "network_connection", collector: "NetworkExtension", fields: [
                "hostname": WorkflowField("synthetic.example.test"), "decision": WorkflowField("blocked_threat_domain")], relatedEventIDs: [instruction])
            let context = WorkflowContext.build(from: timeline, sources: [.init("network", "active", "synthetic probe")])
            guard case let .workflow(review) = try await engine.request(.workflowContext(context)),
                  review.eventCount == 2, review.linkCount == 1, review.classifiedFields == 1,
                  review.signals.contains(where: { $0.kind == "observed_domain_block" }), review.shadowOnly,
                  case .workflowCleared = try await engine.request(.workflowClear) else { throw EngineFailure.protocolViolation }
            print("WORKFLOW_PASS: linked context accepted, text classified, network evidence retained, context cleared")
            guard case .stopped = try await engine.request(.shutdown) else { throw EngineFailure.protocolViolation }
            await engine.stop()
            try await engine.start(configuration: options.configuration)
            guard case let .recent(persisted, _) = try await engine.request(.recent(30)), identifiers.allSatisfy({ id in persisted.contains { $0.id == id } }) else { throw EngineFailure.protocolViolation }
            print("RESTART_PASS: sanitized records readable from the same data directory")
            await engine.stop()
            print("STOPPED: owned child terminated and reaped")
        } catch {
            await engine.stop()
            // Never print arbitrary error descriptions, CLI arguments, responses or clipboard text.
            print("PROBE_FAILED: \((error as? EngineFailure)?.description ?? "Unexpected probe failure.")")
            exit(1)
        }
    }
}
