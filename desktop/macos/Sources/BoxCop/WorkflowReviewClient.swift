#if os(macOS)
import Foundation
import BoxCopCore

/// The one engine that may run the local model, so model work never queues ahead of protection requests.
/// Nothing else in the app starts a model. Stopping this engine stops the model runtime with it.
@MainActor final class WorkflowReviewClient {
    private var engine: EngineClient?
    private var task: Task<Void, Never>?
    private var generation = 0
    private var lastSent = Date.distantPast
    private var clearPending = false
    /// Above zero while an old engine is still exiting; no new one starts until it has gone.
    private var stopping = 0

    static var dataDirectory: URL { EngineTools.dataDirectory.appendingPathComponent("workflow-review") }

    func clear() {
        generation += 1; clearPending = true; lastSent = .distantPast
        // An in-flight send is followed by clear in its completion path.
        if task == nil, let engine {
            task = Task { [weak self] in
                _ = try? await engine.request(.workflowClear())
                self?.clearPending = false; self?.task = nil
            }
        }
    }
    /// Triage off, protection paused, or a failed setup being retried.
    func stop() { Task { await stopAndWait() } }
    /// Returns once the reviewer engine has exited, including one that was still starting.
    func stopAndWait() async {
        generation += 1; lastSent = .distantPast
        stopping += 1; defer { stopping -= 1 }
        let inFlight = task; inFlight?.cancel()
        let old = engine; engine = nil
        await old?.stop()
        await inFlight?.value
    }
    func submit(_ context: WorkflowContext, update: @escaping (String, WorkflowJudgmentStatus?) -> Void) {
        guard task == nil, stopping == 0, Date().timeIntervalSince(lastSent) >= 3 else { return }
        lastSent = Date(); let token = generation
        task = Task { [weak self] in
            guard let self else { return }
            defer { task = nil }
            var started: EngineClient?
            do {
                if engine == nil {
                    guard let configuration = EngineTools.configuration(dataDirectory: Self.dataDirectory) else { throw EngineFailure.invalidConfiguration }
                    let client = EngineClient()
                    engine = client; started = client
                    try await client.start(configuration: configuration)
                    // stop() may have run while this engine was starting. It is never left behind, and never replaced by a second one.
                    guard engine === client, token == generation, !Task.isCancelled else {
                        await client.stop()
                        if engine === client { engine = nil }
                        return
                    }
                }
                guard let engine, !Task.isCancelled else { return }
                if clearPending { _ = try await engine.request(.workflowClear()); clearPending = false }
                guard token == generation else { return }
                if case .workflow(let assessment) = try await engine.request(.workflowContext(context)), token == generation, !Task.isCancelled {
                    update("Reviewed \(assessment.eventCount) recent events.", assessment.judgment)
                }
                if token != generation || clearPending { _ = try? await engine.request(.workflowClear()); clearPending = false }
            } catch {
                NSLog("BoxCop workflow request failure: %@", (error as? EngineFailure)?.rawValue ?? "unknown")
                if token == generation { update("The local model is unavailable. " + ((error as? EngineFailure)?.description ?? "The request failed.") + " Protection is not affected.", nil) }
                await started?.stop()
                if let current = engine, started == nil || current === started { await current.stop(); engine = nil }
            }
        }
    }

    /// Deletes the downloaded model through a short-lived engine that never loads it. Nil when the engine did not answer.
    func removeModel() async -> ModelRemoval? {
        await stopAndWait()
        guard let configuration = EngineTools.configuration(dataDirectory: Self.dataDirectory) else { return nil }
        stopping += 1; defer { stopping -= 1 }
        let client = EngineClient(requestTimeout: 30)
        var removal: ModelRemoval?
        if (try? await client.start(configuration: configuration)) != nil,
           case let .workflowCleared(answer)? = try? await client.request(.workflowClear(removeModel: true)) { removal = answer }
        await client.stop()
        return removal
    }
}
#endif
