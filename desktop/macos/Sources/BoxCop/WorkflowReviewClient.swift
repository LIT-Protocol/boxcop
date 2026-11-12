#if os(macOS)
import Foundation
import BoxCopCore

/// A dedicated engine for the local model, so model work never queues ahead of protection requests.
@MainActor final class WorkflowReviewClient {
    private var engine: EngineClient?
    private var task: Task<Void, Never>?
    private var generation = 0
    private var lastSent = Date.distantPast
    private var clearPending = false
    func clear() {
        generation += 1; clearPending = true; lastSent = .distantPast
        // An in-flight send is followed by clear in its completion path.
        if task == nil, let engine {
            task = Task { [weak self] in
                _ = try? await engine.request(.workflowClear)
                self?.clearPending = false; self?.task = nil
            }
        }
    }
    func stop() {
        generation += 1; task?.cancel()
        let old = engine; engine = nil
        Task { await old?.stop() }
    }
    func submit(_ context: WorkflowContext, update: @escaping (String, WorkflowJudgmentStatus?) -> Void) {
        guard task == nil, Date().timeIntervalSince(lastSent) >= 3 else { return }
        lastSent = Date(); let token = generation
        task = Task { [weak self] in
            guard let self else { return }
            defer { task = nil }
            do {
                if engine == nil {
                    let client = EngineClient()
                    engine = client
                    guard let configuration = EngineTools.configuration(dataDirectory: EngineTools.dataDirectory.appendingPathComponent("workflow-review")) else { throw EngineFailure.invalidConfiguration }
                    try await client.start(configuration: configuration)
                }
                guard let engine, !Task.isCancelled else { return }
                if clearPending { _ = try await engine.request(.workflowClear); clearPending = false }
                guard token == generation else { return }
                if case .workflow(let assessment) = try await engine.request(.workflowContext(context)), token == generation, !Task.isCancelled {
                    update("Reviewed \(assessment.eventCount) recent events.", assessment.judgment)
                }
                if token != generation || clearPending { _ = try? await engine.request(.workflowClear); clearPending = false }
            } catch {
                NSLog("BoxCop workflow request failure: %@", (error as? EngineFailure)?.rawValue ?? "unknown")
                if token == generation { update("The local model is unavailable. " + ((error as? EngineFailure)?.description ?? "The request failed.") + " Protection is not affected.", nil) }
                await engine?.stop(); engine = nil
            }
        }
    }
}
#endif
