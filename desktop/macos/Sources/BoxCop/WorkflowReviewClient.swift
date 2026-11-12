#if os(macOS)
import Foundation
import BoxCopCore

/// Dedicated background sidecar: context IPC/model work never queues ahead of a paste decision.
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
                    let directory = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/BoxCop/workflow-review")
                    try await client.start(configuration: EngineConfiguration.resolve(bundleURL: Bundle.main.bundleURL, environment: ProcessInfo.processInfo.environment, dataDirectory: directory))
                }
                guard let engine, !Task.isCancelled else { return }
                if clearPending { _ = try await engine.request(.workflowClear); clearPending = false }
                guard token == generation else { return }
                if case .workflow(let assessment) = try await engine.request(.workflowContext(context)), token == generation, !Task.isCancelled {
                    update("Local context: \(assessment.eventCount) observations · \(assessment.linkCount) links · \(assessment.classifiedFields) text fields classified · \(assessment.signals.count) review signals" + (assessment.incomplete ? " · incomplete coverage" : "") + ". Advisory only.", assessment.judgment)
                }
                if token != generation || clearPending { _ = try? await engine.request(.workflowClear); clearPending = false }
            } catch {
                NSLog("BoxCop workflow request failure: %@", (error as? EngineFailure)?.rawValue ?? "unknown")
                if token == generation { update("Local context reviewer unavailable. " + ((error as? EngineFailure)?.description ?? "Review request failed.") + " Timeline and deterministic protection continue.", nil) }
                await engine?.stop(); engine = nil
            }
        }
    }
}
#endif
