#if os(macOS)
import Foundation
import BoxCopCore

struct PendingApproval: Equatable, Sendable, Identifiable {
    let id: String
    let application: String
    let reasons: [String]
    let expires: Double
}

/// Watches the local approval inbox so held agent actions reach the person while the agent waits.
/// Read-only and display-only: approving and rejecting still go through the review service and Mac
/// authentication. Hooks rewrite the state file on every gated call, so changes are detected by
/// request identity and status, not by modification time alone.
@MainActor final class AgentApprovalWatcher: ObservableObject {
    @Published private(set) var pending: [PendingApproval] = []
    /// Bumped when request statuses or advisory summaries change, so an open inbox refreshes itself.
    @Published private(set) var revision = 0
    var onNew: ((PendingApproval) -> Void)?
    var onGone: (([String]) -> Void)?
    var onChange: (() -> Void)?
    /// Summaries come from the local model, so they are requested only while smart triage is on.
    var explainEnabled = false

    private let path: URL
    private var task: Task<Void, Never>?
    private var stamp: (Date, Int)?
    private var rows: [PendingApproval] = []
    private var signature: [String] = []
    private var announced: Set<String> = []
    private var explained: Set<String> = []
    private var explaining = false

    init(directory: URL = EngineTools.dataDirectory.appendingPathComponent("human-review", isDirectory: true)) {
        path = directory.appendingPathComponent("state.json")
    }

    func start() {
        guard task == nil else { return }
        task = Task { [weak self] in
            while !Task.isCancelled {
                self?.tick()
                try? await Task.sleep(nanoseconds: 2_000_000_000)
            }
        }
    }

    func stop() { task?.cancel(); task = nil }

    /// Asks for a fresh read, e.g. after the inbox approved or rejected a request.
    func touch() { stamp = nil; tick() }

    private func tick() {
        let attributes = try? FileManager.default.attributesOfItem(atPath: path.path)
        let next = attributes.map { (($0[.modificationDate] as? Date) ?? .distantPast, ($0[.size] as? Int) ?? 0) }
        if next == nil { rows = []; signature = [] }
        else if stamp.map({ $0 != next! }) ?? true, let read = read() {
            stamp = next
            if read.signature != signature { signature = read.signature; revision &+= 1 }
            rows = read.pending
        }
        let now = Date().timeIntervalSince1970
        let live = rows.filter { $0.expires > now }
        guard live != pending else { return }
        let before = Set(pending.map(\.id)), after = Set(live.map(\.id))
        pending = live
        for request in live where !announced.contains(request.id) {
            announced.insert(request.id); onNew?(request)
        }
        let gone = before.subtracting(after)
        if !gone.isEmpty { onGone?(Array(gone)) }
        onChange?()
        if !after.subtracting(explained).isEmpty { explain() }
    }

    private func read() -> (pending: [PendingApproval], signature: [String])? {
        guard let data = try? Data(contentsOf: path), data.count <= 2_000_000,
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let requests = object["requests"] as? [[String: Any]] else { return nil }
        var pending: [PendingApproval] = [], signature: [String] = []
        for row in requests {
            guard let id = row["id"] as? String, let status = row["status"] as? String else { continue }
            signature.append(id + ":" + status)
            if status == "pending", let expires = (row["expires"] as? NSNumber)?.doubleValue {
                pending.append(PendingApproval(id: id, application: row["application"] as? String ?? "agent",
                                               reasons: row["reasons"] as? [String] ?? [], expires: expires))
            }
        }
        return (pending, signature)
    }

    /// Optional local-model summaries. One batch at a time; each request is attempted once.
    private func explain() {
        guard !explaining, explainEnabled else { return }
        explaining = true
        let ids = Set(pending.map(\.id))
        Task { [weak self] in
            _ = await ReviewService.request(["op": "explain"])
            guard let self else { return }
            self.explained.formUnion(ids)
            self.explaining = false
            self.revision &+= 1
            if !Set(self.pending.map(\.id)).subtracting(self.explained).isEmpty { self.explain() }
        }
    }
}
#endif
