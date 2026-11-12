#if os(macOS)
import AppKit
import LocalAuthentication
import CryptoKit
import BoxCopCore

struct ReviewPolicies: Codable, Equatable {
    var external = false
    var destructive = false
    var spending = false
    var threshold_cents = 2500
    var currency = "usd"
}
struct ReviewRequest: Codable, Identifiable {
    let id: String
    let status: String
    let application: String
    let source: String
    let command: String
    let input: String
    let reasons: [String]
    let expires: Double
    var created: Double?
    var reviewed_at: Double?
    var consumed_at: Double?
}
/// Advisory, local-model text. Never part of what is approved.
struct ReviewSummary: Decodable {
    let summary: String?
    let concerns: [String]?
    let failed: Bool?
}
struct ReviewSnapshot: Decodable {
    let ok: Bool
    let policies: ReviewPolicies?
    let requests: [ReviewRequest]?
    let error: String?
    let managed_by: String?
    var summaries: [String: ReviewSummary]?
    var summary_model: Bool?
}

extension ReviewRequest {
    var item: ApprovalItem {
        ApprovalItem(id: id, application: application, reasons: reasons, command: AgentActionDetails(application: application, command: command, input: input).command ?? command,
                     status: consumed_at != nil ? "consumed" : status,
                     created: Date(timeIntervalSince1970: created ?? (expires - 600)), expires: Date(timeIntervalSince1970: expires))
    }
}

/// The approval inbox lives in the engine. Each call is one short engine run; approving makes the engine
/// start `BoxCop --review-agent-action`, which asks the Mac owner to authenticate.
enum ReviewService {
    static func request(_ payload: [String: Any]) async -> ReviewSnapshot? {
        guard let input = try? JSONSerialization.data(withJSONObject: payload),
              let data = await EngineTools.runAsync(["--human-review", "--data-dir", EngineTools.dataDirectory.path, "--executable", EngineTools.selfExecutable],
                                                    input: input, timeout: 125, requireSuccess: false, priority: .userInitiated) else { return nil }
        return try? JSONDecoder().decode(ReviewSnapshot.self, from: data)
    }
}

/// The CLI cannot supply an approval flag: this entry point always asks the Mac owner.
@MainActor enum AgentActionReview {
    static func run() -> Never {
        let bytes = FileHandle.standardInput.readData(ofLength: 100001)
        guard bytes.count <= 100000,
              let request = try? JSONDecoder().decode(ReviewRequest.self, from: bytes),
              request.status == "pending", request.expires > Date().timeIntervalSince1970 else { exit(1) }
        _ = NSApplication.shared
        NSApp.setActivationPolicy(.accessory)
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = "Approve this \(AgentActionDetails.agentName(request.application)) action once?"
        alert.informativeText = "\(request.reasons.joined(separator: "; "))\n\nAllows one exact retry in the reported session before expiry. This does not execute the action or verify completion."
        alert.addButton(withTitle: "Cancel")
        alert.addButton(withTitle: "Authenticate and approve")
        alert.buttons[0].keyEquivalent = "\r"
        alert.buttons[1].keyEquivalent = ""
        let scroll = NSScrollView(frame: NSRect(x: 0, y: 0, width: 650, height: 350))
        scroll.hasVerticalScroller = true
        let text = NSTextView(frame: scroll.bounds)
        text.isEditable = false; text.isSelectable = true
        text.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
        let details = AgentActionDetails(application: request.application, command: request.command, input: request.input)
        var lines = ["Agent: \(details.agent)" + (details.tool.map { " · \($0)" } ?? "")]
        if let path = details.workingDirectory { lines.append("Folder: \(path)") }
        if details.sandboxDisabled { lines.append("Sandbox: DISABLED for this command") }
        if let description = details.agentDescription { lines.append("Agent says: \(description)") }
        lines.append("\nCommand:\n\(details.command ?? request.command)")
        lines.append("\n— Exact request (this is what is approved) —\n\(details.rawJSON)")
        text.string = lines.joined(separator: "\n")
        text.isVerticallyResizable = true
        text.textContainer?.widthTracksTextView = true
        text.autoresizingMask = [.width]
        scroll.documentView = text
        alert.accessoryView = scroll
        guard alert.runModal() == .alertSecondButtonReturn else { exit(1) }
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else { exit(1) }
        var finished = false, approved = false
        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "approve the exact agent action you reviewed.") { success, _ in
            DispatchQueue.main.async { approved = success; finished = true }
        }
        let deadline = Date().addingTimeInterval(90)
        while !finished && Date() < deadline { RunLoop.current.run(until: Date().addingTimeInterval(0.05)) }
        context.invalidate()
        guard finished && approved && request.expires > Date().timeIntervalSince1970 else { exit(1) }
        let digest = SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
        print("{\"approved\":true,\"review_sha256\":\"\(digest)\"}")
        exit(0)
    }
}
#endif
