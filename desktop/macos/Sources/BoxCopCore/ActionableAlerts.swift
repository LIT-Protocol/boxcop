import Foundation

/// Presentation only. Producers retain detection, consent, deduplication and resolution.
public struct ActionableAlert: Equatable, Sendable, Identifiable {
    public enum Category: String, Sendable, CaseIterable {
        case protection, email, draft, code, pdf, software, workflow, approval
        public var supportsHeadsUp: Bool { [.email, .draft, .code, .pdf].contains(self) }
        public var title: String {
            switch self {
            case .email: return "Review your AI-assisted email"
            case .draft: return "Review before sending"
            case .code: return "Review code checks"
            case .pdf: return "Review your PDF attachment"
            case .software: return "Software needs review"
            case .protection: return "Protection needs attention"
            case .workflow: return "Workflow findings"
            case .approval: return "An agent is waiting for your approval"
            }
        }
    }
    public let category: Category
    public let itemIDs: Set<String>
    public var id: Category { category }
    public init(category: Category, itemIDs: Set<String>) {
        self.category = category; self.itemIDs = itemIDs
    }
    public var keys: Set<String> { Set(itemIDs.map { category.rawValue + ":" + $0 }) }
    public static func countSummary(_ count: Int) -> String {
        count == 1 ? "1 item needs review" : "\(count) items need review"
    }
}

public enum ReviewAlertDelivery: Equatable, Sendable { case none, notification, headsUp }
public enum ReviewHeadsUpOutcome: Equatable, Sendable { case notUsed, requested, duplicate }
public enum ReviewAlertDeliveryPolicy {
    public static func delivery(category: ActionableAlert.Category, featureAllowed: Bool,
                                notificationsAllowed: Bool, bannersAllowed: Bool,
                                headsUpsEnabled: Bool, sharing: Bool, voiceOver: Bool = false) -> ReviewAlertDelivery {
        guard featureAllowed, notificationsAllowed else { return .none }
        // A heads-up replaces the macOS request, so there is never a second banner.
        return category.supportsHeadsUp && bannersAllowed && headsUpsEnabled && !sharing && !voiceOver ? .headsUp : .notification
    }
}

public struct ReviewHeadsUpItem: Equatable, Sendable, Identifiable {
    public let category: ActionableAlert.Category
    public let itemID: String
    public var id: String { category.rawValue + ":" + itemID }
    public init(category: ActionableAlert.Category, itemID: String) { self.category = category; self.itemID = itemID }
}

/// An event-driven, session-local presentation ledger. Time is injected (monotonic seconds).
/// Hiding never changes producer evidence or pending-review counts. There is no backlog replay.
public struct ReviewHeadsUpState: Sendable {
    public static let duration: TimeInterval = 8
    public static let burstLimit: TimeInterval = 20
    public private(set) var items: [ReviewHeadsUpItem] = []
    private var seen: Set<String> = []
    private var order: [String] = []
    private var startedAt: TimeInterval = 0
    private var expiresAt: TimeInterval = 0
    private var hoverStartedAt: TimeInterval?
    public init() {}

    public var title: String { items.count == 1 ? items[0].category.title : "Review \(items.count) items" }
    public var singleDestination: ReviewHeadsUpItem? { items.count == 1 ? items.first : nil }

    @discardableResult
    public mutating func offer(_ item: ReviewHeadsUpItem, eligible: Bool, now: TimeInterval, keepVisible: Bool) -> Bool {
        tick(now: now, keepVisible: keepVisible)
        guard seen.insert(item.id).inserted else { return false }
        order.append(item.id)
        if order.count > 4096 { seen.remove(order.removeFirst()) }
        guard eligible, item.category.supportsHeadsUp else { return false }
        let effectiveNow = hoverStartedAt ?? now
        if items.isEmpty { startedAt = effectiveNow }
        items.append(item)
        expiresAt = min(effectiveNow + Self.duration, startedAt + Self.burstLimit)
        return true
    }
    public mutating func tick(now: TimeInterval, keepVisible: Bool) {
        if !items.isEmpty, !keepVisible, hoverStartedAt == nil, now >= expiresAt { hide() }
    }
    public mutating func hover(_ hovering: Bool, now: TimeInterval) {
        if hovering, hoverStartedAt == nil { hoverStartedAt = now }
        else if !hovering, let start = hoverStartedAt {
            let elapsed = max(0, now - start)
            startedAt += elapsed; expiresAt += elapsed; hoverStartedAt = nil
        }
    }
    /// Removal-only safety net. New state can never manufacture a heads-up.
    public mutating func retain(_ liveKeys: Set<String>) {
        items.removeAll { !liveKeys.contains($0.id) }
        if items.isEmpty { hide() }
    }
    public mutating func hide() { items = []; hoverStartedAt = nil }
}
