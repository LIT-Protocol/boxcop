import Foundation

/// One installed program with an advisory that still needs a decision.
public struct FindingItem: Equatable, Sendable {
    public let id: String
    public let name: String
    public let version: String
    public let path: String
    public let advisories: [String]
    public let guidance: String
    public let fixedVersions: String
    public let checkedAt: Date
    public init(id: String, name: String, version: String, path: String, advisories: [String], guidance: String, fixedVersions: String, checkedAt: Date) {
        self.id = id; self.name = name; self.version = version; self.path = path; self.advisories = advisories
        self.guidance = guidance; self.fixedVersions = fixedVersions; self.checkedAt = checkedAt
    }
}

/// One row in the Events list, whatever layer it came from.
public struct FeedEvent: Identifiable, Equatable, Sendable {
    public enum Status: String, Sendable {
        case blocked, warned, finding
        public var label: String { rawValue.prefix(1).uppercased() + rawValue.dropFirst() }
    }
    public enum Action: Equatable, Sendable {
        case allowRelease(PackageRelease), allowForPackage(package: String, host: String), openHealth, copyDetails
        public var title: String {
            switch self {
            case .allowRelease: return "Allow this release"
            case .allowForPackage: return "Allow for this package"
            case .openHealth: return "Open in Health"
            case .copyDetails: return "Copy details"
            }
        }
    }
    public let id: String
    public let time: Date
    public let layer: LayerID
    public let status: Status
    public let title: String
    /// Why, in plain words.
    public let reason: String
    /// What exactly: package@version, host, or the redacted command.
    public private(set) var command: String?
    public private(set) var workingDirectory: String?
    public private(set) var retryNote: String?
    public private(set) var approvalEventID: String?
    public let subject: String
    /// The agent or app it came from.
    public let source: String
    /// Who started it, outermost first.
    public let chain: [String]
    public let signing: String?
    public let policyIDs: [String]
    /// The exact release an install-gate row is about, when the engine named it.
    public let release: PackageRelease?
    /// True when that release is reported as malware but not confirmed, and is not already allowed.
    public let allowable: Bool
    public let exception: ScriptDestinationException?
    /// The local model's explanation, when smart triage produced one.
    public var explanation: String?

    public init(id: String, time: Date, layer: LayerID, status: Status, title: String, reason: String, subject: String, source: String,
                chain: [String] = [], signing: String? = nil, policyIDs: [String] = [], release: PackageRelease? = nil, allowable: Bool = false,
                exception: ScriptDestinationException? = nil, explanation: String? = nil) {
        self.id = id; self.time = time; self.layer = layer; self.status = status; self.title = title; self.reason = reason
        self.subject = subject; self.source = source; self.chain = chain; self.signing = signing; self.policyIDs = policyIDs
        self.release = release; self.allowable = allowable && release != nil; self.exception = exception; self.explanation = explanation
    }

    public var actions: [Action] {
        var actions: [Action] = []
        if let release, allowable, status == .blocked { actions.append(.allowRelease(release)) }
        if let exception, status == .blocked { actions.append(.allowForPackage(package: exception.package, host: exception.host)) }
        if status == .finding { actions.append(.openHealth) }
        return actions + [.copyDetails]
    }

    /// Plain text for a bug report or a teammate. Built only from what the row already shows.
    public var detailsText: String {
        let stamp = ISO8601DateFormatter().string(from: time)
        var lines = ["BoxCop event", "What happened: \(title)", "Status: \(status.label)", "Layer: \(layer.name)", "When: \(stamp)"]
        if !reason.isEmpty { lines.append("Why: \(reason)") }
        if !subject.isEmpty { lines.append("What exactly: \(subject)") }
        if let command { lines.append("Command: \(command)") }
        if let workingDirectory { lines.append("Directory: \(workingDirectory)") }
        if !chain.isEmpty { lines.append("Started by: \(chain.joined(separator: " -> "))") }
        if let signing { lines.append("Signed by: \(signing)") }
        if !policyIDs.isEmpty { lines.append("Rules: \(policyIDs.joined(separator: ", "))") }
        if let explanation { lines.append("Local model: \(explanation)") }
        lines.append("Reference: \(id)")
        return lines.joined(separator: "\n")
    }
}

extension FeedEvent {
    /// Layers 1, 2 and 4, as reported by the engine.
    public init(_ event: SecurityEvent) {
        let layer: LayerID
        switch event.layer {
        case .installGate: layer = .installGate
        case .containment: layer = .containment
        case .agentActions: layer = .agentChecks
        }
        let status: Status
        switch event.outcome {
        case .blocked: status = .blocked
        case .warned: status = .warned
        }
        let agent = event.agent.map(AgentHookHealth.displayName)
        var chain: [String] = []
        if let agent { chain.append(agent) }
        if layer == .containment, let command = event.command { chain.append(command) }
        if layer == .containment, let package = event.package { chain.append("install script of \(package)") }
        let exception: ScriptDestinationException?
        if layer == .containment, status == .blocked, let package = event.package, let host = event.host {
            exception = ScriptDestinationException(package: package, host: host)
        } else { exception = nil }
        // The feed has two tiers. Only the unconfirmed one may be allowed, and its row always says which tier it is.
        var reason = event.reason
        if layer == .installGate, status == .blocked, event.reportedOnly, !reason.localizedCaseInsensitiveContains("not yet confirmed") {
            reason = Self.reportedNotice + (reason.isEmpty ? "." : ". " + reason)
        }
        self.init(id: "engine:" + event.id, time: event.time, layer: layer, status: status, title: event.title, reason: reason,
                  subject: event.subject.isEmpty ? (event.package ?? event.host ?? event.command ?? "") : event.subject,
                  source: agent ?? (layer == .agentChecks ? "Agent" : "Package install"), chain: chain, policyIDs: event.policyIDs,
                  release: event.release, allowable: status == .blocked && event.allowable, exception: exception)
        command = event.command
        workingDirectory = event.workingDirectory
        retryNote = event.retryNote
        approvalEventID = event.canApprove ? event.id : nil
    }
    public static let reportedNotice = "Reported as malware, not yet confirmed"

    /// Layer 3. Only connections the network extension dropped become events.
    public init?(network event: NetworkActivityEvent) {
        guard let threat = event.threat else { return nil }
        func name(_ process: NetworkProcessMetadata) -> String? {
            process.name ?? process.executable.map { URL(fileURLWithPath: $0).lastPathComponent }
        }
        let process = name(event.process), app = name(event.responsibleApp)
        var chain = (event.process.ancestors ?? []).reversed().compactMap { $0.executable.map { URL(fileURLWithPath: $0).lastPathComponent } }
        if let app, app != process, !chain.contains(app) { chain.insert(app, at: 0) }
        if let process { chain.append(process) }
        var signing: [String] = []
        if let identifier = event.process.signingIdentifier { signing.append(identifier) }
        if let team = event.process.teamIdentifier { signing.append("team \(team)") }
        if signing.isEmpty, event.process.signingStatus != "unavailable" { signing.append(event.process.signingStatus.replacingOccurrences(of: "_", with: " ")) }
        self.init(id: "network:" + event.id.uuidString, time: event.timestamp, layer: .outboundControl, status: .blocked,
                  title: "Blocked connection to \(threat.hostname)",
                  reason: "\(threat.hostname) is on the list of known malware and phishing hosts (\(threat.source)). The connection was dropped before any data was sent.",
                  subject: threat.hostname + (event.remotePort.map { ":" + $0 } ?? ""),
                  source: app ?? process ?? "Unknown app", chain: chain, signing: signing.isEmpty ? nil : signing.joined(separator: ", "))
    }

    /// Layer 5. One row per installed program that still needs a decision.
    public init(finding item: FindingItem) {
        self.init(id: "finding:" + item.id, time: item.checkedAt, layer: .machineHealth, status: .finding,
                  title: "\(item.name) \(item.version) has a known security issue",
                  reason: item.guidance.isEmpty ? "A security advisory applies to this installed version." : item.guidance,
                  subject: "\(item.name) \(item.version) at \(item.path)" + (item.fixedVersions.isEmpty ? "" : " (fixed in \(item.fixedVersions))"),
                  source: "Machine health", policyIDs: item.advisories)
    }
}

public struct EventFilter: Equatable, Sendable {
    public enum Kind: String, CaseIterable, Sendable, Identifiable {
        case all = "All", blocked = "Blocked", findings = "Findings"
        public var id: String { rawValue }
    }
    public var kind: Kind
    public var layer: LayerID?
    public var search: String
    public init(kind: Kind = .all, layer: LayerID? = nil, search: String = "") { self.kind = kind; self.layer = layer; self.search = search }

    public func matches(_ event: FeedEvent) -> Bool {
        switch kind {
        case .all: break
        case .blocked: guard event.status == .blocked else { return false }
        case .findings: guard event.status == .finding else { return false }
        }
        if let layer, event.layer != layer { return false }
        let query = search.trimmingCharacters(in: .whitespaces)
        guard !query.isEmpty else { return true }
        return [event.title, event.subject, event.source, event.reason, event.command ?? "", event.workingDirectory ?? ""].contains { $0.localizedCaseInsensitiveContains(query) }
    }
}

public enum EventFeed {
    /// One list from every source, newest first. Duplicate ids keep the first row.
    public static func merge(security: [SecurityEvent], network: [NetworkActivityEvent], findings: [FindingItem],
                             explanations: [String: String] = [:]) -> [FeedEvent] {
        var rows = security.map(FeedEvent.init)
        rows += network.compactMap(FeedEvent.init(network:))
        rows += findings.map(FeedEvent.init(finding:))
        var seen = Set<String>()
        rows = rows.filter { seen.insert($0.id).inserted }
        for index in rows.indices { rows[index].explanation = explanations[rows[index].id] }
        return sort(rows)
    }

    public static func sort(_ rows: [FeedEvent]) -> [FeedEvent] {
        rows.sorted { a, b in a.time != b.time ? a.time > b.time : a.id < b.id }
    }

    public static func filter(_ rows: [FeedEvent], _ filter: EventFilter) -> [FeedEvent] { rows.filter(filter.matches) }
}
