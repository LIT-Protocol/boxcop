import Foundation
import Darwin
import EndpointSecurity
import BoxCopCore

/// Lifecycle is serialized by the extension control queue. ES callbacks are serial.
public final class CredentialSecurityClient {
    public enum StartError: Error {
        case create(es_new_client_result_t)
        case subscribe(es_return_t)
    }
    private var client: OpaquePointer?
    private let lock = NSLock()
    private var report = CredentialProtectionStatus(state: "active", detail: "Protecting recognized signed agents and tracked descendants. Restart agents after enabling protection.")
    private var tracker = CredentialProcessTracker()
    private var sequence: UInt64?
    private var exceptions = CredentialExceptions()
    private let homes: [String]
    private var fileIndex: [CredentialFileID: String]
    private let policy: CredentialProtectionPolicy

    public init(homeDirectories: [String]) throws {
        homes = homeDirectories
        fileIndex = CredentialFileIndex.load(homes: homeDirectories)
        policy = CredentialProtectionPolicy(homeDirectories: homeDirectories)
        var created: OpaquePointer?
        let result = es_new_client(&created) { [weak self] client, message in
            guard let self else {
                if message.pointee.event_type == ES_EVENT_TYPE_AUTH_OPEN { es_respond_flags_result(client, message, UInt32.max, false) }
                return
            }
            self.handle(client, message)
        }
        guard result == ES_NEW_CLIENT_RESULT_SUCCESS, let created else { throw StartError.create(result) }
        var events = [ES_EVENT_TYPE_AUTH_OPEN, ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_FORK, ES_EVENT_TYPE_NOTIFY_EXIT]
        let subscribed = es_subscribe(created, &events, UInt32(events.count))
        guard subscribed == ES_RETURN_SUCCESS else { es_delete_client(created); throw StartError.subscribe(subscribed) }
        client = created
    }
    public func refreshFileIndex() {
        let updated = CredentialFileIndex.load(homes: homes)
        lock.lock(); fileIndex = updated; lock.unlock()
    }
    public func status() -> CredentialProtectionStatus {
        lock.lock(); defer { lock.unlock() }; return report
    }
    public func allowTemporarily(_ id: UUID) -> Bool {
        lock.lock(); defer { lock.unlock() }; return exceptions.approve(id)
    }
    public func stop() {
        if let client { es_delete_client(client); self.client = nil }
    }
    private func token(_ value: audit_token_t) -> Data {
        var value = value; return withUnsafeBytes(of: &value) { Data($0) }
    }
    private func text(_ value: es_string_token_t) -> String {
        EndpointSecurityText.decode(value)
    }
    private func scope(_ process: es_process_t, version: UInt32) -> CredentialProtectionPolicy.Scope {
        // These pairs were verified from installed Developer ID apps. A name/path
        // alone never establishes identity. ES supplies kernel-validated signing data.
        let trusted = CredentialAgentIdentity.recognized(team: text(process.team_id), identifier: text(process.signing_id), flags: process.codesigning_flags)
        return tracker.scope(token: token(process.audit_token),
                             parent: version >= 4 ? token(process.parent_audit_token) : nil,
                             responsible: version >= 4 ? token(process.responsible_audit_token) : nil,
                             trustedAgent: trusted)
    }
    private func handle(_ client: OpaquePointer, _ pointer: UnsafePointer<es_message_t>) {
        let message = pointer.pointee
        if message.version >= 4 {
            if let previous = sequence, message.global_seq_num != previous &+ 1 { tracker.lostEvents() }
            sequence = message.global_seq_num
        } else { tracker.lostEvents() }
        let current = scope(message.process.pointee, version: message.version)
        switch message.event_type {
        case ES_EVENT_TYPE_NOTIFY_EXEC:
            let target = message.event.exec.target.pointee
            // Preserve scope across exec even when audit-token credentials change.
            _ = tracker.scope(token: token(target.audit_token), parent: token(message.process.pointee.audit_token), responsible: nil, trustedAgent: false)
            _ = scope(target, version: message.version)
        case ES_EVENT_TYPE_NOTIFY_FORK:
            tracker.fork(parent: token(message.process.pointee.audit_token), child: token(message.event.fork.child.pointee.audit_token))
        case ES_EVENT_TYPE_NOTIFY_EXIT:
            tracker.exit(token: token(message.process.pointee.audit_token))
        case ES_EVENT_TYPE_AUTH_OPEN:
            let event = message.event.open
            let file = event.file.pointee
            var decision = policy.evaluate(path: text(file.path), truncated: file.path_truncated,
                                           reads: event.fflag & Int32(FREAD) != 0, scope: current)
            let access = CredentialExceptions.Access(process: token(message.process.pointee.audit_token), device: file.stat.st_dev, inode: file.stat.st_ino)
            lock.lock()
            if current == .agent, event.fflag & Int32(FREAD) != 0, let category = fileIndex[CredentialFileID(file.stat)] {
                decision = .deny(category)
            }
            if exceptions.allows(access) { decision = .allow }
            lock.unlock()
            let flags: UInt32
            if case .deny = decision { flags = 0 } else { flags = UInt32.max }
            // Respond before taking the reporting lock. No I/O, inference or IPC.
            let result = es_respond_flags_result(client, pointer, flags, false)
            lock.lock()
            if result != ES_RESPOND_RESULT_SUCCESS { report.responseFailures &+= 1 }
            if case .unresolvedPath = decision { report.unresolved &+= 1; report.lastUnresolvedPath = String(text(file.path).prefix(1024)) }
            if case let .deny(category) = decision, result == ES_RESPOND_RESULT_SUCCESS {
                report.blocked &+= 1
                let event = CredentialBlockEvent(process: String(text(message.process.pointee.executable.pointee.path).suffix(512)), credential: category)
                report.events.append(event)
                exceptions.record(event.id, access: access)
                if report.events.count > 50 { report.events.removeFirst() }
            }
            lock.unlock()
        default: break
        }
        if tracker.degraded || report.responseFailures > 0 || report.unresolved > 0 {
            lock.lock(); report.state = "degraded"
            report.detail = "Some events or paths could not be handled reliably. Coverage is incomplete. Turn protection off and on, then restart agents."
            lock.unlock()
        }
    }
    deinit { stop() }
}

/// ES uses null data for empty signing/team identifiers (for example unsigned code).
enum EndpointSecurityText {
    static func decode(_ token: es_string_token_t) -> String {
        guard token.length > 0, let data = token.data else { return "" }
        return String(decoding: UnsafeBufferPointer(start: UnsafeRawPointer(data).assumingMemoryBound(to: UInt8.self), count: token.length), as: UTF8.self)
    }
}
