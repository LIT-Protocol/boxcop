import Foundation
import Darwin
import EndpointSecurity
import Security
import BoxCopCore
import BoxCopEndpointSecurity

/// Invoked only on the activity service's serial control queue.
final class CredentialProtection {
    private var client: CredentialSecurityClient?
    private var state = CredentialProtectionStatus(state: "off", detail: "Credential protection is off.")
    private let preference = NetworkActivityService.root.appendingPathComponent("credential-protection.json")
    private var wanted = false

    init() {
        // The service has validated its root-owned 0700 directory before this runs.
        let fd = open(preference.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        if fd >= 0 {
            defer { close(fd) }
            var info = stat()
            if fstat(fd, &info) == 0, info.st_uid == 0, info.st_mode & S_IFMT == S_IFREG,
               info.st_mode & 0o077 == 0, info.st_size <= 8,
               let data = try? FileHandle(fileDescriptor: fd, closeOnDealloc: false).readToEnd(),
               let value = try? JSONDecoder().decode(Bool.self, from: data) { wanted = value }
            else { state = .init(state: "unavailable", detail: "Cannot read credential-protection preference.") }
        } else if errno != ENOENT { state = .init(state: "unavailable", detail: "Cannot read credential-protection preference.") }
        if wanted { start() }
    }
    func status() -> CredentialProtectionStatus {
        // Retry after the user grants FDA; no restart or polling daemon needed.
        if wanted && client == nil { start() }
        client?.refreshFileIndex()
        var report = client?.status() ?? state
        report.enabled = wanted
        return report
    }
    func setEnabled(_ enabled: Bool) -> String {
        do {
            try JSONEncoder().encode(enabled).write(to: preference, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: preference.path)
        } catch { return "Could not save credential protection preference." }
        wanted = enabled
        if enabled { if client == nil { start() } }
        else { client?.stop(); client = nil; state = .init(state: "off", detail: "Credential protection is off.") }
        return state.detail
    }
    func allowTemporarily(_ id: UUID) -> String {
        client?.allowTemporarily(id) == true ? "Allowed this process to read this file for five minutes. Retry the action." : "This block has expired. Retry the action to create a new event."
    }
    private func start() {
        var homes: Set<String> = []
        setpwent()
        while let entry = getpwent() {
            let home = String(cString: entry.pointee.pw_dir)
            guard home.hasPrefix("/"), home != "/", home != "/var/empty" else { continue }
            homes.insert(home)
            if let resolved = realpath(home, nil) { homes.insert(String(cString: resolved)); free(resolved) }
        }
        endpwent()
        guard !homes.isEmpty else { state = .init(state: "unavailable", detail: "Could not discover account home directories."); return }
        do {
            client = try CredentialSecurityClient(homeDirectories: Array(homes))
            state = client!.status()
        } catch CredentialSecurityClient.StartError.create(let result) where result == ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED {
            state = .init(state: "needsPermission", detail: "Allow BoxCop Network Filter in Full Disk Access, then refresh. Restart agents after protection starts.")
        } catch CredentialSecurityClient.StartError.create(let result) where result == ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED {
            state = .init(state: "unavailable", detail: "This extension is missing Apple's Endpoint Security entitlement. Install an updated signed build.")
        } catch {
            state = .init(state: "unavailable", detail: "Endpoint Security could not start. Retry enabling protection or reinstall the signed build.")
        }
    }

    /// Same-user processes must not disable credential protection. Authenticate
    /// the peer by its audit token and the app's Developer ID requirement.
    static func authorizedController(_ fd: Int32) -> Bool {
        var token = audit_token_t(), length = socklen_t(MemoryLayout<audit_token_t>.size)
        guard getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &length) == 0,
              length == MemoryLayout<audit_token_t>.size else { return false }
        var own: SecCode?, ownStatic: SecStaticCode?, info: CFDictionary?
        guard SecCodeCopySelf([], &own) == errSecSuccess, let own,
              SecCodeCopyStaticCode(own, [], &ownStatic) == errSecSuccess, let ownStatic,
              SecCodeCopySigningInformation(ownStatic, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let team = (info as? [String: Any])?[kSecCodeInfoTeamIdentifier as String] as? String,
              team.range(of: "^[A-Z0-9]{10}$", options: .regularExpression) != nil else { return false }
        let data = withUnsafeBytes(of: &token) { Data($0) }
        var peer: SecCode?, requirement: SecRequirement?
        let expression = "anchor apple generic and identifier \"local.sentinel.endpoint\" and certificate leaf[subject.OU] = \"\(team)\""
        guard SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributeAudit: data] as CFDictionary, [], &peer) == errSecSuccess,
              let peer, SecRequirementCreateWithString(expression as CFString, [], &requirement) == errSecSuccess,
              let requirement else { return false }
        return SecCodeCheckValidity(peer, [], requirement) == errSecSuccess
    }
}
