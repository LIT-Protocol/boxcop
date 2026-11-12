import Foundation
import Darwin
import Security
import BoxCopCore

/// Best-effort telemetry, never used to authorize a connection. Unknown processes remain visible.
enum NetworkProcessInspection {
    static func inspect(_ token: Data?) -> NetworkProcessMetadata {
        var result = NetworkProcessMetadata()
        guard let token, token.count == 32 else { return result }
        let words = token.withUnsafeBytes { bytes in (0..<8).map { bytes.loadUnaligned(fromByteOffset: $0 * 4, as: UInt32.self) } }
        result.uid = words[1]; result.pid = words[5]; result.incarnation = words[7]
        var code: SecCode?
        if SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributeAudit as String: token] as CFDictionary, [], &code) == errSecSuccess, let code {
            let status = SecCodeCheckValidity(code, [], nil)
            result.signingStatus = status == errSecSuccess ? "valid" : "invalid_or_unsigned(\(status))"
            var info: CFDictionary?
            var staticCode: SecStaticCode?
            if SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
               SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess, let values = info as? [String: Any] {
                result.executable = (values[kSecCodeInfoMainExecutable as String] as? URL)?.path
                result.signingIdentifier = (values[kSecCodeInfoIdentifier as String] as? String).map { String($0.prefix(4096)) }
                result.teamIdentifier = (values[kSecCodeInfoTeamIdentifier as String] as? String).map { String($0.prefix(64)) }
                result.signingFlags = (values[kSecCodeInfoFlags as String] as? NSNumber)?.uint32Value
                result.signingAuthorities = (values[kSecCodeInfoCertificates as String] as? [SecCertificate])?.prefix(8).compactMap { certificate in
                    var name: CFString?
                    guard SecCertificateCopyCommonName(certificate, &name) == errSecSuccess, let name else { return nil }
                    return String((name as String).prefix(512))
                }
                result.codeHash = (values[kSecCodeInfoUnique as String] as? Data)?.map { String(format: "%02x", $0) }.joined()
            }
        }
        let pid = pid_t(bitPattern: words[5])
        // Do not attach a reused PID's path, arguments or ancestry to an older flow.
        if currentToken(pid) == token {
            let livePath = path(pid)
            let args = arguments(pid)
            let parents = ancestors(pid)
            if currentToken(pid) == token {
                result.executable = result.executable ?? livePath
                result.arguments = args; result.ancestors = parents
                result.metadataStatus = "live_process_snapshot"
            } else { result.metadataStatus = "process_exited_or_changed" }
        } else { result.metadataStatus = "audit_identity_only" }
        result.executable = result.executable.map { String($0.prefix(4096)) }
        result.name = result.executable.map { URL(fileURLWithPath: $0).lastPathComponent }
        return result
    }
    static func currentToken(_ pid: pid_t) -> Data? {
        var task: mach_port_name_t = 0
        guard pid > 0, task_name_for_pid(mach_task_self_, pid, &task) == KERN_SUCCESS else { return nil }
        defer { mach_port_deallocate(mach_task_self_, task) }
        var token = audit_token_t()
        var count = mach_msg_type_number_t(MemoryLayout<audit_token_t>.size / MemoryLayout<integer_t>.size)
        let status = withUnsafeMutablePointer(to: &token) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { task_info(task, task_flavor_t(TASK_AUDIT_TOKEN), $0, &count) }
        }
        return status == KERN_SUCCESS ? withUnsafeBytes(of: token) { Data($0) } : nil
    }
    private static func path(_ pid: pid_t) -> String? {
        var buffer = [CChar](repeating: 0, count: 4096)
        guard proc_pidpath(pid, &buffer, UInt32(buffer.count)) > 0 else { return nil }
        return String(cString: buffer)
    }
    private static func ancestors(_ pid: pid_t) -> [NetworkProcessAncestor] {
        var current = pid, seen = Set<pid_t>(), result: [NetworkProcessAncestor] = []
        while current > 1, result.count < 16, seen.insert(current).inserted {
            var info = proc_bsdshortinfo()
            guard proc_pidinfo(current, PROC_PIDT_SHORTBSDINFO, 0, &info, Int32(MemoryLayout.size(ofValue: info))) == MemoryLayout.size(ofValue: info) else { break }
            current = pid_t(bitPattern: info.pbsi_ppid)
            guard current > 0 else { break }
            result.append(.init(pid: UInt32(current), executable: path(current).map { String($0.prefix(512)) }))
        }
        return result
    }
    private static func arguments(_ pid: pid_t) -> [String]? {
        var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid], size = 0
        guard sysctl(&mib, UInt32(mib.count), nil, &size, nil, 0) == 0, size > 4, size <= 1_048_576 else { return nil }
        var bytes = [UInt8](repeating: 0, count: size)
        guard sysctl(&mib, UInt32(mib.count), &bytes, &size, nil, 0) == 0 else { return nil }
        let argc = bytes.withUnsafeBytes { $0.loadUnaligned(as: Int32.self) }
        guard argc > 0 else { return [] }
        var index = 4
        while index < size && bytes[index] != 0 { index += 1 } // executable path
        while index < size && bytes[index] == 0 { index += 1 }
        var result: [String] = [], remaining = 4096
        while index < size && result.count < min(Int(argc), 64) && remaining > 0 {
            let start = index
            while index < size && bytes[index] != 0 { index += 1 }
            let value = String(decoding: bytes[start..<min(index, start + remaining)], as: UTF8.self)
            result.append(value); remaining -= value.utf8.count; index += 1
        }
        return result // Never read environment variables after argv.
    }
}
