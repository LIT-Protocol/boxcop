import Foundation
#if canImport(CryptoKit)
import CryptoKit
import Security
import LocalAuthentication
#endif
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

/// Versioned, authenticated records. Keys never reside beside the journal.
/// Serial caller only; each writer owns its cipher. No plaintext fallback.
public final class JournalEncryption {
    public enum Failure: Error { case unavailable, keychain(Int32), invalidRecord }
    public static let prefix = Data("boxcop.encrypted.v1:".utf8)
    private let purpose: String
    private let keyProvider: (Bool) throws -> Data
    private var cachedKey: Data?

    public init(purpose: String, allowInteraction: Bool = false) {
        self.purpose = purpose
        self.keyProvider = { create in try Self.keychainKey(purpose: purpose, create: create, allowInteraction: allowInteraction) }
    }
    // Test injection stays internal: production never substitutes an insecure cipher.
    init(purpose: String, keyProvider: @escaping (Bool) throws -> Data) {
        self.purpose = purpose; self.keyProvider = keyProvider
    }
    private func key(create: Bool) throws -> Data {
        if let cachedKey { return cachedKey }
        let bytes = try keyProvider(create)
        guard bytes.count == 32 else { throw Failure.invalidRecord }
        cachedKey = bytes
        return bytes
    }
    public func seal(_ plaintext: Data) throws -> Data {
#if canImport(CryptoKit)
        let box = try AES.GCM.seal(plaintext, using: SymmetricKey(data: key(create: true)),
                                   authenticating: Data(("boxcop.encrypted.v1:" + purpose).utf8))
        guard let combined = box.combined else { throw Failure.invalidRecord }
        return Self.prefix + Data(combined.base64EncodedString().utf8)
#else
        throw Failure.unavailable
#endif
    }
    public func open(_ record: Data) throws -> Data {
#if canImport(CryptoKit)
        guard record.starts(with: Self.prefix),
              let combined = Data(base64Encoded: record.dropFirst(Self.prefix.count)) else { throw Failure.invalidRecord }
        return try AES.GCM.open(AES.GCM.SealedBox(combined: combined), using: SymmetricKey(data: key(create: false)),
                                authenticating: Data(("boxcop.encrypted.v1:" + purpose).utf8))
#else
        throw Failure.unavailable
#endif
    }
    /// Migrate only owner-private regular files, replacing atomically with ciphertext.
    /// Partial final records are encrypted too, preserving replay's incomplete-tail signal.
    func migrate(_ url: URL, maximumBytes: Int, lines: Bool = true) throws {
        guard let data = try Self.readPrivate(url, maximumBytes: maximumBytes) else { return }
        let records = lines ? data.split(separator: 10, omittingEmptySubsequences: false).map { Data($0) } : [data]
        // Authenticate existing encrypted records before creating a key or replacing anything.
        for (index, row) in records.enumerated() where row.starts(with: Self.prefix) {
            if lines && index == records.count - 1 && data.last != 10 {
                // A crash-truncated tail is retained for diagnosis; never append to it.
                // Still require the old key, rather than silently generating a replacement.
                _ = try key(create: false)
            } else { _ = try open(row) }
        }
        guard records.contains(where: { !$0.isEmpty && !$0.starts(with: Self.prefix) }) else { return }
        var output = Data()
        for (index, row) in records.enumerated() {
            if !row.isEmpty { output.append(try row.starts(with: Self.prefix) ? row : seal(row)) }
            if lines && index < records.count - 1 { output.append(10) }
        }
        guard output.count <= maximumBytes else { throw CocoaError(.fileWriteOutOfSpace) }
        try Self.replacePrivate(url, data: output)
    }
    static func readPrivate(_ url: URL, maximumBytes: Int, allowRoot: Bool = false) throws -> Data? {
        let fd = openFile(url.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        if fd < 0 { if errno == ENOENT { return nil }; throw CocoaError(.fileReadNoPermission) }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG, (info.st_uid == geteuid() || (allowRoot && geteuid() == 0)),
              info.st_mode & 0o077 == 0, info.st_nlink == 1, info.st_size <= maximumBytes else { throw CocoaError(.fileReadNoPermission) }
        return try FileHandle(fileDescriptor: fd, closeOnDealloc: false).readToEnd() ?? Data()
    }
    static func replacePrivate(_ url: URL, data: Data) throws {
        let temp = url.deletingLastPathComponent().appendingPathComponent(".encrypted-\(UUID().uuidString).tmp")
        let fd = openFile(temp.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw CocoaError(.fileWriteNoPermission) }
        defer { close(fd); unlink(temp.path) }
        try FileHandle(fileDescriptor: fd, closeOnDealloc: false).write(contentsOf: data)
        guard fsync(fd) == 0, rename(temp.path, url.path) == 0 else { throw CocoaError(.fileWriteUnknown) }
        let parent = openFile(url.deletingLastPathComponent().path, O_RDONLY | O_CLOEXEC)
        guard parent >= 0 else { throw CocoaError(.fileWriteUnknown) }
        defer { close(parent) }
        guard fsync(parent) == 0 else { throw CocoaError(.fileWriteUnknown) }
    }
    static func keychainKey(purpose: String, create: Bool, allowInteraction: Bool, keychainPath: String? = nil) throws -> Data {
#if canImport(CryptoKit)
        var query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "local.boxcop.journal-encryption.v1",
            kSecAttrAccount as String: "\(geteuid()):\(purpose)"]
        // Daemons use the system keychain, independent of a logged-in user's keychain.
        var system: SecKeychain?
        if geteuid() == 0 || keychainPath != nil {
            let status = SecKeychainOpen(keychainPath ?? "/Library/Keychains/System.keychain", &system)
            guard status == errSecSuccess, let system else { throw Failure.keychain(status) }
            query[kSecMatchSearchList as String] = [system]
        }
        if !allowInteraction {
            let context = LAContext(); context.interactionNotAllowed = true
            query[kSecUseAuthenticationContext as String] = context
        }
        var lookup = query
        lookup[kSecReturnData as String] = true
        lookup[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(lookup as CFDictionary, &result)
        if status == errSecSuccess, let data = result as? Data { return data }
        guard status == errSecItemNotFound, create else { throw Failure.keychain(status) }
        let data = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
        query.removeValue(forKey: kSecMatchSearchList as String)
        if let system { query[kSecUseKeychain as String] = system }
        query[kSecValueData as String] = data
        query[kSecAttrLabel as String] = "BoxCop encrypted \(purpose) history"
        let added = SecItemAdd(query as CFDictionary, nil)
        if added == errSecDuplicateItem { return try keychainKey(purpose: purpose, create: false, allowInteraction: allowInteraction, keychainPath: keychainPath) }
        guard added == errSecSuccess else { throw Failure.keychain(added) }
        return data
#else
        throw Failure.unavailable
#endif
    }
}
private func openFile(_ path: String, _ flags: Int32, _ mode: mode_t = 0) -> Int32 {
#if canImport(Darwin)
    Darwin.open(path, flags, mode)
#else
    Glibc.open(path, flags, mode)
#endif
}
