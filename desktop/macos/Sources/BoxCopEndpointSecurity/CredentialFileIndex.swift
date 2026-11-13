import Foundation
import Darwin
import BoxCopCore

struct CredentialFileID: Hashable {
    let device: Int32
    let inode: UInt64
    init(_ info: stat) { device = info.st_dev; inode = info.st_ino }
}

/// Metadata only, outside ES callbacks. Existing aliases/hard links match by inode.
/// Periodic refresh narrows but does not eliminate the window for newly created
/// credentials accessed exclusively through aliases. No secret bytes are read.
enum CredentialFileIndex {
    static func load(homes: [String]) -> [CredentialFileID: String] {
        let policy = CredentialProtectionPolicy(homeDirectories: homes)
        var result: [CredentialFileID: String] = [:]
        for home in homes {
            var names = [".aws/credentials", ".config/gcloud/application_default_credentials.json", ".npmrc", ".pypirc", ".netrc"]
            names += ["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_ecdsa_sk", "id_ed25519_sk"].map { ".ssh/" + $0 }
            // Enumeration is bounded; oversized caches remain covered by path rules.
            if let enumerator = FileManager.default.enumerator(at: URL(fileURLWithPath: home + "/.aws/sso/cache"), includingPropertiesForKeys: nil, options: [.skipsSubdirectoryDescendants]) {
                var count = 0
                while let url = enumerator.nextObject() as? URL, count < 1024 {
                    count += 1
                    if url.pathExtension == "json" { names.append(".aws/sso/cache/" + url.lastPathComponent) }
                }
            }
            for name in names {
                let path = home + "/" + name
                var info = stat()
                if stat(path, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
                   case let .deny(category) = policy.evaluate(path: path, reads: true, scope: .agent) {
                    result[CredentialFileID(info)] = category
                }
            }
        }
        return result
    }
}
