import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

public struct SoftwareConsoleSnapshot: Decodable, Sendable {
    public let text: String
    public let status: String
    public let updatedAt: String
    public let truncated: Bool
}

public enum SoftwareConsole {
    public static func read(id: String, directory: URL) -> SoftwareConsoleSnapshot? {
        guard id.count == 24, id.allSatisfy({ "0123456789abcdef".contains($0) }) else { return nil }
        let root = open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard root >= 0 else { return nil }
        defer { close(root) }
        var info = stat()
        guard fstat(root, &info) == 0, info.st_uid == getuid(), info.st_mode & 0o077 == 0 else { return nil }
        let fd = openat(root, id + ".json", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
              info.st_uid == getuid(), info.st_mode & 0o077 == 0, info.st_size <= 2 * 1024 * 1024,
              let data = try? FileHandle(fileDescriptor: fd, closeOnDealloc: false).readToEnd() else { return nil }
        let decoder = JSONDecoder(); decoder.keyDecodingStrategy = .convertFromSnakeCase
        return try? decoder.decode(SoftwareConsoleSnapshot.self, from: data)
    }
}
