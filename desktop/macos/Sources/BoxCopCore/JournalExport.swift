import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

/// Explicit plaintext export; never writes keys or silently overwrites an existing destination.
public enum JournalExport {
    public static func run(purpose: String, source: URL, destination: URL, encryption: JournalEncryption? = nil) throws {
        guard ["workflow", "network", "network-summary", "development", "agent-egress"].contains(purpose) else {
            throw JournalEncryption.Failure.invalidRecord
        }
        var info = stat()
        guard lstat(source.path, &info) == 0, (info.st_uid == geteuid() || (purpose == "agent-egress" && geteuid() == 0)), info.st_mode & 0o077 == 0 else {
            throw CocoaError(.fileReadNoPermission)
        }
        let isDirectory = info.st_mode & S_IFMT == S_IFDIR
        let files: [URL]
        if isDirectory {
            files = try FileManager.default.contentsOfDirectory(at: source, includingPropertiesForKeys: nil).filter {
                if purpose == "agent-egress" { return ["events.jsonl", "events.jsonl.1", "events.jsonl.2", "events.jsonl.3"].contains($0.lastPathComponent) }
                if purpose == "workflow" { return WorkflowJournal.isSegment($0.lastPathComponent) }
                if purpose == "network" { return ["connections.jsonl", "connections.previous.jsonl"].contains($0.lastPathComponent) }
                return $0.lastPathComponent == (purpose == "development" ? "development.jsonl" : "network-summary.json")
            }.sorted { $0.lastPathComponent < $1.lastPathComponent }
        } else { files = [source] }
        guard !files.isEmpty else { throw CocoaError(.fileNoSuchFile) }
        let cipher = encryption ?? JournalEncryption(purpose: purpose, allowInteraction: true)
        let agentReader: ((Data) throws -> Data)?
        if purpose == "agent-egress" {
            let root = (isDirectory ? source : source.deletingLastPathComponent()).deletingLastPathComponent()
            agentReader = try AgentJournalKey.reader(privateKeyFile: root.appendingPathComponent("agent-egress-private.enc"))
        } else { agentReader = nil }
        // All records authenticate before any plaintext is written.
        var outputs: [(URL, Data)] = []
        var total = 0
        for file in files {
            guard let data = try JournalEncryption.readPrivate(file, maximumBytes: 48 * 1024 * 1024, allowRoot: purpose == "agent-egress") else { throw CocoaError(.fileNoSuchFile) }
            total += data.count
            guard total <= 256 * 1024 * 1024 else { throw CocoaError(.fileReadTooLarge) }
            let plaintext: Data
            if purpose == "network-summary" { plaintext = try cipher.open(data) }
            else {
                var decoded = Data()
                let rows = data.split(separator: 10, omittingEmptySubsequences: false)
                for (index, row) in rows.enumerated() {
                    if !row.isEmpty {
                        if let agentReader {
                            decoded.append(try agentReader(Data(row)))
                        } else { decoded.append(try cipher.open(Data(row))) }
                    }
                    if index < rows.count - 1 { decoded.append(10) }
                }
                plaintext = decoded
            }
            outputs.append((destination.appendingPathComponent(file.lastPathComponent), plaintext))
        }
        if isDirectory && purpose == "workflow",
           let health = try JournalEncryption.readPrivate(source.appendingPathComponent("health.json"), maximumBytes: 4096) {
            _ = try JSONDecoder().decode(WorkflowJournal.State.self, from: health)
            outputs.append((destination.appendingPathComponent("health.json"), health))
        }
        // mkdir, not createDirectory(withIntermediateDirectories:), rejects existing output.
        guard mkdir(destination.path, 0o700) == 0 else { throw CocoaError(.fileWriteFileExists) }
        do {
            for (file, data) in outputs { try JournalEncryption.replacePrivate(file, data: data) }
        } catch {
            try? FileManager.default.removeItem(at: destination)
            throw error
        }
    }
}
