import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

/// Projection of Apple's IPS format. Decode only the fields needed here; never
/// serialize the original report, diagnostic strings, paths, registers or symbols.
public struct CrashReport: Encodable, Sendable {
    public struct Frame: Encodable, Sendable {
        public let image_uuid: UUID
        public let image_offset: UInt64
        public let image_kind: String
    }
    public let schema_version = 1
    public let kind = "crash"
    public let report_id: UUID
    public let app_version: String
    public let app_build: String
    public let os_version: String
    public let architecture: String
    public let exception: String
    public let signal: String
    public let frames: [Frame]

    public static let maximumFileBytes = 8 * 1024 * 1024
    public static let exceptions: Set<String> = ["EXC_BAD_ACCESS", "EXC_BAD_INSTRUCTION", "EXC_ARITHMETIC", "EXC_BREAKPOINT",
        "EXC_CRASH", "EXC_RESOURCE", "EXC_GUARD", "EXC_SOFTWARE", "EXC_EMULATION"]
    public static let signals: Set<String> = ["SIGABRT", "SIGBUS", "SIGFPE", "SIGILL", "SIGKILL", "SIGQUIT", "SIGSEGV", "SIGSYS", "SIGTRAP"]

    private struct Header: Decodable { let bug_type: String; let incident_id: UUID; let bundleID: String }
    private struct Body: Decodable {
        struct BundleInfo: Decodable { let CFBundleIdentifier: String; let CFBundleShortVersionString: String; let CFBundleVersion: String }
        struct OS: Decodable { let train: String }
        struct Exception: Decodable { let type: String?; let signal: String? }
        struct Thread: Decodable { let frames: [InputFrame]? }
        struct InputFrame: Decodable { let imageIndex: Int?; let imageOffset: UInt64? }
        struct Image: Decodable { let uuid: String?; let name: String?; let path: String? }
        let bundleInfo: BundleInfo; let procName: String; let captureTime: String; let cpuType: String
        let osVersion: OS; let exception: Exception; let faultingThread: Int
        let threads: [Thread]; let usedImages: [Image]
    }
    public struct Candidate: Sendable {
        public let report: CrashReport
        public let capturedAt: Date // Local consent/retention check only, never uploaded.
    }
    public static func project(_ data: Data, since: Date, now: Date = Date()) -> Candidate? {
        guard data.count <= maximumFileBytes, let newline = data.firstIndex(of: 10) else { return nil }
        let decoder = JSONDecoder()
        guard let header = try? decoder.decode(Header.self, from: data[..<newline]), header.bug_type == "309",
              header.bundleID == "local.sentinel.endpoint",
              let body = try? decoder.decode(Body.self, from: data[data.index(after: newline)...]),
              body.bundleInfo.CFBundleIdentifier == header.bundleID, body.procName == "BoxCop",
              let build = ProductBuild(version: body.bundleInfo.CFBundleShortVersionString, build: body.bundleInfo.CFBundleVersion),
              let raw = try? JSONSerialization.jsonObject(with: data[data.index(after: newline)...]) as? [String: Any],
              !isTrue(raw["isNonFatal"]), !isTrue(raw["isSimulated"]) else { return nil }
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss.SSSS Z"
        guard let captured = formatter.date(from: body.captureTime), captured >= since, captured <= now,
              captured >= now.addingTimeInterval(-7 * 86400),
              ["ARM-64", "X86-64"].contains(body.cpuType),
              body.osVersion.train.hasPrefix("macOS "),
              let os = body.osVersion.train.split(separator: " ").dropFirst().first.map(String.init), ProductBuild.validVersion(os),
              body.threads.indices.contains(body.faultingThread),
              let inputFrames = body.threads[body.faultingThread].frames else { return nil }
        let frames = inputFrames.prefix(64).compactMap { frame -> Frame? in
            guard let index = frame.imageIndex, body.usedImages.indices.contains(index),
                  let offset = frame.imageOffset, offset <= 1 << 40,
                  let uuid = body.usedImages[index].uuid.flatMap(UUID.init(uuidString:)) else { return nil }
            let image = body.usedImages[index]
            let kind = image.name == "BoxCop" ? "app" :
                (image.path?.hasPrefix("/System/Library/") == true || image.path?.hasPrefix("/usr/lib/") == true ? "system" : "other")
            return Frame(image_uuid: uuid, image_offset: offset, image_kind: kind)
        }
        guard !frames.isEmpty else { return nil }
        let exception = body.exception.type ?? "UNKNOWN", signal = body.exception.signal ?? "UNKNOWN"
        return Candidate(report: Self(report_id: header.incident_id, app_version: build.version, app_build: build.build,
            os_version: os, architecture: body.cpuType == "ARM-64" ? "arm64" : "x86_64",
            exception: exceptions.contains(exception) ? exception : "UNKNOWN", signal: signals.contains(signal) ? signal : "UNKNOWN",
            frames: frames), capturedAt: captured)
    }
    private static func isTrue(_ value: Any?) -> Bool { (value as? Bool) == true || (value as? String) == "true" || (value as? String) == "1" }

    public static func candidates(in directories: [URL], state: CrashReportingState, now: Date = Date()) -> [Candidate] {
        guard let since = state.enabledSince else { return [] }
        var result: [UUID: Candidate] = [:]
        for directory in directories {
            guard let files = try? FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil) else { continue }
            for file in files where file.pathExtension == "ips" && file.lastPathComponent.hasPrefix("BoxCop-") {
                guard !Task.isCancelled else { return [] }
                // No symlinks, devices, unbounded reads, raw-report copies or writes to Apple's directories.
                let fd = open(file.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
                guard fd >= 0 else { continue }
                let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
                defer { try? handle.close() }
                var info = stat()
                guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG, info.st_size > 0,
                      info.st_size <= maximumFileBytes,
                      let data = try? handle.read(upToCount: maximumFileBytes + 1),
                      let candidate = project(data, since: since, now: now), state.shouldSend(candidate) else { continue }
                result[candidate.report.report_id] = candidate
                // Keep a bounded oldest-first batch. Remaining OS reports are retried on the next scan.
                if result.count > 10, let newest = result.values.max(by: { $0.capturedAt < $1.capturedAt }) { result[newest.report.report_id] = nil }
            }
        }
        return result.values.sorted { $0.capturedAt < $1.capturedAt }
    }
}

/// Only consent and bounded delivery receipts are persisted. The OS retains the
/// source reports, so offline retries don't need a second sensitive disk queue.
public struct CrashReportingState: Codable, Sendable {
    public private(set) var enabledSince: Date?
    private var delivered: [UUID: Date] = [:]
    public init() {}
    public mutating func setEnabled(_ enabled: Bool, now: Date = Date()) {
        if enabled && enabledSince == nil { enabledSince = now }
        if !enabled { enabledSince = nil; delivered.removeAll() }
    }
    public func shouldSend(_ candidate: CrashReport.Candidate) -> Bool {
        guard let since = enabledSince else { return false }
        return candidate.capturedAt >= since && delivered[candidate.report.report_id] == nil
    }
    public mutating func acknowledge(_ candidate: CrashReport.Candidate, now: Date = Date()) {
        guard shouldSend(candidate) else { return }
        delivered[candidate.report.report_id] = candidate.capturedAt
        prune(now: now)
        if delivered.count > 256 {
            // Advance the lower bound only at this exceptional volume; old reports
            // must never become eligible again after a receipt is evicted.
            let oldest = delivered.values.min()!
            enabledSince = max(enabledSince!, oldest.addingTimeInterval(0.001))
            delivered = delivered.filter { $0.value >= enabledSince! }
        }
    }
    public mutating func prune(now: Date = Date()) {
        delivered = delivered.filter { $0.value >= now.addingTimeInterval(-7 * 86400) }
    }
}
