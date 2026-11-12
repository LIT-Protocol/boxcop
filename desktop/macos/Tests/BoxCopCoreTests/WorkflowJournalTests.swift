import XCTest
@testable import BoxCopCore

final class WorkflowJournalTests: XCTestCase {
    private func directory() throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        return url
    }
    func testJournalSurvivesTimelineClearAndWriterRestart() async throws {
        let dir = try directory(); defer { try? FileManager.default.removeItem(at: dir) }
        let journal = try WorkflowJournal(directory: dir, synthetic: true, encryption: try journalTestCipher())
        var timeline = WorkflowTimeline(capacity: 1)
        timeline.onAppend = { journal.append($0) }
        timeline.append(kind: "browser_copy", collector: "fixture", fields: ["selected_text": WorkflowField("fake")])
        timeline.clear()
        timeline.append(kind: "browser_paste", collector: "fixture", phase: "attempted")
        await journal.flush()
        let next = try WorkflowJournal(directory: dir, synthetic: true, encryption: try journalTestCipher())
        timeline.onAppend = { next.append($0) }
        timeline.append(kind: "browser_file_selected", collector: "fixture")
        await next.flush()
        let files = try FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil).filter { $0.pathExtension == "jsonl" }
        XCTAssertEqual(files.count, 2)
        var rows: [[String: Any]] = []
        for file in files {
            XCTAssertEqual((try FileManager.default.attributesOfItem(atPath: file.path)[.posixPermissions] as? NSNumber)?.intValue, 0o600)
            for line in try String(contentsOf: file).split(separator: "\n") {
                rows.append(try XCTUnwrap(JSONSerialization.jsonObject(with: journalTestCipher().open(Data(line.utf8))) as? [String: Any]))
            }
        }
        XCTAssertEqual(rows.count, 3)
        XCTAssertTrue(rows.allSatisfy { $0["schemaVersion"] as? String == "boxcop.workflow.journal.v1" && $0["synthetic"] as? Bool == true })
        XCTAssertEqual(journal.state().written, 2)
        XCTAssertEqual(next.state().written, 3)
    }
    func testBatchedBurstFlushAndRotationPreserveAllRecords() async throws {
        let dir = try directory(); defer { try? FileManager.default.removeItem(at: dir) }
        let journal = try WorkflowJournal(directory: dir, segmentBytes: 65536, maximumSegments: 64, synthetic: true, maximumPending: 4096, batchSize: 64, encryption: try journalTestCipher())
        var timeline = WorkflowTimeline(capacity: 1); timeline.onAppend = { journal.append($0) }
        for i in 0..<2000 { timeline.append(kind: "file_open", collector: "fixture", fields: ["ordinal": WorkflowField(String(i))]) }
        await journal.flush()
        XCTAssertEqual(journal.state().written, 2000)
        XCTAssertEqual(journal.state().dropped, 0)
        XCTAssertFalse(journal.state().failed)
        let files = try FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil).filter { $0.pathExtension == "jsonl" }.sorted { $0.lastPathComponent < $1.lastPathComponent }
        var ordinals: [String] = []
        for file in files {
            for line in try String(contentsOf: file).split(separator: "\n") {
                let row = try XCTUnwrap(JSONSerialization.jsonObject(with: journalTestCipher().open(Data(line.utf8))) as? [String: Any])
                let event = try XCTUnwrap(row["event"] as? [String: Any])
                let fields = try XCTUnwrap(event["fields"] as? [String: [String: Any]])
                ordinals.append(try XCTUnwrap(fields["ordinal"]?["value"] as? String))
            }
        }
        XCTAssertEqual(ordinals, (0..<2000).map(String.init))
    }
    func testRotationBoundsDiskAndReportsEviction() async throws {
        let dir = try directory(); defer { try? FileManager.default.removeItem(at: dir) }
        let journal = try WorkflowJournal(directory: dir, segmentBytes: 1024, maximumSegments: 2, encryption: try journalTestCipher())
        var timeline = WorkflowTimeline(); timeline.onAppend = { journal.append($0) }
        for _ in 0..<8 { timeline.append(kind: "click", collector: "fixture") }
        await journal.flush()
        let files = try FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil).filter { $0.pathExtension == "jsonl" }
        XCTAssertLessThanOrEqual(files.count, 2)
        for file in files { XCTAssertLessThanOrEqual(try Data(contentsOf: file).count, 1024) }
        XCTAssertEqual(journal.state().written, 8)
        XCTAssertGreaterThan(journal.state().evictedSegments, 0)
        XCTAssertFalse(journal.state().failed)
    }
    func testClockRollbackDoesNotEvictNewActiveSegment() async throws {
        let dir = try directory(); defer { try? FileManager.default.removeItem(at: dir) }
        let future = dir.appendingPathComponent("9999999999.000000-00000000-0000-0000-0000-000000000000.jsonl")
        try Data("old".utf8).write(to: future)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: future.path)
        let journal = try WorkflowJournal(directory: dir, maximumSegments: 1, encryption: try journalTestCipher())
        var timeline = WorkflowTimeline(); timeline.onAppend = { journal.append($0) }
        timeline.append(kind: "click", collector: "fixture")
        await journal.flush()
        XCTAssertFalse(FileManager.default.fileExists(atPath: future.path))
        let files = try FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil).filter { $0.pathExtension == "jsonl" }
        XCTAssertEqual(files.count, 1)
        XCTAssertTrue(try String(decoding: journalTestCipher().open(Data(Data(contentsOf: files[0]).dropLast())), as: UTF8.self).contains("click"))
    }
    func testRejectsSymlinkDirectoryAndReportsOversizedRecord() async throws {
        let dir = try directory(); defer { try? FileManager.default.removeItem(at: dir) }
        let link = dir.appendingPathComponent("link")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: dir)
        XCTAssertThrowsError(try WorkflowJournal(directory: link, encryption: try journalTestCipher()))
        let journal = try WorkflowJournal(directory: dir, segmentBytes: 1024, encryption: try journalTestCipher())
        var timeline = WorkflowTimeline(); timeline.onAppend = { journal.append($0) }
        timeline.append(kind: "context", collector: "fixture", fields: ["text": WorkflowField(String(repeating: "x", count: 4096))])
        await journal.flush()
        XCTAssertEqual(journal.state().dropped, 1); XCTAssertTrue(journal.state().failed)
        XCTAssertEqual(journal.state().written, 0)
    }
}
