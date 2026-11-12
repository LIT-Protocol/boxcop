import XCTest
@testable import BoxCopCore

final class AgentActionDetailsTests: XCTestCase {
    private let input = #"{"cwd": "/Users/me/.t3/worktrees/BoxCop/t3-280416ab", "hook_event_name": "PreToolUse", "session_id": "337f02ec-dda2-48bb-9a7a-8b47e1b2fb8d", "tool_input": {"command": "ssh lab 'mkdir -p ~/pr135 && cat > ~/pr135/probe.command <<\"EOF\"\n#!/bin/zsh\ncd /tmp\nEOF\n'; rm -f ~/pr135/probe.log", "dangerouslyDisableSandbox": true, "description": "Run Claude in guest GUI session via open", "timeout": 120000, "run_in_background": false}, "tool_name": "Bash"}"#

    func testReadsHeldClaudeBashRequest() {
        let details = AgentActionDetails(application: "claude", command: "fallback", input: input)
        XCTAssertEqual(details.agent, "Claude Code")
        XCTAssertEqual(details.tool, "Bash")
        XCTAssertEqual(details.agentDescription, "Run Claude in guest GUI session via open")
        XCTAssertTrue(details.sandboxDisabled)
        XCTAssertEqual(details.timeoutSeconds, 120)
        XCTAssertEqual(details.shortSessionID, "337f02ec")
        XCTAssertEqual(details.displayPath(home: "/Users/me"), "~/.t3/worktrees/BoxCop/t3-280416ab")
        // Escapes are decoded so heredocs read as the lines they are.
        XCTAssertTrue(details.command!.contains("#!/bin/zsh\ncd /tmp\n"))
        XCTAssertEqual(details.otherArguments, [.init(name: "run_in_background", value: "false")])
        XCTAssertTrue(details.rawJSON.range(of: #""dangerouslyDisableSandbox"\s*:\s*true"#, options: .regularExpression) != nil)
    }

    func testIntegerArgumentsAreNotRenderedAsBooleans() {
        let input = #"{"tool_input": {"command": "ls", "flag": true, "count": 1, "zero": 0}, "tool_name": "Bash"}"#
        let details = AgentActionDetails(application: "claude", command: "", input: input)
        XCTAssertEqual(details.otherArguments, [.init(name: "count", value: "1"), .init(name: "flag", value: "true"), .init(name: "zero", value: "0")])
    }

    func testFallsBackWhenInputIsNotJSON() {
        let details = AgentActionDetails(application: "codex", command: "rm -rf build", input: "not json")
        XCTAssertEqual(details.agent, "Codex")
        XCTAssertEqual(details.command, "rm -rf build")
        XCTAssertEqual(details.rawJSON, "not json")
        XCTAssertFalse(details.sandboxDisabled)
        XCTAssertNil(details.displayPath())
    }

    func testNotificationCopyNeverIncludesCommandContent() {
        XCTAssertEqual(AgentApprovalCopy.title(application: "claude"), "Claude Code is waiting for your approval")
        let body = AgentApprovalCopy.body(reasons: ["Review destructive actions"])
        XCTAssertEqual(body, "Destructive action was held for review. Open BoxCop to approve or reject it.")
        let id = "6c1f0c58-0000-4000-8000-000000000000"
        XCTAssertEqual(AgentApprovalCopy.requestID(notificationIdentifier: AgentApprovalCopy.notificationIdentifier(id)), id)
        XCTAssertNil(AgentApprovalCopy.requestID(notificationIdentifier: "boxcop-review-x"))
    }
}
