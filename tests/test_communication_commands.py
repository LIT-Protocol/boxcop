"""Regression fixtures are inspected as text; no messages are sent."""
import pytest

from server.human_review import DEFAULT_POLICIES, gate, reasons, state
from server.host_agents import normalize


LOOKUP = "command -v gog; command -v gws; rg --files -g AGENTS.md -g '*mail*' -g '*gmail*' -g '*email*' -g '!node_modules' -g '!vendor' ."
SEND = "NODE_PATH=/tmp/dependencies TS_NODE_TRANSPILE_ONLY=true node -r ts-node/register -e 'const { gmailClient } = require(\"./lib/gmail\"); (async () => { const gmail = gmailClient(); await gmail.users.messages.send({userId: \"me\", requestBody: {raw: \"fixture\"}}); })();'"


def event(command):
    payload = {'hook_event_name': 'PreToolUse', 'tool_name': 'Bash',
               'tool_input': {'command': command}, 'cwd': '/tmp', 'session_id': 'test'}
    return normalize('codex', payload), payload


@pytest.mark.parametrize('command', [
    LOOKUP,
    "cat scripts/vesting/mail-test.ts scripts/vesting/lib/gmail.ts scripts/vesting/lib/mail.ts package.json",
    "rg -n 'gog|gws|sendmail|smtp|external_communication' server/human_review.py",
    "grep -niE 'mail|sendmail|smtp' source.py",
    "printf '%s' 'mail someone@example.test'",
    "echo 'gog gmail send'; echo smtp://example.test",
    "printf '%s' ';' mail",
    "printf '%s' '\n' mail",
    'command -v mail', 'command -V sendmail', 'command -pv mail',
    'which mail', 'type sendmail', 'env command -v mail',
    'gog gmail list; echo send', 'gws gmail users messages list',
    'gog gmail list --query send', 'gws gmail users messages list --query send',
    'true # mail someone@example.test',
    'cat > mail', 'cat < mail',
    'node script.js --eval "gmail.users.messages.send({})"',
    'node -- -e "gmail.users.messages.send({})"',
    "node -e 'console.log(\"gmail.users.messages.send({})\")'",
    "node -e '// gmail.users.messages.send({})'",
    "node -e '/* gmail.users.messages.send({}) */ console.log(1)'",
    "node -e 'gmail.users.messages.list({userId: \"me\"})'",
    'echo "node -e \'gmail.users.messages.send({})\'"',
    "sh -c 'command -v mail; printf hello'",
])
def test_non_sends_do_not_request_review(command):
    assert reasons(event(command)[0], {**DEFAULT_POLICIES, 'external': True}) == []


@pytest.mark.parametrize('command', [
    SEND,
    'mail someone@example.test', '/usr/sbin/sendmail -t',
    'printf body | mailx someone@example.test',
    'true && mail someone@example.test', 'false || mail someone@example.test',
    'pwd; mail someone@example.test', 'pwd\nmail someone@example.test',
    'env CONFIG=value /usr/bin/mail someone@example.test',
    'sudo -u example /usr/bin/mail someone@example.test',
    'command -- mail someone@example.test', 'command -p mail someone@example.test',
    'exec mail someone@example.test',
    'gog gmail send --to someone@example.test', 'gws gmail +send --to someone@example.test',
    'gog --account example@example.test gmail send --to someone@example.test',
    'gws gmail users messages send --json "{}"',
    'curl --url smtp://example.test --upload-file message.txt',
    'curl --url=smtps://example.test --upload-file message.txt',
    "sh -lc 'mail someone@example.test'",
    "node -e 'gmail.users.messages.send({})'",
    "node --eval='gmail.users.drafts.send({})'",
    "node -p 'gmail.users.messages.send({})'",
    "node -r ts-node/register --eval 'gmail.users . messages . send ({})'",
    "node -e '/* comment */ gmail.users.messages.send({})'",
    "if true; then mail someone@example.test; fi",
    '> output.txt mail someone@example.test',
])
def test_outbound_commands_require_review(command):
    assert reasons(event(command)[0], {**DEFAULT_POLICIES, 'external': True}) == ['Review external communications']
    assert reasons(event(command)[0], DEFAULT_POLICIES) == []


def test_lookup_creates_no_request_but_sdk_send_does(tmp_path):
    with state(tmp_path) as value:
        value['policies']['external'] = True
    assert gate(tmp_path, *event(LOOKUP))[0]
    with state(tmp_path) as value:
        assert not value['requests']
    assert not gate(tmp_path, *event(SEND))[0]
    with state(tmp_path) as value:
        request, = value['requests']
        assert request['status'] == 'pending'
        assert request['command'] == SEND
