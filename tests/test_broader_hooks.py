"""Real hook subprocess contracts; no operator configuration or vendor sessions."""
import json
import sqlite3

import pytest

from server.host_agents import CURSOR_READ_EVENTS, integrations
from test_host_agents import call, layout


def read_payload(home, event, path='notes.txt', content='Public notes', **extra):
    return {'hook_event_name': event, 'file_path': str(home / path),
            'content': content, 'conversation_id': 'fixture', **extra}


@pytest.mark.parametrize('event', CURSOR_READ_EVENTS)
@pytest.mark.parametrize('path,content,allowed', [
    ('.aws/credentials', 'synthetic file bytes 7913', False),
    ('.env', 'synthetic file bytes 7913', False),
    ('notes.txt', 'password=synthetic-private-value', False),
    ('.env.example', 'EXAMPLE=public', True),
    ('.ssh/id_ed25519.pub', 'public fixture', True),
    ('notes.txt', 'Public notes', True),
])
def test_cursor_file_policy_and_audit(layout, event, path, content, allowed):
    home, data, _ = layout
    result = call('cursor', data, json.dumps(read_payload(home, event, path, content)))
    assert result.returncode == 0
    answer = json.loads(result.stdout)
    assert answer['permission'] == ('allow' if allowed else 'deny')
    assert content not in result.stdout
    with sqlite3.connect(data / 'events.sqlite3') as db:
        raw = db.execute('select record from events').fetchone()[0]
    record = json.loads(raw)
    assert record['event']['action'] == 'read'
    assert record['event']['content'] == '[not retained]'
    assert content not in raw


@pytest.mark.parametrize('event', CURSOR_READ_EVENTS)
@pytest.mark.parametrize('updates', [
    {'file_path': 'relative.txt'}, {'file_path': '~/notes.txt'}, {'file_path': ''}, {'content': None},
    {'content': 'x' * 20001}, {'attachments': [{}]},
    {'attachments': [{'type': 'file', 'file_path': 'relative'}]},
    {'hook_event_name': 'afterFileEdit', 'command': 'printf harmless'},
])
def test_invalid_read_never_falls_through_to_shell(layout, event, updates):
    home, data, _ = layout
    payload = {**read_payload(home, event), **updates}
    assert json.loads(call('cursor', data, json.dumps(payload)).stdout)['permission'] == 'deny'


@pytest.mark.parametrize('harness', ['claude', 'cursor'])
@pytest.mark.parametrize('reverse', [False, True])
def test_sensitive_symlink_in_either_direction(layout, harness, reverse):
    home, data, _ = layout
    (home / '.aws').mkdir()
    sensitive, plain = home / '.aws/credentials', home / 'notes.txt'
    target, alias = (plain, sensitive) if reverse else (sensitive, plain)
    target.write_text('fixture')
    alias.symlink_to(target)
    payload = read_payload(home, 'beforeReadFile', str(alias))
    if harness == 'claude':
        payload = {'hook_event_name': 'PreToolUse', 'tool_name': 'Read',
                   'tool_input': {'file_path': str(alias)}, 'cwd': str(home)}
    answer = json.loads(call(harness, data, json.dumps(payload)).stdout)
    assert answer['permission'] == 'deny' if harness == 'cursor' else answer['hookSpecificOutput']['permissionDecision'] == 'deny'


def test_attached_credential_is_held(layout):
    home, data, _ = layout
    payload = read_payload(home, 'beforeReadFile', attachments=[
        {'type': 'rule', 'file_path': str(home / '.aws/credentials')}])
    assert json.loads(call('cursor', data, json.dumps(payload)).stdout)['permission'] == 'deny'


def test_upgrade_relocation_remove_and_partial_status(layout):
    home, data, app = layout
    path = home / '.cursor/hooks.json'
    command = f'{app} --host-agent-hook cursor'
    other = {'command': 'other-security-hook', 'failClosed': True}
    path.write_text(json.dumps({'version': 1, 'hooks': {
        'beforeShellExecution': [{'command': command}],
        'beforeReadFile': [other], 'afterFileEdit': [{'command': 'formatter'}]}}))
    assert integrations('status', *layout)['harnesses']['cursor']['state'] == 'not_configured'
    integrations('install', *layout)
    first = path.read_bytes()
    integrations('install', *layout)
    assert path.read_bytes() == first
    config = json.loads(first)
    for event in ('beforeShellExecution', *CURSOR_READ_EVENTS):
        assert config['hooks'][event][-1]['failClosed'] is True
    config['hooks']['beforeTabFileRead'] = []
    path.write_text(json.dumps(config))
    status = integrations('status', *layout)['harnesses']['cursor']
    assert status['state'] == 'not_configured'
    assert not status['registered_events']['beforeTabFileRead']
    integrations('install', home, data, app.parent / 'Moved BoxCop')
    integrations('remove', home, data, app.parent / 'Moved BoxCop')
    hooks = json.loads(path.read_text())['hooks']
    assert hooks['beforeReadFile'] == [other]
    assert hooks['beforeShellExecution'] == hooks['beforeTabFileRead'] == []
    assert hooks['afterFileEdit'] == [{'command': 'formatter'}]


def test_malformed_new_hook_does_not_partially_install(layout):
    home, _, _ = layout
    path = home / '.cursor/hooks.json'
    original = json.dumps({'hooks': {'beforeReadFile': 'invalid'}})
    path.write_text(original)
    assert integrations('install', *layout)['harnesses']['cursor']['state'] == 'configuration_conflict'
    assert path.read_text() == original


def test_status_detects_narrowed_matcher_and_disabled_failure_policy(layout):
    home, _, _ = layout
    integrations('install', *layout)
    claude = home / '.claude/settings.json'
    config = json.loads(claude.read_text())
    config['hooks']['PreToolUse'][0]['matcher'] = '^Bash$'
    claude.write_text(json.dumps(config))
    cursor = home / '.cursor/hooks.json'
    config = json.loads(cursor.read_text())
    config['hooks']['beforeReadFile'][0]['failClosed'] = False
    cursor.write_text(json.dumps(config))
    status = integrations('status', *layout)['harnesses']
    assert status['claude']['state'] == status['cursor']['state'] == 'not_configured'
