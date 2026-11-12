"""P01 per-action health through real hook subprocesses and isolated vendor configs.

These tests establish callback diagnostics, not installed-vendor enforcement.
"""
from datetime import datetime, timedelta, timezone
import json

import pytest

from server.host_agents import ACTIONS, CONFIGS, integrations
from test_host_agents import call, layout, payload


def action_payload(harness, tool, home, sensitive=False):
    path = home / ('.aws/credentials' if sensitive else 'public.txt')
    if tool in {'Bash', 'beforeShellExecution'}:
        return payload(harness, 'cat .aws/credentials' if sensitive else 'printf harmless')
    if harness == 'cursor':
        return json.dumps({'hook_event_name': tool, 'file_path': str(path),
                           'content': 'public fixture', 'conversation_id': 'health-test'})
    fields = {'file_path': str(path), 'content': 'public fixture', 'new_string': 'public fixture'}
    return json.dumps({'hook_event_name': 'PreToolUse', 'tool_name': tool,
                       'tool_input': fields, 'cwd': str(home), 'session_id': 'health-test'})


CASES = [(harness, tool) for harness, tools in ACTIONS.items() for tool in tools]


@pytest.mark.parametrize('harness,tool', CASES)
def test_each_callback_only_observes_its_reported_action(layout, harness, tool):
    home, data, _ = layout
    integrations('install', *layout)
    for sensitive in (False, True):
        result = call(harness, data, action_payload(harness, tool, home, sensitive))
        assert result.returncode == 0
        answer = json.loads(result.stdout)
        if harness == 'cursor':
            assert answer['permission'] == ('deny' if sensitive else 'allow')
        else:
            assert (answer == {}) is (not sensitive)
        row = integrations('status', *layout)['harnesses'][harness]
        assert row['state'] == 'callback_observed'
        assert set(row['actions']) == set(ACTIONS[harness])
        for key, detail in row['actions'].items():
            assert detail['state'] == ('callback_observed' if key == tool else 'configured_not_observed')
            assert detail['enforcement'] == 'unverified'
        receipt = row['actions'][tool]['last_callback']
        assert receipt['tool'] == tool
        assert (receipt['decision'] == 'allow') is (not sensitive)
        raw = (data / f'{harness}-{tool}-receipt.json').read_text()
        assert 'public fixture' not in raw and '.aws/credentials' not in raw and str(home) not in raw


def test_legacy_receipt_never_populates_action_evidence(layout):
    _, data, _ = layout
    integrations('install', *layout)
    (data / 'claude-receipt.json').write_text(json.dumps({
        'schema_version': 1, 'harness': 'claude', 'state': 'observed',
        'at': datetime.now(timezone.utc).isoformat(), 'decision': 'allow'}))
    row = integrations('status', *layout)['harnesses']['claude']
    assert row['state'] == 'callback_observed'
    assert all(r['last_callback'] is None and r['state'] == 'configured_not_observed'
               for r in row['actions'].values())


def test_read_error_is_not_hidden_by_later_successful_shell_callback(layout):
    home, data, _ = layout
    integrations('install', *layout)
    bad = {'hook_event_name': 'beforeReadFile', 'file_path': 'relative', 'content': 'public'}
    assert json.loads(call('cursor', data, json.dumps(bad)).stdout)['permission'] == 'deny'
    call('cursor', data, payload('cursor', 'printf harmless'))
    row = integrations('status', *layout)['harnesses']['cursor']
    assert row['state'] == 'callback_observed'
    assert row['actions']['beforeReadFile']['state'] == 'callback_error'
    assert row['actions']['beforeShellExecution']['state'] == 'callback_observed'
    assert row['actions']['beforeTabFileRead']['state'] == 'configured_not_observed'


@pytest.mark.parametrize('harness,tool', CASES)
def test_configuration_change_and_repair_require_new_action_evidence(layout, harness, tool):
    home, data, _ = layout
    integrations('install', *layout)
    call(harness, data, action_payload(harness, tool, home))
    path = home / CONFIGS[harness]
    path.write_text('{}')
    assert integrations('status', *layout)['harnesses'][harness]['actions'][tool]['state'] == 'not_configured'
    repaired = integrations('install', *layout)['harnesses'][harness]
    assert repaired['actions'][tool]['state'] == 'callback_before_configuration'
    call(harness, data, action_payload(harness, tool, home))
    assert integrations('status', *layout)['harnesses'][harness]['actions'][tool]['state'] == 'callback_observed'


@pytest.mark.parametrize('age', [timedelta(days=2), timedelta(days=-1)])
def test_action_freshness_is_independent_of_harness_callback(layout, age):
    home, data, _ = layout
    integrations('install', *layout)
    call('claude', data, action_payload('claude', 'Read', home))
    path = data / 'claude-Read-receipt.json'
    receipt = json.loads(path.read_text())
    receipt['at'] = (datetime.now(timezone.utc) - age).isoformat()
    path.write_text(json.dumps(receipt))
    call('claude', data, payload('claude', 'printf harmless'))
    row = integrations('status', *layout)['harnesses']['claude']
    assert row['state'] == 'callback_observed'
    assert row['actions']['Read']['state'] == 'callback_stale'
    assert row['actions']['Bash']['state'] == 'callback_observed'


@pytest.mark.parametrize('damage', ['json', 'identity', 'symlink'])
def test_unreadable_action_receipt_does_not_mask_other_diagnostics_or_edit_config(layout, damage):
    home, data, _ = layout
    integrations('install', *layout)
    call('claude', data, action_payload('claude', 'Read', home))
    path = data / 'claude-Read-receipt.json'
    if damage == 'json':
        path.write_text('{')
    elif damage == 'identity':
        receipt = json.loads(path.read_text()); receipt['tool'] = 'Bash'
        path.write_text(json.dumps(receipt))
    else:
        path.unlink(); path.symlink_to(data / 'claude-receipt.json')
    config = home / CONFIGS['claude']; before = config.read_bytes()
    row = integrations('status', *layout)['harnesses']['claude']
    assert row['actions']['Read']['state'] == 'callback_unavailable'
    assert row['actions']['Read']['last_callback'] is None
    assert row['actions']['Bash']['state'] == 'configured_not_observed'
    assert config.read_bytes() == before


def test_unsupported_action_cannot_create_receipt_paths(layout):
    _, data, _ = layout
    integrations('install', *layout)
    for tool in ('../untrusted', 'mcp__some_tool', ['Read']):
        raw = json.dumps({'hook_event_name': 'PreToolUse', 'tool_name': tool, 'tool_input': {}})
        result = call('claude', data, raw)
        assert json.loads(result.stdout)['hookSpecificOutput']['permissionDecision'] == 'deny'
    assert sorted(p.name for p in data.glob('*receipt.json')) == ['claude-receipt.json']
    row = integrations('status', *layout)['harnesses']['claude']
    assert row['state'] == 'callback_error'
    assert all(r['last_callback'] is None for r in row['actions'].values())


def test_partial_registration_preserves_independent_shell_observation(layout):
    home, data, _ = layout
    integrations('install', *layout)
    path = home / CONFIGS['cursor']
    config = json.loads(path.read_text()); del config['hooks']['beforeReadFile']
    path.write_text(json.dumps(config))
    call('cursor', data, payload('cursor', 'printf harmless'))
    row = integrations('status', *layout)['harnesses']['cursor']
    assert row['state'] == 'not_configured'
    assert row['actions']['beforeShellExecution']['state'] == 'callback_observed'
    assert row['actions']['beforeReadFile']['state'] == 'not_configured'
    assert not row['actions']['beforeReadFile']['registered']


def test_corrupt_aggregate_receipt_keeps_registration_and_action_evidence(layout):
    home, data, _ = layout
    integrations('install', *layout)
    call('claude', data, action_payload('claude', 'Read', home))
    (data / 'claude-receipt.json').write_text('{')
    row = integrations('status', *layout)['harnesses']['claude']
    assert row['state'] == 'callback_unavailable'
    assert row['registered_events']['PreToolUse']
    assert row['actions']['Read']['state'] == 'callback_observed'


@pytest.mark.parametrize('harness,tool', [(h, t) for h, t in CASES if h != 'cursor'])
def test_disabled_vendor_does_not_reuse_action_evidence(layout, harness, tool):
    home, data, _ = layout
    integrations('install', *layout)
    call(harness, data, action_payload(harness, tool, home))
    path = home / CONFIGS[harness]
    config = json.loads(path.read_text()); config['disableAllHooks'] = True
    path.write_text(json.dumps(config))
    row = integrations('status', *layout)['harnesses'][harness]
    assert row['state'] == 'disabled_by_harness'
    assert all(not r['registered'] and r['state'] == 'disabled_by_harness' for r in row['actions'].values())


@pytest.mark.parametrize('harness,tool', CASES)
def test_audit_outage_records_action_error_and_recovery(layout, harness, tool):
    import sqlite3
    home, data, _ = layout
    integrations('install', *layout)
    raw = action_payload(harness, tool, home)
    call(harness, data, raw)
    with sqlite3.connect(data / 'events.sqlite3') as db:
        db.execute('BEGIN IMMEDIATE')
        response = json.loads(call(harness, data, raw).stdout)
        if harness == 'cursor':
            assert response['permission'] == 'deny'
        else:
            assert response['hookSpecificOutput']['permissionDecision'] == 'deny'
        detail = integrations('status', *layout)['harnesses'][harness]['actions'][tool]
        assert detail['state'] == 'callback_error'
        assert detail['last_callback']['decision'] == 'deny'
    call(harness, data, raw)
    detail = integrations('status', *layout)['harnesses'][harness]['actions'][tool]
    assert detail['state'] == 'callback_observed'
    assert detail['last_callback']['decision'] == 'allow'
    assert detail['enforcement'] == 'unverified'


@pytest.mark.parametrize('mode', ['status', 'auto', 'install'])
def test_cursor_disable_flag_does_not_claim_hooks_stopped_or_rewrite_settings(layout, mode):
    home, data, _ = layout
    integrations('install', *layout)
    path = home / CONFIGS['cursor']
    config = json.loads(path.read_text()); config['disableAllHooks'] = True
    path.write_text(json.dumps(config)); original = path.read_bytes()
    call('cursor', data, payload('cursor', 'printf harmless'))
    row = integrations(mode, *layout)['harnesses']['cursor']
    assert row['state'] == 'disable_setting_unverified'
    assert 'Remove BoxCop' in row['next_step']
    assert row['actions']['beforeShellExecution']['state'] == 'callback_observed'
    assert all(row['registered_events'].values())
    assert path.read_bytes() == original


@pytest.mark.parametrize('harness', CONFIGS)
def test_explicit_removal_works_even_when_disable_flag_is_set(layout, harness):
    home, _, _ = layout
    integrations('install', *layout)
    path = home / CONFIGS[harness]
    config = json.loads(path.read_text()); config['disableAllHooks'] = True
    config['unrelated'] = 'preserved'
    path.write_text(json.dumps(config))
    row = integrations('remove', *layout)['harnesses'][harness]
    assert row['state'] == 'not_configured'
    assert not any(row['registered_events'].values())
    after = json.loads(path.read_text())
    assert after['disableAllHooks'] is True and after['unrelated'] == 'preserved'
    assert integrations('auto', *layout)['disabled'] is True


def test_supervisor_failure_invalidates_older_actions_until_fresh_callbacks(layout):
    home, data, _ = layout
    integrations('install', *layout)
    call('claude', data, action_payload('claude', 'Bash', home))
    call('claude', data, action_payload('claude', 'Read', home))
    failure = {'schema_version': 1, 'harness': 'claude', 'state': 'error',
               'source': 'native_supervisor', 'at': datetime.now(timezone.utc).isoformat()}
    (data / 'claude-supervisor-receipt.json').write_text(json.dumps(failure))
    actions = integrations('status', *layout)['harnesses']['claude']['actions']
    assert all(row['state'] == 'callback_error' for row in actions.values())
    call('claude', data, action_payload('claude', 'Bash', home))
    actions = integrations('status', *layout)['harnesses']['claude']['actions']
    assert actions['Bash']['state'] == 'callback_observed'
    assert actions['Read']['state'] == 'callback_error'


def test_cursor_imported_claude_read_is_evaluated_without_claiming_native_callback(layout):
    home, data, _ = layout
    integrations('install', *layout)
    for sensitive in [False, True]:
        raw = json.dumps({'hook_event_name': 'preToolUse', 'cursor_version': '3.28.7',
                          'workspace_roots': [str(home)], 'conversation_id': 'cursor-desktop',
                          'tool_name': 'Read', 'tool_input': {'file_path': str(home/('.aws/credentials' if sensitive else 'public.txt'))}})
        result = call('claude', data, raw)
        reply = json.loads(result.stdout)
        assert (reply == {}) is (not sensitive)
        if sensitive: assert reply['hookSpecificOutput']['permissionDecision'] == 'deny'
    row = integrations('status', *layout)
    assert row['harnesses']['cursor']['state'] == 'callback_observed'
    assert all(r['state']=='configured_not_observed' for r in row['harnesses']['cursor']['actions'].values())
    assert all(r['state']=='configured_not_observed' for r in row['harnesses']['claude']['actions'].values())
    assert not (data/'claude-receipt.json').exists()


@pytest.mark.parametrize('fault', ['no_version','relative_root','ambiguous_roots','unknown_tool'])
def test_cursor_imported_unknown_shape_stays_denied(layout, fault):
    home,data,_=layout
    raw={'hook_event_name':'preToolUse','cursor_version':'3.28.7','workspace_roots':[str(home)],
         'tool_name':'Read','tool_input':{'file_path':str(home/'public.txt')}}
    if fault=='no_version':del raw['cursor_version']
    elif fault=='relative_root':raw['workspace_roots']=['relative']
    elif fault=='ambiguous_roots':raw['workspace_roots']=[str(home),'/other']
    else:raw['tool_name']='Unknown'
    reply=json.loads(call('claude',data,json.dumps(raw)).stdout)
    assert reply['hookSpecificOutput']['permissionDecision']=='deny'


@pytest.mark.parametrize('tool, fields', [
    ('Shell', {'command': 'cat .aws/credentials'}),
    ('Write', {'file_path': '.aws/credentials', 'content': 'synthetic'}),
    ('Edit', {'file_path': '.aws/credentials', 'old_string': 'old', 'new_string': 'synthetic'}),
])
def test_cursor_imported_risky_shell_and_mutations_remain_denied(layout, tool, fields):
    home, data, _ = layout
    raw = {'hook_event_name': 'preToolUse', 'cursor_version': '3.28.7',
           'workspace_roots': [str(home)], 'tool_name': tool, 'tool_input': fields}
    reply = json.loads(call('claude', data, json.dumps(raw)).stdout)
    assert reply['hookSpecificOutput']['permissionDecision'] == 'deny'
    receipt = json.loads((data/'cursor-receipt.json').read_text())
    assert receipt['state'] == 'observed' and receipt.get('tool') is None
