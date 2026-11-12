"""Scoped effect evidence must not survive changed installations or claim other tools."""
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path

import pytest

from server.host_agent_verification import binding, evidence_path, record, verification
from server.host_agents import integrations


@pytest.fixture
def evidence(tmp_path):
    home = tmp_path / 'home'; data = home / 'data'
    data.mkdir(parents=True, mode=0o700)
    (home / '.claude').mkdir()
    (home / '.claude/settings.json').write_text('{}')
    app = home / 'BoxCop.app/Contents/MacOS/BoxCop'
    engine = app.parent.parent / 'Resources/engine/boxcop-engine'
    vendor = home / 'bin/claude'
    for path in [app, engine, vendor]:
        path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(b'v1')
    integrations('install', home, data, app)
    report = {'harness': 'claude', 'scenario': 'credential', 'status': 'PASS',
              'checks': {'independent_effect': True}, 'version': '1.0',
              'started_at': datetime.now(timezone.utc).isoformat(),
              'sip': 'System Integrity Protection status: enabled.',
              'qualification_scope': 'scoped_vendor_route',
              'verification_binding': binding('claude', home, app, vendor)}
    record(data, report)
    return home, data, app, vendor, report


def status(evidence, **kwargs):
    home, data, app, _, _ = evidence
    return verification('claude', 'Bash', data, home, app, True, 'callback_observed', **kwargs)['state']


def test_verified_is_separate_from_callback_health_and_other_actions(evidence):
    home, data, app, _, _ = evidence
    actions = integrations('status', home, data, app)['harnesses']['claude']['actions']
    assert actions['Bash']['state'] == 'configured_not_observed'
    assert actions['Bash']['enforcement'] == 'effect_verified'
    assert all(actions[tool]['enforcement'] == 'unverified' for tool in ['Read', 'Write', 'Edit'])


@pytest.mark.parametrize('component', ['vendor', 'app', 'engine', 'configuration'])
def test_same_size_replacement_with_preserved_mtime_invalidates(evidence, component):
    path = Path(evidence[-1]['verification_binding'][component]['path'])
    info = path.stat(); original = path.read_bytes()
    path.write_bytes(b'x' * len(original)); os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns))
    assert status(evidence) == 'invalidated'


def test_vendor_symlink_retarget_even_identical_bytes_invalidates(evidence):
    home, data, app, vendor, report = evidence
    first = home / 'first'; second = home / 'second'
    first.write_bytes(vendor.read_bytes()); second.write_bytes(vendor.read_bytes())
    vendor.unlink(); vendor.symlink_to(first)
    report['verification_binding'] = binding('claude', home, app, vendor); record(data, report)
    assert status(evidence) == 'effect_verified'
    vendor.unlink(); vendor.symlink_to(second)
    assert status(evidence) == 'invalidated'
    vendor.unlink(); vendor.symlink_to(first)
    assert status(evidence) == 'invalidated'


@pytest.mark.parametrize('hours', [-1, 25])
def test_future_and_expired_evidence_cannot_verify(evidence, hours):
    _, data, _, _, report = evidence
    report['started_at'] = (datetime.now(timezone.utc)-timedelta(hours=hours)).isoformat()
    record(data, report)
    assert status(evidence) == 'expired'


def test_failed_rerun_supersedes_pass(evidence):
    _, data, _, _, report = evidence
    report['checks']['independent_effect'] = False
    record(data, report)
    assert status(evidence) == 'failed'


def test_missing_vendor_invalidates(evidence):
    evidence[3].unlink()
    assert status(evidence) == 'invalidated'


@pytest.mark.parametrize('callback', ['callback_error', 'callback_unavailable'])
def test_current_callback_failure_invalidates(evidence, callback):
    home, data, app, _, _ = evidence
    assert verification('claude', 'Bash', data, home, app, True, callback)['state'] == 'invalidated'


def test_removed_registration_invalidates(evidence):
    home, data, app, _, _ = evidence
    actions = integrations('remove', home, data, app)['harnesses']['claude']['actions']
    assert actions['Bash']['enforcement'] == 'invalidated'


@pytest.mark.parametrize('contents', ['{}', '[]', '{', '{"schema":1,"scenario":"unknown"}'])
def test_corrupt_or_legacy_reports_do_not_verify(evidence, contents):
    evidence_path(evidence[1], 'claude', 'Bash').write_text(contents)
    assert status(evidence) == 'unavailable'


def test_symlinked_evidence_is_rejected(evidence):
    path = evidence_path(evidence[1], 'claude', 'Bash')
    target = path.with_suffix('.old'); path.rename(target); path.symlink_to(target)
    assert status(evidence) == 'unavailable'


def test_development_evidence_cannot_be_recorded(evidence):
    _, data, _, _, report = evidence
    report['qualification_scope'] = 'development_only'
    with pytest.raises(ValueError): record(data, report)


def test_native_route_is_not_interchangeable(evidence):
    home, data, app, _, report = evidence
    report['scenario'] = 'native_edit'; record(data, report)
    assert verification('claude', 'Edit', data, home, app, True, 'callback_observed')['state'] == 'effect_verified'
    assert verification('claude', 'Write', data, home, app, True, 'callback_observed')['state'] == 'unverified'
    report['harness'] = 'codex'
    with pytest.raises(ValueError): record(data, report)


def test_restoring_old_config_bytes_does_not_resurrect_verification(evidence):
    path = Path(evidence[-1]['verification_binding']['configuration']['path'])
    original = path.read_bytes()
    path.write_bytes(b'{}')
    assert status(evidence) == 'invalidated'
    path.write_bytes(original)
    assert status(evidence) == 'invalidated'
    report = evidence[-1]
    report['verification_binding'] = binding('claude', evidence[0], evidence[2], evidence[3])
    record(evidence[1], report)
    assert status(evidence) == 'effect_verified'


def test_cursor_runtime_update_invalidates_unchanged_launcher(tmp_path):
    from server.host_agent_verification import vendor_identity
    root = tmp_path / 'runtime'; root.mkdir()
    launcher = root / 'cursor-agent'
    for path in [launcher, root / 'node', root / 'index.js']:
        path.write_bytes(b'original')
    before = vendor_identity('cursor', launcher)
    (root / 'index.js').write_bytes(b'updated')
    assert vendor_identity('cursor', launcher) != before
    (root / 'chunk.js').write_bytes(b'new chunk')
    assert vendor_identity('cursor', launcher) != before


def desktop_evidence(evidence):
    home,data,app,_,report=evidence
    (home/'.cursor').mkdir();(home/'.cursor/hooks.json').write_text('{}')
    vendor=home/'Cursor.app/Contents/MacOS/Cursor'
    for path in [vendor,vendor.parent.parent/'Info.plist',vendor.parent.parent/'_CodeSignature/CodeResources']:
        path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'desktop-v1')
    report.update(harness='cursor',scenario='cursor_native_read',version='3.28.7',
                  verification_binding=binding('cursor',home,app,vendor,'cursor_desktop'))
    record(data,report)
    return vendor


def test_desktop_effects_do_not_verify_tab_or_cli(evidence):
    home,data,app,_,_=evidence;desktop_evidence(evidence)
    row=verification('cursor','beforeReadFile',data,home,app,True,'callback_observed')
    assert row['state']=='effect_verified' and row['vendor_kind']=='cursor_desktop'
    for tool in ['beforeShellExecution','beforeTabFileRead']:
        assert verification('cursor',tool,data,home,app,True,'callback_observed')['state']=='unverified'


@pytest.mark.parametrize('change',['seal','info','imported_hooks','settings_created'])
def test_desktop_update_or_import_settings_change_invalidates(evidence,change):
    home,data,app,_,_=evidence;vendor=desktop_evidence(evidence)
    path={'seal':vendor.parent.parent/'_CodeSignature/CodeResources',
          'info':vendor.parent.parent/'Info.plist',
          'imported_hooks':home/'.claude/settings.json',
          'settings_created':home/'Library/Application Support/Cursor/User/settings.json'}[change]
    path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'changed')
    assert verification('cursor','beforeReadFile',data,home,app,True,'callback_observed')['state']=='invalidated'


def test_desktop_recording_rejects_cli_binding(evidence):
    _,data,_,_,report=evidence
    report.update(harness='cursor',scenario='cursor_tab_read')
    with pytest.raises(ValueError,match='CLI binding'):record(data,report)
