import json
from pathlib import Path
from unittest.mock import patch

import pytest

from server import software_remediation as fix
from server.exposure_advisories import findings


def record(name='node', version='26.0.0', path=None, kind='package_metadata'):
    path = path or f'/opt/homebrew/Cellar/{name}/{version}/INSTALL_RECEIPT.json'
    return dict(id=fix.digest(path)[:24], name=name, version=version, path=path,
                kind=kind, advisories=findings(name, version), metadata_sha256='original',
                identity={'inode': 1})


def report(*records, incomplete=False):
    return dict(records=list(records), incomplete=incomplete)


def brew_info(target='26.12.1'):
    return dict(formulae=[dict(name='node', tap='homebrew/core', pinned=False,
                              linked_keg='26.0.0', versions={'stable': target})])


def brew_run(argv, **kwargs):
    if 'info' in argv:
        return json.dumps(brew_info())
    return 'Would upgrade node and dependency example'


def test_group_directory_and_receipt_but_keep_separate_managers():
    receipt = record()
    directory = record(path='/opt/homebrew/Cellar/node/26.0.0', kind='version_directory_hint')
    nvm = record(version='24.1.0', path=str(Path.home() / '.nvm/versions/node/v24.1.0'), kind='version_directory_hint')
    items = fix.items(report(receipt, directory, nvm))
    assert len(items) == 2
    brew = next(i for i in items if i['adapter'] == 'homebrew')
    assert set(brew['observation_ids']) == {receipt['id'], directory['id']}
    assert next(i for i in items if i['adapter'] == 'review')['detail'].startswith('Migration needed')


def test_unverified_and_hints_cannot_be_automatically_updated():
    hint = record(kind='version_directory_hint', path='/opt/homebrew/Cellar/node/26.0.0')
    unknown = record(version='20.1.0')
    assert all(i['adapter'] == 'review' for i in fix.items(report(hint, unknown)))


def test_unrelated_paths_and_formula_names_are_not_commands():
    malicious = record(path='/tmp/Cellar/node/26.0.0/INSTALL_RECEIPT.json')
    assert fix.items(report(malicious))[0]['adapter'] == 'review'
    malicious['name'] = 'node; touch /tmp/pwned'
    assert fix.items(report(malicious))[0]['adapter'] == 'review'


@patch.object(fix, 'checked_executable', return_value='/opt/homebrew/bin/brew')
@patch.object(fix, 'run', side_effect=brew_run)
def test_preview_has_target_impact_and_stable_fingerprint(run, executable):
    source = report(record())
    item = fix.items(source)[0]
    plan = fix.prepare(item, source)
    assert plan['ready'] and plan['target'] == '26.12.1'
    assert 'dependency example' in plan['impact']
    assert plan['fingerprint'] == fix.prepare(item, source)['fingerprint']
    source['records'][0]['metadata_sha256'] = 'changed'
    assert plan['fingerprint'] != fix.prepare(item, source)['fingerprint']
    assert all('upgrade' not in c.args[0] or '--dry-run' in c.args[0] for c in run.call_args_list)


@pytest.mark.parametrize('target', ['27.0.0', '26.0.0', 'unknown'])
@patch.object(fix, 'checked_executable', return_value='/opt/homebrew/bin/brew')
def test_no_unverified_or_major_runtime_upgrade(executable, target):
    source = report(record())
    with patch.object(fix, 'run', return_value=json.dumps(brew_info(target))):
        assert not fix.prepare(fix.items(source)[0], source)['ready']


@patch.object(fix, 'run')
def test_incomplete_scan_does_not_execute_manager(run):
    source = report(record(), incomplete=True)
    assert not fix.prepare(fix.items(source)[0], source)['ready']
    run.assert_not_called()


@patch.object(fix, 'checked_executable', return_value='/opt/homebrew/bin/brew')
@patch.object(fix, 'run', side_effect=brew_run)
def test_stale_approval_cannot_mutate(run, executable):
    source = report(record())
    result = fix.apply(fix.items(source)[0]['id'], '0' * 64, scan=lambda: source)
    assert result['status'] == 'needs_review'
    assert all('upgrade' not in c.args[0] or '--dry-run' in c.args[0] for c in run.call_args_list)


@pytest.mark.parametrize('after, expected', [
    (report(record(version='26.12.1')), 'restart_needed'),
    (report(record()), 'unverified'),
    (report(), 'unverified'),
    (report(record(version='26.12.1'), incomplete=True), 'unverified'),
    (report(record(), record(version='26.12.1')), 'cleanup_needed'),
])
@patch.object(fix, 'checked_executable', return_value='/opt/homebrew/bin/brew')
@patch.object(fix, 'run', side_effect=brew_run)
def test_success_requires_positive_complete_rescan(run, executable, after, expected):
    before = report(record())
    item = fix.items(before)[0]
    plan = fix.prepare(item, before)
    scans = iter([before, after])
    result = fix.apply(item['id'], plan['fingerprint'], scan=lambda: next(scans))
    assert result['status'] == expected
    assert sum(c.args[0] == ['/opt/homebrew/bin/brew', 'upgrade', '--formula', 'node'] for c in run.call_args_list) == 1


@patch.object(fix, 'checked_executable', return_value='/opt/homebrew/bin/brew')
def test_failed_update_never_reports_fixed(executable):
    source = report(record())
    item = fix.items(source)[0]
    with patch.object(fix, 'run', side_effect=brew_run):
        plan = fix.prepare(item, source)
    def fail(argv, **kwargs):
        if 'upgrade' in argv and '--dry-run' not in argv:
            raise fix.UpdateError('Failed to install')
        return brew_run(argv)
    with patch.object(fix, 'run', side_effect=fail):
        assert fix.apply(item['id'], plan['fingerprint'], scan=lambda: source)['status'] == 'failed'


def pillow_record():
    return record('pillow', '12.2.0', str(Path.home() / '.pyenv/versions/3.12.4/lib/python3.12/site-packages/pillow-12.2.0.dist-info/METADATA'))


def pillow_run(argv, **kwargs):
    if '--report' in argv:
        Path(argv[argv.index('--report') + 1]).write_text(json.dumps({'install': [dict(
            metadata={'name': 'Pillow', 'version': '13.0.0'},
            download_info={'url': 'https://files.pythonhosted.org/packages/pillow.whl',
                           'archive_info': {'hashes': {'sha256': 'a' * 64}}})]}))
    return '[]' if '-c' in argv else ''


@patch.object(fix, 'checked_executable', return_value='/trusted/python3')
@patch.object(fix, 'run', side_effect=pillow_run)
def test_pillow_resolves_exact_environment_and_hash_pinned_wheel(run, executable):
    source = report(pillow_record())
    item = fix.items(source)[0]
    assert item['adapter'] == 'pillow'
    plan = fix.prepare(item, source)
    assert plan['ready'] and plan['target'] == '13.0.0'
    after_record = pillow_record()
    after_record.update(version='13.0.0', path=after_record['path'].replace('12.2.0', '13.0.0'))
    scans = iter([source, report(after_record)])
    result = fix.apply(item['id'], plan['fingerprint'], scan=lambda: next(scans))
    assert result['status'] == 'restart_needed'
    installs = [c.args[0] for c in run.call_args_list if 'install' in c.args[0] and '--dry-run' not in c.args[0]]
    assert len(installs) == 1 and any(arg.endswith('#sha256=' + 'a' * 64) for arg in installs[0])
    assert all(c.args[0][0] == '/trusted/python3' for c in run.call_args_list)


@patch.object(fix, 'checked_executable', return_value='/trusted/python3')
def test_pillow_reverse_dependency_conflict_blocks_update(executable):
    def conflict(argv, **kwargs):
        return '["dependent-app"]' if '-c' in argv else pillow_run(argv)
    source = report(pillow_record())
    with patch.object(fix, 'run', side_effect=conflict):
        plan = fix.prepare(fix.items(source)[0], source)
    assert not plan['ready'] and 'constrain Pillow' in plan['impact']


def test_executable_must_stay_in_expected_installation(tmp_path):
    link = tmp_path / 'python3'
    link.symlink_to('/bin/sh')
    with pytest.raises(fix.UpdateError):
        fix.checked_executable(link, tmp_path)


def test_runner_timeout_stops_process_group(monkeypatch, tmp_path):
    monkeypatch.setattr(Path, 'home', lambda: tmp_path)
    import sys
    with pytest.raises(fix.UpdateError, match='time or output limit'):
        fix.run([sys.executable, '-c', 'import time; time.sleep(10)'], timeout=.1)


@patch.object(fix, 'checked_executable', return_value='/opt/homebrew/bin/brew')
def test_keg_only_formula_can_be_updated(executable):
    info = brew_info()
    info['formulae'][0].update(linked_keg=None, keg_only=True)
    source = report(record())
    with patch.object(fix, 'run', side_effect=lambda argv: json.dumps(info) if 'info' in argv else 'Would upgrade node'):
        assert fix.prepare(fix.items(source)[0], source)['ready']


@pytest.mark.parametrize('change', [dict(pinned=True), dict(tap='third-party/tap'), dict(disabled=True)])
@patch.object(fix, 'checked_executable', return_value='/opt/homebrew/bin/brew')
def test_unapproved_formula_state_blocks_plan(executable, change):
    info = brew_info()
    info['formulae'][0].update(change)
    source = report(record())
    with patch.object(fix, 'run', return_value=json.dumps(info)) as run:
        assert not fix.prepare(fix.items(source)[0], source)['ready']
    assert run.call_count == 1


@patch.object(fix, 'checked_executable', return_value='/trusted/python3')
@pytest.mark.parametrize('change', ['unofficial', 'missing_hash', 'extra_dependency', 'no_candidate'])
def test_pillow_rejects_unapproved_resolution(executable, change):
    def bad_resolution(argv, **kwargs):
        result = pillow_run(argv)
        if '--report' in argv:
            path = Path(argv[argv.index('--report') + 1])
            data = json.loads(path.read_text())
            if change == 'unofficial':
                data['install'][0]['download_info']['url'] = 'https://example.com/pillow.whl'
            elif change == 'missing_hash':
                del data['install'][0]['download_info']['archive_info']['hashes']['sha256']
            elif change == 'extra_dependency':
                data['install'].append(data['install'][0])
            else:
                data['install'] = []
            path.write_text(json.dumps(data))
        return result
    source = report(pillow_record())
    with patch.object(fix, 'run', side_effect=bad_resolution):
        assert not fix.prepare(fix.items(source)[0], source)['ready']


def test_inventory_main_adds_actions_without_executing_packages(tmp_path, capsys):
    from server import software_inventory
    with patch.object(software_inventory.Scan, 'run', return_value=report(record())), patch.object(fix, 'run') as run:
        assert software_inventory.main(['--root', str(tmp_path)]) == 0
    run.assert_not_called()
    assert json.loads(capsys.readouterr().out)['remediation_items'][0]['adapter'] == 'homebrew'


def test_cli_lock_prevents_overlapping_updates(tmp_path, monkeypatch, capsys):
    import fcntl
    import io
    import os
    import sys
    directory = tmp_path / 'Library/Application Support/BoxCop'
    directory.mkdir(parents=True, mode=0o700)
    monkeypatch.setattr(Path, 'home', lambda: tmp_path)
    monkeypatch.setattr(sys, 'stdin', io.TextIOWrapper(io.BytesIO(b'{"ids":["example"]}')))
    with (directory / 'software-remediation.lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with patch.object(fix.Scan, 'run') as scan:
            assert fix.main(['prepare']) == 1
        scan.assert_not_called()
    assert 'another update' in json.loads(capsys.readouterr().out)['error']


def test_cli_rejects_command_input(tmp_path, monkeypatch, capsys):
    import io
    import sys
    (tmp_path / 'Library/Application Support/BoxCop').mkdir(parents=True, mode=0o700)
    monkeypatch.setattr(Path, 'home', lambda: tmp_path)
    monkeypatch.setattr(sys, 'stdin', io.TextIOWrapper(io.BytesIO(b'{"id":"node;touch /tmp/pwned","fingerprint":"fake"}')))
    with patch.object(fix, 'apply') as apply:
        assert fix.main(['apply']) == 1
    apply.assert_not_called()
    assert json.loads(capsys.readouterr().out)['error']


def test_group_writable_manager_directory_is_supported(tmp_path):
    directory = tmp_path / 'bin'
    directory.mkdir(mode=0o775)
    directory.chmod(0o775)
    executable = directory / 'brew'
    executable.write_text('#!/bin/sh\nexit 0\n')
    executable.chmod(0o755)
    assert fix.checked_executable(executable, tmp_path) == str(executable)


def test_stderr_warning_does_not_corrupt_json_stdout():
    import sys
    value = fix.run([sys.executable, '-c', 'import sys; print("warning", file=sys.stderr); print("{}")'])
    assert json.loads(value) == {}


def test_command_failure_has_details_and_private_bounded_log(tmp_path, monkeypatch):
    import sys
    directory = tmp_path / 'Library/Application Support/BoxCop'
    directory.mkdir(parents=True, mode=0o700)
    monkeypatch.setattr(Path, 'home', lambda: tmp_path)
    path = directory / 'software-remediation.jsonl'
    path.write_bytes(b'x' * (256 * 1024))
    with pytest.raises(fix.UpdateError) as raised:
        fix.run([sys.executable, '-c', 'import sys; print("missing dependency", file=sys.stderr); sys.exit(1)'])
    assert raised.value.returncode == 1
    assert 'missing dependency' in raised.value.diagnostics
    row = json.loads(path.read_text())
    assert 'missing dependency' in row['output']
    assert path.stat().st_size < 256 * 1024
    assert path.stat().st_mode & 0o777 == 0o600


def test_diagnostics_redact_url_credentials_and_tokens():
    value = fix.redact('https://user:password@example.org/a?token=abc&x=ok')
    assert 'password' not in value and 'abc' not in value and 'x=ok' in value


@pytest.mark.parametrize('after, expected', [({'unrelated issue'}, 'restart_needed'), ({'unrelated issue', 'new Pillow conflict'}, 'failed')])
@patch.object(fix, 'checked_executable', return_value='/trusted/python3')
@patch.object(fix, 'run', side_effect=pillow_run)
def test_existing_dependency_problems_do_not_block_but_new_ones_fail(run, executable, after, expected):
    source = report(pillow_record())
    item = fix.items(source)[0]
    after_record = pillow_record()
    after_record.update(version='13.0.0', path=after_record['path'].replace('12.2.0', '13.0.0'))
    scans = iter([source, report(after_record)])
    with patch.object(fix, 'dependency_issues', side_effect=[{'unrelated issue'}, {'unrelated issue'}, after]):
        plan = fix.prepare(item, source)
        assert plan['ready'] and 'already has 1 dependency issue' in plan['impact']
        result = fix.apply(item['id'], plan['fingerprint'], scan=lambda: next(scans))
    assert result['status'] == expected
    if expected == 'failed':
        assert 'new Pillow conflict' in result['diagnostics']


def test_optional_dependency_marker_has_extra_environment():
    import subprocess
    import sys
    prefix = '''import importlib.metadata as m
from types import SimpleNamespace
m.distributions = lambda: [SimpleNamespace(requires=['Pillow<12; extra == "images"'], metadata={'Name': 'optional-package'})]
'''
    result = subprocess.run([sys.executable, '-c', prefix + fix.pillow_dependency_script('13.0.0')], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == []


def test_dependency_check_interpreter_failure_still_blocks():
    with patch.object(fix, 'run', side_effect=fix.UpdateError('No pip', returncode=1, stderr='No module named pip')):
        with pytest.raises(fix.UpdateError):
            fix.dependency_issues('/missing/python')


def test_fixed_and_old_homebrew_copies_become_cleanup_action():
    source = report(record(), record(version='26.12.1'))
    item = fix.items(source)[0]
    assert item['adapter'] == 'homebrew_cleanup'
    assert item['state'] == 'cleanup_needed'


@patch.object(fix, 'checked_executable', return_value='/opt/homebrew/bin/brew')
def test_cleanup_is_previewed_revalidated_and_scoped(executable):
    source = report(record(), record(version='26.12.1'))
    info = brew_info()
    info['formulae'][0].update(linked_keg='26.12.1', installed=[{'version': '26.0.0'}, {'version': '26.12.1'}])
    def command(argv, **kwargs):
        return json.dumps(info) if 'info' in argv else 'Would remove /opt/homebrew/Cellar/node/26.0.0'
    with patch.object(fix, 'run', side_effect=command) as run:
        item = fix.items(source)[0]
        plan = fix.prepare(item, source)
        assert plan['ready'] and 'Remove old installed versions' in plan['impact']
        scans = iter([source, report(record(version='26.12.1'))])
        assert fix.apply(item['id'], plan['fingerprint'], scan=lambda: next(scans))['status'] == 'restart_needed'
    assert any(c.args[0] == ['/opt/homebrew/bin/brew', 'cleanup', '--dry-run', 'node'] for c in run.call_args_list)
    actual = [c for c in run.call_args_list if c.args[0] == ['/opt/homebrew/bin/brew', 'cleanup', 'node']]
    assert len(actual) == 1 and actual[0].kwargs['timeout'] is None
    assert not any('upgrade' in c.args[0] for c in run.call_args_list)


@patch.object(fix, 'checked_executable', return_value='/opt/homebrew/bin/brew')
@patch.object(fix, 'run', return_value=json.dumps(brew_info()))
def test_cleanup_requires_fixed_active_version(run, executable):
    source = report(record(), record(version='26.12.1'))
    assert not fix.prepare(fix.items(source)[0], source)['ready']
    assert run.call_count == 1


def test_saved_migration_and_failures_only_apply_to_matching_evidence():
    source = report(pillow_record())
    item = fix.items(source)[0]
    source['remediation_results'] = [dict(id=item['id'], evidence_key=item['evidence_key'], status='migration_needed', detail='Migrate Python')]
    assert fix.items(source)[0]['adapter'] == 'review'
    source['records'][0]['metadata_sha256'] = 'changed'
    assert fix.items(source)[0]['adapter'] == 'pillow'


def test_result_history_survives_reload_and_keeps_latest_per_install(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, 'home', lambda: tmp_path)
    directory = tmp_path / 'Library/Application Support/BoxCop'
    directory.mkdir(parents=True, mode=0o700)
    fix.save_result(dict(id='one', status='in_progress', detail='Started'))
    fix.save_result(dict(id='two', status='migration_needed', detail='Migrate'))
    fix.save_result(dict(id='one', status='failed', detail='Failure details'))
    rows = fix.load_results()
    assert [r['id'] for r in rows] == ['one', 'two']
    assert rows[0]['status'] == 'failed' and rows[0]['attempted_at']
    assert (directory / 'software-remediation-results.json').stat().st_mode & 0o777 == 0o600


def test_uncapped_verbose_install_is_drained_without_aborting():
    import sys
    text = fix.run([sys.executable, '-c', 'import sys,time; sys.stdout.write("x"*3000000); sys.stderr.write("y"*3000000); time.sleep(.2); print("finished")'], timeout=None)
    assert text.endswith('finished\n') and len(text) <= 2 * 1024 * 1024


@patch.object(fix, 'checked_executable', return_value='/opt/homebrew/bin/brew')
@patch.object(fix, 'run', side_effect=brew_run)
def test_previous_failure_state_does_not_invalidate_approved_retry(run, executable):
    source = report(record())
    item = fix.items(source)[0]
    item['state'] = 'failed'
    plan = fix.prepare(item, source)
    scans = iter([source, report(record(version='26.12.1'))])
    assert fix.apply(item['id'], plan['fingerprint'], scan=lambda: next(scans))['status'] == 'restart_needed'
    actual = next(c for c in run.call_args_list if c.args[0] == ['/opt/homebrew/bin/brew', 'upgrade', '--formula', 'node'])
    assert actual.kwargs['timeout'] is None


@patch.object(fix, 'checked_executable', return_value='/opt/homebrew/bin/brew')
def test_unlinked_install_can_retry_upgrade_with_linking_disclosure(executable):
    source = report(record())
    info = brew_info()
    info['formulae'][0]['linked_keg'] = None
    with patch.object(fix, 'run', side_effect=lambda argv: json.dumps(info) if 'info' in argv else 'Would upgrade node'):
        plan = fix.prepare(fix.items(source)[0], source)
    assert plan['ready'] and 'currently unlinked' in plan['impact']


@pytest.mark.parametrize('outcome, expected', [
    ('clean', 'restart_needed'), ('retained', 'cleanup_needed'),
    ('failed', 'cleanup_needed'), ('incomplete', 'unverified'),
    ('missing', 'unverified'), ('inactive', 'cleanup_needed'),
])
@patch.object(fix, 'checked_executable', return_value='/opt/homebrew/bin/brew')
def test_upgrade_includes_verified_scoped_cleanup(executable, outcome, expected):
    before = report(record())
    mixed = report(record(), record(version='26.12.1'))
    final = {'clean': report(record(version='26.12.1')),
             'retained': mixed, 'incomplete': report(record(version='26.12.1'), incomplete=True),
             'missing': report()}.get(outcome, mixed)
    upgraded = False
    def command(argv, **kwargs):
        nonlocal upgraded
        if 'info' in argv:
            info = brew_info()
            if upgraded and outcome != 'inactive':
                info['formulae'][0].update(linked_keg='26.12.1', installed=[{'version': '26.0.0'}, {'version': '26.12.1'}])
            return json.dumps(info)
        if 'upgrade' in argv and '--dry-run' not in argv:
            upgraded = True
        if 'cleanup' in argv and '--dry-run' not in argv and outcome == 'failed':
            raise fix.UpdateError('Cleanup failed', stderr='file busy')
        return 'Would remove old version' if 'cleanup' in argv else 'Would upgrade node'
    with patch.object(fix, 'run', side_effect=command) as run:
        item = fix.items(before)[0]
        plan = fix.prepare(item, before)
        assert 'automatically run Homebrew cleanup for this formula' in plan['impact']
        scans = iter([before, mixed, final])
        result = fix.apply(item['id'], plan['fingerprint'], scan=lambda: next(scans))
        assert result['status'] == expected
        mutations = [c for c in run.call_args_list if '--dry-run' not in c.args[0] and 'info' not in c.args[0]]
        expected_commands = [['/opt/homebrew/bin/brew', 'upgrade', '--formula', 'node']]
        if outcome != 'inactive': expected_commands.append(['/opt/homebrew/bin/brew', 'cleanup', 'node'])
        assert [c.args[0] for c in mutations] == expected_commands
        assert all(c.kwargs['timeout'] is None for c in mutations)
        if outcome == 'failed': assert result['diagnostics'] == 'file busy'
