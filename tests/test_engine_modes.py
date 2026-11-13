"""One-shot engine modes: the offline self-test and the protection status."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import shutil

import pytest

from server import self_test
from server.desktop import main
from server.package_proxy import Firewall, RegistryServer
from server.package_routing import enable as enable_registry
from server.package_scripts import ScriptRuntime

ROOT = Path(__file__).resolve().parents[1]
CHECKS = {'rules', 'package_feed', 'registry_firewall', 'containment', 'inventory', 'triage'}


def engine(*arguments, home):
    env = {'HOME': str(home), 'PATH': '/usr/bin:/bin', 'PYTHONDONTWRITEBYTECODE': '1'}
    return subprocess.run([sys.executable, '-m', 'server.desktop', *arguments], cwd=ROOT, env=env,
                          capture_output=True, text=True, timeout=60)


def test_self_test_prints_one_json_line_offline_and_leaves_no_user_data(tmp_path):
    launcher = '''
import sys
def guard(name, args):
    if name in ('socket.connect', 'socket.getaddrinfo', 'socket.bind'):
        raise AssertionError('The self-test must not use the network')
sys.addaudithook(guard)
from server.desktop import main
raise SystemExit(main())
'''
    env = {'HOME': str(tmp_path), 'PATH': '/usr/bin:/bin', 'PYTHONDONTWRITEBYTECODE': '1'}
    result = subprocess.run([sys.executable, '-c', launcher, '--self-test'], cwd=ROOT, env=env, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    assert result.stderr == '' and result.stdout.count('\n') == 1
    value = json.loads(result.stdout)
    assert value == {'ok': True, 'schema': 'boxcop.self-test.v1', 'engine': 'rules', 'protocol': 1,
                     'checks': dict.fromkeys(sorted(CHECKS), True)}
    assert list(tmp_path.iterdir()) == []  # Nothing is written under the home folder.


def test_self_test_failure_is_nonzero_and_names_the_failed_check(monkeypatch, capsys):
    def broken(directory):
        raise RuntimeError('PRIVATE_FAILURE_DETAIL')
    monkeypatch.setattr(self_test, '_rules', broken)
    monkeypatch.setattr(self_test, '_inventory', lambda: False)
    assert main(['--self-test']) == 1
    output = capsys.readouterr().out
    value = json.loads(output)
    assert value['ok'] is False and value['schema'] == 'boxcop.self-test.v1'
    assert value['checks']['rules'] is False and value['checks']['inventory'] is False and value['checks']['triage'] is True
    assert 'PRIVATE_FAILURE_DETAIL' not in output


def test_self_test_takes_no_other_arguments(tmp_path):
    result = engine('--self-test', '--verbose', home=tmp_path)
    assert result.returncode == 2 and result.stdout == ''


def test_protection_status_reports_nothing_set_up(tmp_path, capsys):
    with socket.socket() as first, socket.socket() as second:
        first.bind(('127.0.0.1', 0)); second.bind(('127.0.0.1', 0))
        ports = first.getsockname()[1], second.getsockname()[1]
    assert self_test.protection_status(['--data-dir', str(tmp_path / 'data')], home=tmp_path,
                                       registry_port=ports[0], script_port=ports[1]) == 0
    value = json.loads(capsys.readouterr().out)
    assert set(value) == {'schema', 'package', 'scripts'} and value['schema'] == 'boxcop.protection-status.v1'
    assert set(value['package']) == {'configured', 'routed', 'listening'} and set(value['scripts']) == {'routed', 'listening'}
    assert all(type(flag) is bool for part in ('package', 'scripts') for flag in value[part].values())
    assert value['package']['routed'] is False and value['package']['listening'] is False
    assert value['scripts'] == {'routed': False, 'listening': False}
    assert not (tmp_path / 'data').exists()  # A status check creates nothing.


def test_protection_status_sees_real_routing_and_listeners(tmp_path, capsys):
    # Unix socket paths are short; pytest's tmp_path is not.
    root = Path(os.path.realpath(tempfile.mkdtemp(prefix='boxcop-', dir='/tmp')))
    home, data = root / 'home', root / 'data'
    home.mkdir()

    class Policies:
        policy = None
        def status(self):
            return {'available': False, 'update_error': None, 'unknown_policy': 'allow', 'stale': True}
    registry = RegistryServer(Firewall(Policies(), b'\0' * 32, upstream=object()), 0)
    scripts = ScriptRuntime(home=home, directory=data / 'script-protection', port=0, available=lambda: True, initiator=lambda pid: None)
    import threading
    threading.Thread(target=registry.serve_forever, daemon=True).start()
    try:
        enable_registry(home, data / 'package-protection')
        assert scripts.command('enable')['active']
        script_port = scripts.proxy.server_address[1]
        assert self_test.protection_status(['--data-dir', str(data)], home=home, registry_port=registry.server_port,
                                           script_port=script_port) == 0
        value = json.loads(capsys.readouterr().out)
        assert value['package']['routed'] is True and value['package']['listening'] is True
        assert value['scripts'] == {'routed': True, 'listening': True}
        # The probe is not a connection attempt by an install script: nothing is recorded as blocked.
        assert scripts.status()['blocked'] == []
        # Some other program on the port is not BoxCop listening.
        with socket.socket() as other:
            other.bind(('127.0.0.1', 0)); other.listen()
            assert self_test.protection_status(['--data-dir', str(data)], home=home, registry_port=other.getsockname()[1],
                                               script_port=other.getsockname()[1]) == 0
        value = json.loads(capsys.readouterr().out)
        assert value['package'] == {**value['package'], 'routed': True, 'listening': False}
        assert value['scripts'] == {'routed': True, 'listening': False}
    finally:
        scripts.close()
        registry.shutdown(); registry.server_close()
        shutil.rmtree(root, ignore_errors=True)


@pytest.mark.parametrize('arguments', [[], ['--data-dir'], ['--data-dir', 'relative/path'], ['--home', '/tmp'],
                                       ['--data-dir', '/tmp/a', '--extra']])
def test_protection_status_requires_an_absolute_data_dir(tmp_path, arguments):
    result = engine('--protection-status', *arguments, home=tmp_path)
    assert result.returncode == 2 and result.stdout == ''


def test_protection_status_argv_mode_prints_one_line(tmp_path):
    result = engine('--protection-status', '--data-dir', str(tmp_path / 'data'), home=tmp_path)
    assert result.returncode == 0 and result.stdout.count('\n') == 1
    value = json.loads(result.stdout)
    assert value['schema'] == 'boxcop.protection-status.v1'
    assert value['package']['routed'] is False and value['scripts']['routed'] is False


@pytest.mark.parametrize('mode', ['--classifier-self-test', '--reviewed-transfer', '--provider-integrations', '--host-agent-correction',
                                  '--agent-corrections', '--team-desktop', '--team-reporting', '--package-protection'])
def test_dropped_modes_are_not_engine_modes(tmp_path, mode):
    result = engine(mode, home=tmp_path)
    assert result.returncode == 2 and result.stdout == ''
    assert result.stderr == 'BoxCop engine could not start.\n'
