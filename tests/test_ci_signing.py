"""Credential lifecycle tests use synthetic secrets and never touch Keychain."""
import base64
import importlib.util
import json
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('ci_signing', ROOT / 'desktop/macos/scripts/ci_signing.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def setup_env(monkeypatch, tmp_path):
    monkeypatch.setenv('GITHUB_ACTIONS', 'true')
    monkeypatch.setenv('RUNNER_TEMP', str(tmp_path))
    monkeypatch.setenv('GITHUB_ENV', str(tmp_path / 'environment'))
    for name in ['BOXCOP_CERTIFICATE_BASE64', 'BOXCOP_APP_PROFILE_BASE64', 'BOXCOP_NETWORK_PROFILE_BASE64']:
        monkeypatch.setenv(name, base64.b64encode(b'synthetic fixture').decode())
    for name in ['BOXCOP_CERTIFICATE_PASSWORD', 'BOXCOP_NOTARY_APPLE_ID', 'BOXCOP_NOTARY_PASSWORD']:
        monkeypatch.setenv(name, 'synthetic-secret')


def test_installs_then_restores_search_list_and_removes_files(tmp_path, monkeypatch):
    setup_env(monkeypatch, tmp_path)
    commands = []
    def run(command):
        commands.append(command)
        if command == ['security', 'list-keychains', '-d', 'user']:
            return '"/original/keychain with spaces"\n'
        if command[:2] == ['security', 'create-keychain']:
            Path(command[-1]).touch()
        return ''
    monkeypatch.setattr(module, 'run', run)
    module.install()
    directory = tmp_path / 'boxcop-signing'
    assert not (directory / 'identity.p12').exists()
    assert (directory / 'Allay_Developer_ID.provisionprofile').read_bytes() == b'synthetic fixture'
    environment = (tmp_path / 'environment').read_text()
    assert 'synthetic-secret' not in environment
    assert 'BOXCOP_KEYCHAIN_PATH=' in environment
    assert any(command[:3] == ['xcrun', 'notarytool', 'store-credentials'] and '--keychain' in command for command in commands)
    module.cleanup()
    assert not directory.exists()
    assert ['security', 'list-keychains', '-d', 'user', '-s', '/original/keychain with spaces'] in commands
    assert ['security', 'delete-keychain', str(directory / 'ci.keychain-db')] in commands


def test_missing_secret_fails_without_creating_files(tmp_path, monkeypatch):
    setup_env(monkeypatch, tmp_path)
    monkeypatch.delenv('BOXCOP_NOTARY_PASSWORD')
    with pytest.raises(RuntimeError, match='Missing required'):
        module.install()
    assert not (tmp_path / 'boxcop-signing').exists()


def test_subprocess_error_never_includes_secret_args_or_output(monkeypatch):
    monkeypatch.setattr(module.subprocess, 'run', lambda *a, **k: subprocess.CompletedProcess(a[0], 1, stdout='synthetic-secret', stderr='synthetic-secret'))
    with pytest.raises(RuntimeError) as error:
        module.run(['security', 'import', 'synthetic-secret'])
    assert 'synthetic-secret' not in str(error.value)


def test_partial_install_cleanup_is_safe(tmp_path, monkeypatch):
    setup_env(monkeypatch, tmp_path)
    directory = tmp_path / 'boxcop-signing'
    directory.mkdir()
    (directory / 'identity.p12').write_bytes(b'synthetic')
    module.cleanup()
    assert not directory.exists()
