import json
from pathlib import Path
import sys
import threading
import time

import pytest

from server.remediation_console import ConsoleLog
from server import software_remediation as fix


@pytest.fixture
def console_home(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, 'home', lambda: tmp_path)
    (tmp_path / 'Library/Application Support/BoxCop').mkdir(parents=True, mode=0o700)
    return tmp_path / 'Library/Application Support/BoxCop/software-console'


def test_running_command_publishes_output_before_completion(console_home, monkeypatch):
    log = ConsoleLog('a' * 24, fix.redact)
    monkeypatch.setattr(fix, '_console', log)
    errors = []
    def run():
        try:
            fix.run([sys.executable, '-u', '-c', 'import time,sys; print("compiling ruby"); print("compiler warning", file=sys.stderr); time.sleep(2); print("done")'], timeout=None)
        except Exception as error: errors.append(error)
    thread = threading.Thread(target=run)
    thread.start()
    path = console_home / ('a' * 24 + '.json')
    live = None
    deadline = time.monotonic() + 1.8
    try:
        while time.monotonic() < deadline:
            row = json.loads(path.read_text())
            if '\ncompiling ruby\n' in row['text'] and '\ncompiler warning\n' in row['text']:
                live = row
                break
            time.sleep(.03)
        assert live is not None and live['status'] == 'running'
        assert thread.is_alive()
    finally:
        thread.join(timeout=5)
    assert not errors and not thread.is_alive()
    log.finish('restart_needed', 'Installed version verified')
    row = json.loads(path.read_text())
    assert 'done' in row['text'] and row['status'] == 'restart_needed'
    assert path.stat().st_mode & 0o777 == 0o600


def test_console_is_bounded_and_redacts_across_chunks(console_home):
    log = ConsoleLog('b' * 24, fix.redact)
    log.append('line\n' * 40000)
    log.feed('stdout', b'https://user:pass')
    log.feed('stdout', b'word@example.com/?token=secret\n')
    log.finish('failed', 'command failed')
    row = json.loads((console_home / ('b' * 24 + '.json')).read_text())
    assert row['truncated'] and len(row['text']) < log.limit + 100
    assert 'password' not in row['text'] and 'secret' not in row['text']
    assert '[redacted]' in row['text']


def test_new_attempt_resets_previous_output(console_home):
    old = ConsoleLog('c' * 24, fix.redact)
    old.append('previous attempt')
    old.finish('failed', 'failed')
    ConsoleLog('c' * 24, fix.redact)
    row = json.loads((console_home / ('c' * 24 + '.json')).read_text())
    assert row['status'] == 'running' and 'previous attempt' not in row['text']


def test_console_does_not_follow_directory_symlink(console_home, tmp_path):
    victim = tmp_path / 'victim'
    victim.mkdir()
    console_home.symlink_to(victim, target_is_directory=True)
    log = ConsoleLog('d' * 24, fix.redact)
    log.finish('failed', 'test')
    assert list(victim.iterdir()) == []


def test_invalid_console_identifier_rejected(console_home):
    with pytest.raises(ValueError): ConsoleLog('../outside', fix.redact)
