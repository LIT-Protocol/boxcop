"""Contained runs execute real commands under the macOS sandbox and check real effects."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import threading

import pytest

from server import containment
from server.package_scripts import sandbox_available
from server.security_events import containment_events
from server.event_log import EventLog

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(not sandbox_available(), reason='needs the macOS sandbox (not available inside another sandbox)')


class Hello(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        body = self.server.body
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def servers():
    started = []
    for body in (b'ALLOWED_SERVER_BODY', b'OTHER_SERVER_BODY'):
        server = ThreadingHTTPServer(('127.0.0.1', 0), Hello)
        server.body = body
        threading.Thread(target=server.serve_forever, daemon=True).start()
        started.append(server)
    yield [server.server_address[1] for server in started]
    for server in started:
        server.shutdown()
        server.server_close()


@pytest.fixture
def layout():
    root = Path(os.path.realpath(tempfile.mkdtemp(prefix='boxcop-contain-test-')))
    home, state, work = root / 'home', root / 'state', root / 'work'
    for folder in (home, work, home / '.ssh', home / '.aws', home / '.claude', home / '.config/gcloud', home / 'Library/Keychains'):
        folder.mkdir(parents=True)
    (home / '.ssh/id_ed25519').write_text('FAKE_PRIVATE_KEY_MATERIAL')
    (home / '.aws/credentials').write_text('FAKE_AWS_SECRET')
    (home / '.config/gcloud/credentials.db').write_text('FAKE_GCLOUD_SECRET')
    (home / 'Library/Keychains/login.keychain-db').write_text('FAKE_KEYCHAIN')
    (home / '.zshrc').write_text('# original\n')
    (home / 'notes.txt').write_text('ordinary file')
    yield home, state, work
    shutil.rmtree(root, ignore_errors=True)


def contained(layout, script, hosts=(), **options):
    home, state, work = layout
    env = {'HOME': str(home), 'PATH': '/usr/bin:/bin', 'WORK': str(work)}
    output = work / 'output.txt'
    code = containment.run(['/bin/sh', '-c', f'({script}) > "$WORK/output.txt" 2>&1'], hosts, home=home, directory=state,
                           env=env, cwd=str(work), **options)
    return code, output.read_text() if output.exists() else ''


def test_benign_work_succeeds_and_exit_code_passes_through(layout):
    home, state, work = layout
    code, output = contained(layout, 'cat "$HOME/notes.txt"; echo built > "$WORK/result.txt"; echo kept > "$HOME/project.txt"; exit 7')
    assert code == 7
    assert output == 'ordinary file'
    assert (work / 'result.txt').read_text() == 'built\n'
    assert (home / 'project.txt').read_text() == 'kept\n'
    assert contained(layout, 'true')[0] == 0


@pytest.mark.parametrize('target', ['.zshrc', '.bash_profile', '.npmrc', '.gitconfig', '.claude/settings.json',
                                    '.codex/hooks.json', '.cursor/hooks.json', 'Library/LaunchAgents/evil.plist',
                                    '.ssh/authorized_keys'])
def test_writes_that_would_run_later_or_change_tool_config_are_denied(layout, target):
    home, _, _ = layout
    path = home / target
    before = path.read_text() if path.exists() else None
    code, output = contained(layout, f'mkdir -p "$(dirname "$HOME/{target}")"; echo PLANTED >> "$HOME/{target}"')
    assert code != 0
    assert 'Operation not permitted' in output
    assert (path.read_text() if path.exists() else None) == before
    assert before is not None or not path.exists()


@pytest.mark.parametrize('target,secret', [('.ssh/id_ed25519', 'FAKE_PRIVATE_KEY_MATERIAL'), ('.aws/credentials', 'FAKE_AWS_SECRET'),
                                           ('.config/gcloud/credentials.db', 'FAKE_GCLOUD_SECRET'),
                                           ('Library/Keychains/login.keychain-db', 'FAKE_KEYCHAIN')])
def test_credential_folders_cannot_be_read(layout, target, secret):
    home, _, work = layout
    code, output = contained(layout, f'cat "$HOME/{target}"; cp "$HOME/{target}" "$WORK/stolen"; ls "$HOME/{target.rsplit("/", 1)[0]}"')
    assert code != 0
    assert secret not in output and 'Operation not permitted' in output
    assert not (work / 'stolen').exists() or secret not in (work / 'stolen').read_text()


def test_state_folder_cannot_be_changed_from_inside(layout):
    home, state, _ = layout
    code, output = contained(layout, f'echo "[]" > "{state}/blocked-connections.json"; echo x > "{state}/planted"')
    assert code != 0 and 'Operation not permitted' in output
    assert not (state / 'planted').exists()


def test_no_network_by_default_and_blocked_attempts_are_recorded(layout, servers):
    home, state, _ = layout
    allowed_port, _ = servers
    code, output = contained(layout, f'curl -s -m 5 http://127.0.0.1:{allowed_port}/', allow_private=True)
    assert 'ALLOWED_SERVER_BODY' not in output
    assert json.loads(output)['error'] == 'BOXCOP_CONTAINED_RUN_NETWORK'
    rows = EventLog(state / 'blocked-connections.json').read()
    assert [(row['kind'], row['program'], row['host'], row['port']) for row in rows] == [('run', 'sh', '127.0.0.1', allowed_port)]
    event, = containment_events(rows, 10)
    assert event['layer'] == 'containment' and event['outcome'] == 'blocked' and event['host'] == '127.0.0.1'
    assert event['title'] == 'Blocked a connection to 127.0.0.1' and event['policy_ids'] == ['contained-run-network']
    assert 'contained run of sh' in event['reason']


def test_only_the_allowed_destination_is_reachable_and_only_through_the_proxy(layout, servers):
    home, state, _ = layout
    allowed_port, other_port = servers
    hosts = [f'127.0.0.1:{allowed_port}']
    code, output = contained(layout, f'curl -s -m 5 http://127.0.0.1:{allowed_port}/', hosts, allow_private=True)
    assert code == 0 and output == 'ALLOWED_SERVER_BODY'
    # A different loopback server is refused by the proxy.
    code, output = contained(layout, f'curl -s -m 5 http://127.0.0.1:{other_port}/', hosts, allow_private=True)
    assert 'OTHER_SERVER_BODY' not in output and 'BOXCOP_CONTAINED_RUN_NETWORK' in output
    # Going around the proxy is refused by the sandbox, even for the allowed server.
    for port in (allowed_port, other_port):
        code, output = contained(layout, f"curl -s -S -m 5 --noproxy '*' http://127.0.0.1:{port}/", hosts, allow_private=True)
        assert code != 0 and 'SERVER_BODY' not in output
    # The same requests work outside containment, so the failures above are the sandbox.
    plain = subprocess.run(['/usr/bin/curl', '-s', '-m', '5', '--noproxy', '*', f'http://127.0.0.1:{other_port}/'],
                           capture_output=True, text=True, env={'PATH': '/usr/bin:/bin'})
    assert plain.stdout == 'OTHER_SERVER_BODY'
    assert [row['port'] for row in EventLog(state / 'blocked-connections.json').read()] == [other_port]


def test_private_addresses_are_refused_even_when_the_host_is_allowed(layout, servers):
    allowed_port, _ = servers
    code, output = contained(layout, f'curl -s -m 5 http://127.0.0.1:{allowed_port}/', [f'127.0.0.1:{allowed_port}'])
    assert 'ALLOWED_SERVER_BODY' not in output


def test_children_and_detached_descendants_stay_contained(layout, servers):
    home, _, work = layout
    allowed_port, _ = servers
    script = (f"(nohup /bin/sh -c 'sleep 0.2; curl -s -m 3 --noproxy \"*\" http://127.0.0.1:{allowed_port}/ > \"$WORK/late.txt\" 2>&1; "
              "echo PLANTED >> \"$HOME/.zshrc\"; echo done > \"$WORK/finished\"' >/dev/null 2>&1 &) ; true")
    assert contained(layout, script)[0] == 0
    import time
    deadline = time.monotonic() + 10
    while not (work / 'finished').exists():
        assert time.monotonic() < deadline
        time.sleep(.05)
    assert 'ALLOWED_SERVER_BODY' not in (work / 'late.txt').read_text()
    assert (home / '.zshrc').read_text() == '# original\n'


def test_profile_names_the_denied_paths():
    profile = containment.run_profile('/Users/example', '/Users/example/Library/Application Support/BoxCop/script-protection', 4321)
    assert '(deny network*)' in profile and '(remote ip "localhost:4321")' in profile
    for path in ('/Users/example/.zshrc', '/Users/example/.gitconfig', '/Users/example/.npmrc', '/Users/example/.claude',
                 '/Users/example/.ssh', '/Users/example/.aws', '/Users/example/.gnupg', '/Users/example/.config/gcloud',
                 '/Users/example/Library/Keychains', '/Users/example/Library/LaunchAgents'):
        assert '"' + path + '"' in profile


@pytest.mark.parametrize('value', ['', 'localhost', 'http://example.com', 'example.com:0', 'example.com:port', 'exa mple.com', '*.example.com'])
def test_invalid_allow_hosts_are_refused(value):
    with pytest.raises(ValueError):
        containment.parse_host(value)
    assert containment.parse_host('Example.COM') == ('example.com', None)
    assert containment.parse_host('example.com:8443') == ('example.com', 8443)


def test_engine_argv_mode_runs_standalone_and_keeps_data_folder_private(layout):
    home, _, work = layout
    env = {'HOME': str(home), 'PATH': '/usr/bin:/bin', 'PYTHONDONTWRITEBYTECODE': '1'}
    def engine(*arguments):
        return subprocess.run([sys.executable, '-m', 'server.desktop', '--contain', *arguments], cwd=ROOT, env=env,
                              capture_output=True, text=True, timeout=30)
    result = engine('--', '/bin/sh', '-c', f'echo out; echo err >&2; echo PLANTED >> "$HOME/.zshrc"; touch "{work}/ran"; exit 3')
    assert result.returncode == 3
    assert result.stdout == 'out\n' and 'err' in result.stderr
    assert (work / 'ran').exists() and (home / '.zshrc').read_text() == '# original\n'
    blocked = engine('--allow-host', 'example.com', '--', '/usr/bin/curl', '-s', '-m', '5', 'http://blocked.example/')
    assert 'BOXCOP_CONTAINED_RUN_NETWORK' in blocked.stdout
    data = home / 'Library/Application Support/BoxCop'
    rows = json.loads((data / 'script-protection/blocked-connections.json').read_text())
    assert [(row['program'], row['host'], row['port']) for row in rows] == [('curl', 'blocked.example', 80)]
    # The engine refuses a data folder other users can read, so creating it here must keep it private.
    for folder in (data, data / 'script-protection'):
        assert stat.S_IMODE(folder.stat().st_mode) == 0o700
    for arguments in ([], ['--'], ['--allow-host'], ['--allow-host', 'bad host', '--', '/usr/bin/true'], ['/usr/bin/true'],
                      ['--unknown', '--', '/usr/bin/true']):
        refused = engine(*arguments)
        assert refused.returncode == 2 and refused.stdout == ''
    missing = engine('--', '/nonexistent/program')
    assert missing.returncode not in (0, 2)
