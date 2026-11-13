"""Install-script containment: routing, destination policy, proxy, and a real npm install."""
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time

import httpx
import pytest

from server import package_routing
from server.desktop import _validate
from server.package_scripts import (BEGIN, Guard, ProxyServer, ScriptRuntime, disable_routing, enable_routing,
                                    profile, routing_status, sandbox_available, wrapper)


@pytest.fixture
def short():
    # Unix socket paths are limited to about 100 bytes; pytest's tmp_path is longer.
    path = Path(os.path.realpath(tempfile.mkdtemp(prefix='boxcop-', dir='/tmp')))
    yield path
    shutil.rmtree(path, ignore_errors=True)


class Receiver:
    """A harmless destination that records every request that reaches it."""
    def __init__(self):
        hits = self.hits = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                hits.append(self.path)
                self.send_response(200)
                self.send_header('Content-Length', '2')
                self.end_headers()
                self.wfile.write(b'ok')
            do_POST = do_GET

            def log_message(self, *_):
                pass
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.port = self.server.server_port
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def receiver():
    value = Receiver()
    yield value
    value.close()


def proxied(port, token):
    return httpx.Client(proxy=f'http://boxcop:{token}@127.0.0.1:{port}', trust_env=False, timeout=5)


@pytest.mark.parametrize('original', ['', 'audit=false', 'audit=false\n'])
def test_routing_is_reversible_and_coexists_with_registry_routing(tmp_path, original):
    config, state, shell = tmp_path / '.npmrc', tmp_path / 'state', '/Users/a/Library/Application Support/BoxCop/script-protection/boxcop-script-shell'
    config.write_text(original)
    package_routing.enable(tmp_path, state)
    enable_routing(tmp_path, state, shell)
    enable_routing(tmp_path, state, shell)
    assert config.read_text().count(BEGIN) == 1
    assert routing_status(tmp_path, shell) == {'managed': True, 'configured': True}
    assert package_routing.status(tmp_path)['configured']
    disable_routing(tmp_path, state)
    assert not routing_status(tmp_path, shell)['managed']
    package_routing.disable(tmp_path, state)
    assert config.read_text() == original


def test_routing_preserves_existing_shell_and_rejects_edits_and_unsafe_paths(tmp_path):
    config, state = tmp_path / '.npmrc', tmp_path / 'state'
    config.write_text('script-shell=/bin/zsh\n')
    with pytest.raises(ValueError, match='preserved'):
        enable_routing(tmp_path, state, '/safe/shell')
    assert config.read_text() == 'script-shell=/bin/zsh\n'
    config.unlink()
    for unsafe in ('/has#comment/shell', '/has${HOME}/shell', '/line\nbreak'):
        with pytest.raises(ValueError):
            enable_routing(tmp_path, state, unsafe)
    assert not config.exists()
    enable_routing(tmp_path, state, '/safe/shell')
    config.write_text(config.read_text() + 'script-shell=/bin/zsh\n')
    assert not routing_status(tmp_path, '/safe/shell')['configured']
    config.write_text(config.read_text().replace('/safe/shell', '/other/shell') + BEGIN + '\n')
    with pytest.raises(ValueError, match='edited'):
        disable_routing(tmp_path, state)


def test_policy_scopes_destinations_to_the_registered_package(tmp_path):
    guard = Guard(tmp_path)
    electron = guard.register('electron', '30.0.0', 'postinstall', '/work/app', 'Claude Code')
    other = guard.register('left-pad', '1.0.0', 'postinstall', '/work/app')
    assert guard.decide(other, 'registry.npmjs.org', 443)[0]
    assert guard.decide(electron, 'GitHub.com.', 443)[0]
    # The same destination is not open to a different package, a made-up token, or another port.
    assert not guard.decide(other, 'github.com', 443)[0]
    assert not guard.decide('forged', 'github.com', 443)[0]
    assert not guard.decide(electron, 'github.com', 22)[0]
    assert not guard.decide(electron, 'collector.example', 443)[0]
    assert not guard.decide(electron, '', 443)[0]
    blocked, exceptions = guard.snapshot()
    assert exceptions == []
    first = next(item for item in blocked if item['host'] == 'collector.example')
    assert first['package'] == 'electron' and first['agent'] == 'Claude Code'
    assert 'Claude Code started an install of electron@30.0.0' in first['message']
    assert 'collector.example' in first['message'] and 'key' not in first
    unknown = next(item for item in blocked if item['package'] is None)
    assert unknown['message'].startswith('A package install script tried to connect to github.com')
    # Repeats update one row rather than growing the list.
    guard.decide(electron, 'collector.example', 443)
    assert [item['count'] for item in guard.snapshot()[0] if item['host'] == 'collector.example'] == [2]


def test_exceptions_are_narrow_persistent_and_revocable(tmp_path):
    guard = Guard(tmp_path)
    run = guard.register('left-pad', '1.0.0', 'install', '/work/app')
    assert not guard.decide(run, 'downloads.example', 443)[0]
    guard.change('allow', 'left-pad', 'Downloads.Example')
    assert guard.snapshot() == ([], [{'package': 'left-pad', 'host': 'downloads.example'}])
    assert guard.decide(run, 'downloads.example', 443)[0]
    assert not guard.decide(guard.register('other', '1.0.0', 'install', '/work/app'), 'downloads.example', 443)[0]
    reloaded = Guard(tmp_path)
    assert reloaded.decide(reloaded.register('left-pad', '2.0.0', 'install', '/work/app'), 'downloads.example', 443)[0]
    reloaded.change('revoke', 'left-pad', 'downloads.example')
    assert not Guard(tmp_path).decide(run, 'downloads.example', 443)[0]
    for package, host in (('Not A Package', 'downloads.example'), ('left-pad', 'not a host'), ('left-pad', '*')):
        with pytest.raises(ValueError):
            guard.change('allow', package, host)
    (tmp_path / 'exceptions.json').write_text('{damaged')
    assert Guard(tmp_path).snapshot()[1] == []


def test_proxy_never_connects_to_local_or_private_addresses(tmp_path):
    guard = Guard(tmp_path)
    for host in ('127.0.0.1', '10.0.0.1', '169.254.169.254', '::1'):
        with pytest.raises(OSError):
            guard.address(host, 443)
    assert Guard(tmp_path, allow_private=True).address('127.0.0.1', 443) == '127.0.0.1'


def test_proxy_blocks_before_connecting_and_forwards_approved_requests(tmp_path, receiver):
    guard = Guard(tmp_path, allow_private=True, ports=(receiver.port,))
    server = ProxyServer(guard, 0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        run = guard.register('fixture', '1.0.0', 'postinstall', '/work/app')
        with proxied(server.server_port, run) as client:
            refused = client.get(f'http://127.0.0.1:{receiver.port}/secret?value=1')
            assert refused.status_code == 403 and refused.json()['error'] == 'BOXCOP_INSTALL_SCRIPT_NETWORK'
            assert receiver.hits == []
            guard.change('allow', 'fixture', '127.0.0.1')
            assert client.get(f'http://127.0.0.1:{receiver.port}/artifact?x=1').text == 'ok'
            assert client.post(f'http://127.0.0.1:{receiver.port}/upload', content=b'body').status_code == 200
        assert receiver.hits == ['/artifact?x=1', '/upload']
        # Another run's token does not inherit that approval; neither does no token at all.
        with proxied(server.server_port, guard.register('other', '1.0.0', 'postinstall', '/work/app')) as client:
            assert client.get(f'http://127.0.0.1:{receiver.port}/other').status_code == 403
        with httpx.Client(trust_env=False, timeout=5) as direct:
            assert direct.get(f'http://127.0.0.1:{server.server_port}/status').status_code == 400
        assert len(receiver.hits) == 2
    finally:
        server.shutdown()
        server.server_close()


def test_connect_tunnel_is_decided_before_any_bytes_are_relayed(tmp_path, receiver):
    guard = Guard(tmp_path, allow_private=True, ports=(receiver.port,))
    server = ProxyServer(guard, 0)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    def tunnel(token):
        auth = base64.b64encode(f'boxcop:{token}'.encode()).decode()
        stream = socket.create_connection(('127.0.0.1', server.server_port), timeout=5)
        stream.sendall(f'CONNECT 127.0.0.1:{receiver.port} HTTP/1.1\r\nProxy-Authorization: Basic {auth}\r\n\r\n'.encode())
        return stream, stream.recv(4096)
    try:
        run = guard.register('fixture', '1.0.0', 'postinstall', '/work/app')
        stream, reply = tunnel(run)
        assert reply.startswith(b'HTTP/1.0 403')
        stream.close()
        guard.change('allow', 'fixture', '127.0.0.1')
        stream, reply = tunnel(run)
        assert reply.startswith(b'HTTP/1.1 200')
        stream.sendall(b'GET /through-tunnel HTTP/1.0\r\n\r\n')
        reply = b''
        while data := stream.recv(4096):
            reply += data
        assert reply.endswith(b'ok')
        stream.close()
        assert receiver.hits == ['/through-tunnel']
    finally:
        server.shutdown()
        server.server_close()


def test_engine_protocol_accepts_only_known_script_actions():
    def request(**fields):
        return dict(version=1, id='s1', op='script_protection', **fields)
    _validate(request(action='allow', package='left-pad', host='downloads.example'))
    _validate(request(action='status', package='', host=''))
    for bad in (request(action='status'), request(action='run', package='', host=''),
                request(action='allow', package=1, host=''), request(action='allow', package='x' * 256, host='')):
        with pytest.raises(ValueError):
            _validate(bad)


def test_unavailable_sandbox_never_changes_npm_configuration(tmp_path):
    runtime = ScriptRuntime(home=tmp_path, directory=tmp_path / 'state', port=0, available=lambda: False)
    status = runtime.command('enable')
    assert not status['active'] and not status['routed'] and 'sandbox' in status['summary']
    assert not (tmp_path / '.npmrc').exists()


def test_wrapper_and_profile_quote_unusual_paths():
    text = wrapper("/Users/o'brien/Library/Application Support/BoxCop/script-protection")
    assert "D='/Users/o'\\''brien/Library/Application Support/BoxCop/script-protection'" in text
    rules = profile('/Users/a"b', '/Users/a"b/state')
    assert '(literal "/Users/a\\"b/.npmrc")' in rules and '(deny network*)' in rules


@pytest.mark.skipif(not sandbox_available(), reason='needs macOS sandbox-exec')
@pytest.mark.parametrize('contained_run', [False, True])
def test_contained_code_cannot_allow_itself_past_the_install_gate(short, contained_run):
    """The install gate's allowed releases live in BoxCop's own state, which neither
    a contained install script nor a contained run can write."""
    from server.containment import run_profile
    from server.package_exceptions import Exceptions
    home, state = short / 'home', short / 'BoxCop' / 'script-protection'
    package_state = short / 'BoxCop' / 'package-protection'
    for folder in (home, state, package_state):
        folder.mkdir(parents=True)
    exceptions = Exceptions(package_state)
    exceptions.change('allow', 'npm', 'already-allowed', '1.0.0')
    before = exceptions.path.read_bytes()
    rules = run_profile(home, state, 1) if contained_run else profile(home, state)
    assert '(subpath "' + str(package_state) + '")' in rules
    forged = json.dumps([{'ecosystem': 'npm', 'package': 'evil', 'version': '6.6.6', 'added': '2026-11-12T00:00:00Z'}])
    attempts = (f'printf %s {json.dumps(forged)!r} > "$P/exceptions.json"', 'rm "$P/exceptions.json"',
                'mv "$P/exceptions.json" "$P/gone"', 'echo x > "$P/new-file"', f'printf %s {json.dumps(forged)!r} > "$O"; mv "$O" "$P/exceptions.json"')
    for attempt in attempts:
        result = subprocess.run(['/usr/bin/sandbox-exec', '-p', rules, '/bin/sh', '-c', attempt], capture_output=True, text=True, timeout=20,
                                env={'P': str(package_state), 'O': str(short / 'outside.json'), 'PATH': '/usr/bin:/bin'})
        assert result.returncode != 0, attempt
        assert exceptions.path.read_bytes() == before and sorted(p.name for p in package_state.iterdir()) == ['exceptions.json', 'exceptions.json.lock']
    assert not Exceptions(package_state).allows('npm', 'evil', '6.6.6')
    # The same commands succeed uncontained, so the refusals above came from the sandbox.
    assert subprocess.run(['/bin/sh', '-c', attempts[3]], env={'P': str(package_state)}).returncode == 0


SCRIPT = '''
const cp = require('child_process'), fs = require('fs');
const base = process.env.BOXCOP_TEST_URL;
fs.appendFileSync(process.env.BOXCOP_TEST_MARKER, 'ran ' + process.env.npm_package_name + '\\n');
const quiet = {stdio: 'ignore'};
fetch(base + 'direct-fetch').catch(() => {});
try { cp.execSync('/usr/bin/curl -s -m 3 --noproxy "*" ' + base + 'child-direct', quiet); } catch {}
try { cp.execSync('/usr/bin/curl -s -m 3 ' + base + 'child-proxied', quiet); } catch {}
try { cp.execSync('/usr/bin/curl -s -m 3 ' + process.env.BOXCOP_APPROVED_URL + 'approved', quiet); } catch {}
try { cp.execSync('/usr/bin/curl -s -m 2 --unix-socket ' + JSON.stringify(process.env.BOXCOP_CONTROL) + ' -d package=electron http://boxcop/run >> ' + JSON.stringify(process.env.BOXCOP_TEST_MARKER), quiet); } catch {}
try { fs.appendFileSync(process.env.HOME + '/.npmrc', 'script-shell=/bin/sh\\n'); fs.appendFileSync(process.env.BOXCOP_TEST_MARKER, 'npmrc-written\\n'); } catch {}
try { fs.writeFileSync(process.env.HOME + '/.zshenv', 'curl attacker'); fs.appendFileSync(process.env.BOXCOP_TEST_MARKER, 'profile-written\\n'); } catch {}
// Detached from npm and reparented to launchd: ancestry is gone, the sandbox is not.
cp.spawn('/bin/sh', ['-c', '(sleep 1; /usr/bin/curl -s -m 3 --noproxy "*" ' + base + 'detached-orphan) &'], {detached: true, stdio: 'ignore'}).unref();
'''


@pytest.mark.skipif(not sandbox_available() or not shutil.which('npm'), reason='needs macOS sandbox-exec and npm')
def test_real_npm_install_script_is_contained_including_subprocesses(short, receiver):
    approved = Receiver()
    home, state = short / 'home', short / 'state'
    package, app = short / 'evil-fixture', short / 'app'
    for folder in (home, package, app):
        folder.mkdir()
    (package / 'package.json').write_text(json.dumps({'name': 'evil-fixture', 'version': '1.0.0', 'scripts': {'postinstall': 'node install.js'}}))
    (package / 'install.js').write_text(SCRIPT)
    (app / 'package.json').write_text(json.dumps({'name': 'app', 'version': '1.0.0',
        'scripts': {'own': f'/usr/bin/curl -s -m 3 http://127.0.0.1:{receiver.port}/own-project-script'}}))
    marker = short / 'marker.log'
    environment = {key: value for key, value in os.environ.items() if not key.lower().startswith('npm_config_') and 'proxy' not in key.lower()}
    environment.update(HOME=str(home), BOXCOP_TEST_MARKER=str(marker), BOXCOP_TEST_URL=f'http://127.0.0.1:{receiver.port}/',
                       BOXCOP_APPROVED_URL=f'http://127.0.0.1:{approved.port}/', BOXCOP_CONTROL=str(state / 'control.sock'))

    def npm(*arguments):
        return subprocess.run(['npm', *arguments, '--no-audit', '--no-fund', '--offline'], cwd=app, env=environment,
                              capture_output=True, text=True, timeout=120)
    subprocess.run(['npm', 'pack', '--pack-destination', str(short)], cwd=package, env=environment, check=True, capture_output=True, timeout=120)
    archive = str(short / 'evil-fixture-1.0.0.tgz')

    # Baseline: without protection the same script reaches the receiver.
    assert npm('install', archive).returncode == 0
    time.sleep(3)
    assert {'/direct-fetch', '/child-direct', '/child-proxied', '/detached-orphan'} <= set(receiver.hits)
    assert (home / '.zshenv').exists()
    shutil.rmtree(app / 'node_modules')
    (home / '.zshenv').unlink()
    (home / '.npmrc').unlink()
    marker.unlink()
    receiver.hits.clear()
    approved.hits.clear()

    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
    runtime = ScriptRuntime(home=home, directory=state, port=port, allow_private=True, ports=(approved.port,),
                            initiator=lambda pid: 'Claude Code')
    try:
        assert runtime.command('enable')['active'], runtime.status()
        runtime.command('allow', 'evil-fixture', '127.0.0.1')
        before = (home / '.npmrc').read_text()
        result = npm('install', archive)
        assert result.returncode == 0, result.stderr
        time.sleep(3)
        # The install completed and the script ran, but nothing unapproved was delivered.
        assert (app / 'node_modules/evil-fixture/package.json').exists()
        assert marker.read_text() == 'ran evil-fixture\n'
        assert receiver.hits == []
        assert approved.hits == ['/approved']
        assert (home / '.npmrc').read_text() == before and not (home / '.zshenv').exists()
        blocked = runtime.status()['blocked']
        assert [(item['package'], item['package_version'], item['event'], item['host'], item['port']) for item in blocked] == [
            ('evil-fixture', '1.0.0', 'postinstall', '127.0.0.1', receiver.port)]
        assert blocked[0]['message'].startswith('Claude Code started an install of evil-fixture@1.0.0, whose postinstall script tried to connect to 127.0.0.1.')
        # Developer activity outside a dependency install script is untouched.
        assert npm('run', 'own').returncode == 0
        assert receiver.hits == ['/own-project-script']
        # With BoxCop stopped, routing remains and contained scripts have no network at all.
        runtime.close()
        receiver.hits.clear()
        approved.hits.clear()
        marker.unlink()
        shutil.rmtree(app / 'node_modules')
        assert npm('install', archive).returncode == 0
        time.sleep(3)
        assert marker.read_text() == 'ran evil-fixture\n' and receiver.hits == [] and approved.hits == []
    finally:
        runtime.close()
        approved.close()


@pytest.mark.skipif(not sandbox_available(), reason='needs macOS sandbox-exec')
def test_disable_restores_configuration_and_stops_listeners(short):
    home, state = short / 'home', short / 'state'
    home.mkdir()
    (home / '.npmrc').write_text('fund=false\n')
    runtime = ScriptRuntime(home=home, directory=state, port=0)
    try:
        assert runtime.command('enable')['active']
        assert os.access(state / 'boxcop-script-shell', os.X_OK)
        resumed = ScriptRuntime(home=home, directory=state, port=0)
        assert resumed.status()['routed'] and not resumed.status()['active']
        status = runtime.command('disable')
        assert not status['routed'] and not status['active']
        assert (home / '.npmrc').read_text() == 'fund=false\n'
        assert runtime.proxy is None and not (state / 'control.sock').exists()
    finally:
        runtime.close()
