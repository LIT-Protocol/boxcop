"""Contain dependency install scripts: no network except an allowlisting local proxy.

npm's `script-shell` setting sends every lifecycle script through a wrapper. The
wrapper re-executes dependency install scripts under a macOS sandbox profile
that is inherited by every descendant, including detached ones. The sandbox
permits only this module's loopback proxy (and the registry firewall), so the
destination decision happens here, before any upstream connection is opened.

This limits outbound connections during installation. It does not stop a script
from reading files, from abusing an approved destination, or from leaving code
that runs later outside the sandbox.
"""
import base64
from collections import OrderedDict, deque
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import select
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import time
from urllib.parse import parse_qs, urlsplit

from .package_intelligence import atomic_write, canonical
from .package_routing import read_config

BEGIN = '# BEGIN BOXCOP INSTALL SCRIPT PROTECTION'
END = '# END BOXCOP INSTALL SCRIPT PROTECTION'
PORT = 8795
REGISTRY_PORT = 8794
SANDBOX = '/usr/bin/sandbox-exec'
HOST = re.compile(r'(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+')
PACKAGE = re.compile(r'(?=.{1,214}$)(@[a-z0-9~][a-z0-9._~-]*/)?[a-z0-9~][a-z0-9._~-]*')
SAFE_PATH = re.compile(r'/[A-Za-z0-9 _./@+-]+')

# Destinations any contained install script may reach: the public registry and
# the Node.js headers that node-gyp downloads. Deliberately short; hosts that
# accept uploads from anyone (GitHub, cloud storage) are scoped to packages.
DEFAULT_HOSTS = frozenset({'registry.npmjs.org', 'nodejs.org'})
GITHUB_RELEASES = ('github.com', 'objects.githubusercontent.com', 'release-assets.githubusercontent.com')
# A starting list of packages whose install scripts download their own binaries.
# The name is the one npm reports for the installed manifest. Not exhaustive:
# anything missing is blocked, reported, and can be approved per package.
PACKAGE_HOSTS = {
    'electron': GITHUB_RELEASES,
    'sharp': GITHUB_RELEASES,
    'better-sqlite3': GITHUB_RELEASES,
    'sqlite3': GITHUB_RELEASES,
    'bcrypt': GITHUB_RELEASES,
    'canvas': GITHUB_RELEASES,
    'keytar': GITHUB_RELEASES,
    'node-sass': GITHUB_RELEASES,
    'puppeteer': ('storage.googleapis.com', 'googlechromelabs.github.io'),
    'cypress': ('download.cypress.io', 'cdn.cypress.io'),
    'prisma': ('binaries.prisma.sh',),
    '@prisma/engines': ('binaries.prisma.sh',),
    '@sentry/cli': ('downloads.sentry-cdn.com',),
}
AGENTS = (('Claude Code', re.compile(r'(^|/)claude(\s|$)|claude-code')),
          ('Codex', re.compile(r'(^|/)codex(\s|$)|@openai/codex')),
          ('Cursor', re.compile(r'Cursor\.app/|(^|/)cursor-agent(\s|$)')))


def state_directory():
    return Path.home() / 'Library/Application Support/BoxCop/script-protection'


# --- npm routing -----------------------------------------------------------

def _block(shell):
    return f'{BEGIN}\nscript-shell={shell}\n{END}\n'


def _setting(text):
    values = re.findall(r'^\s*script-shell\s*=\s*(.*?)\s*$', text, re.MULTILINE)
    return values[-1].strip('"\'') if values else None


def enable_routing(home, state, shell):
    """Add one reversible user-npmrc block. An existing script-shell is never replaced."""
    path, receipt, shell = Path(home) / '.npmrc', Path(state) / 'npm-script-shell.json', str(shell)
    if not SAFE_PATH.fullmatch(shell):
        raise ValueError('The BoxCop data folder path cannot be written to npm configuration')
    text = read_config(path)
    if BEGIN in text or END in text:
        if _block(shell) not in text or not receipt.exists():
            raise ValueError('Existing BoxCop install-script routing needs manual review')
        if _setting(text) != shell:
            raise ValueError('Another script-shell setting overrides BoxCop install-script protection')
        return
    if _setting(text) is not None:
        raise ValueError('Existing npm script-shell setting preserved; remove it to enable install-script protection')
    newline = bool(text and not text.endswith('\n'))
    atomic_write(receipt, canonical({'created': not path.exists(), 'added_newline': newline}))
    atomic_write(path, (text + ('\n' if newline else '') + _block(shell)).encode())


def disable_routing(home, state):
    path, receipt = Path(home) / '.npmrc', Path(state) / 'npm-script-shell.json'
    text = read_config(path)
    if BEGIN not in text and END not in text:
        receipt.unlink(missing_ok=True)
        return
    blocks = re.findall(re.escape(BEGIN) + r'\nscript-shell=[^\n]*\n' + re.escape(END) + r'\n', text)
    if len(blocks) != 1 or text.count(BEGIN) != 1 or text.count(END) != 1:
        raise ValueError('BoxCop install-script routing was edited; remove the marked block manually')
    value = json.loads(receipt.read_bytes()) if receipt.exists() else {}
    suffix = text.endswith(blocks[0])
    restored = text.replace(blocks[0], '', 1)
    if suffix and value.get('added_newline') and restored.endswith('\n'):
        restored = restored[:-1]
    if not restored and value.get('created'):
        path.unlink()
    else:
        atomic_write(path, restored.encode())
    receipt.unlink(missing_ok=True)


def routing_status(home, shell):
    text = read_config(Path(home) / '.npmrc')
    return {'managed': BEGIN in text or END in text, 'configured': _block(str(shell)) in text and _setting(text) == str(shell)}


# --- wrapper and sandbox profile -------------------------------------------

def _sh(value):
    return "'" + str(value).replace("'", "'\\''") + "'"


def wrapper(directory, port=PORT, registry_port=REGISTRY_PORT):
    """The script-shell. npm runs `<this> -c "<script>"` for every lifecycle script.

    Only dependency install scripts are contained: an install-family event whose
    working directory is inside node_modules or npm's cache (git dependencies).
    The project's own scripts, `npm run`, `npm test` and `npx` pass through.
    """
    return f'''#!/bin/sh
# Managed by BoxCop install-script protection. Turn it off in BoxCop; do not edit.
D={_sh(directory)}
contain=
case "$npm_lifecycle_event" in
  preinstall|install|postinstall|preprepare|prepare|postprepare|prepublish|prepack|postpack)
    case "$PWD/" in */node_modules/*) contain=1;; esac
    if [ -z "$contain" ] && [ -n "$npm_config_cache" ]; then
      case "$PWD/" in "$npm_config_cache"/*) contain=1;; esac
    fi;;
esac
[ -n "$contain" ] || exec /bin/sh "$@"
# A sandbox cannot be nested. Inside an agent's own sandbox (or one of ours),
# that outer sandbox already applies to this script and all its children.
{SANDBOX} -p '(version 1)(allow default)' /usr/bin/true 2>/dev/null || exec /bin/sh "$@"
token=$(/usr/bin/curl -s -m 2 --unix-socket "$D/control.sock" \\
  --data-urlencode "package=$npm_package_name" --data-urlencode "version=$npm_package_version" \\
  --data-urlencode "event=$npm_lifecycle_event" --data-urlencode "project=${{npm_config_local_prefix:-$INIT_CWD}}" \\
  http://boxcop/run 2>/dev/null)
case "$token" in ''|*[!0-9a-f]*) token=offline;; esac
proxy="http://boxcop:$token@127.0.0.1:{port}"
export HTTP_PROXY="$proxy" HTTPS_PROXY="$proxy" http_proxy="$proxy" https_proxy="$proxy"
export npm_config_proxy="$proxy" npm_config_https_proxy="$proxy" NODE_USE_ENV_PROXY=1
export NO_PROXY="127.0.0.1:{registry_port}" no_proxy="127.0.0.1:{registry_port}" npm_config_noproxy="127.0.0.1:{registry_port}"
exec {SANDBOX} -f "$D/profile.sb" /bin/sh "$@"
'''


def _sb(value):
    return '"' + str(value).replace('\\', '\\\\').replace('"', '\\"') + '"'


def profile(home, directory, port=PORT, registry_port=REGISTRY_PORT):
    """Deny all network except the two loopback listeners, and deny writes that
    would disable this protection or start code later outside the sandbox."""
    home, directory = os.path.realpath(home), os.path.realpath(directory)
    files = ['.npmrc', '.zshenv', '.zshrc', '.zprofile', '.zlogin', '.bashrc', '.bash_profile', '.bash_login', '.profile']
    folders = [directory, home + '/Library/LaunchAgents', home + '/.config/fish']
    return '\n'.join([
        '(version 1)', '(allow default)', '(deny network*)',
        f'(allow network-outbound (remote ip "localhost:{port}") (remote ip "localhost:{registry_port}"))',
        '(deny file-write*',
        *('  (literal ' + _sb(home + '/' + name) + ')' for name in files),
        *('  (subpath ' + _sb(folder) + ')' for folder in folders),
        ')', ''])


def sandbox_available():
    if sys.platform != 'darwin' or not os.access(SANDBOX, os.X_OK):
        return False
    try:
        return subprocess.run([SANDBOX, '-p', '(version 1)(allow default)', '/usr/bin/true'],
                              capture_output=True, timeout=10).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


# --- policy and run context ------------------------------------------------

def initiator(pid):
    """Best-effort label for the coding agent above a live install. Display only."""
    try:
        rows = subprocess.run(['/bin/ps', '-axo', 'pid=,ppid=,command='], capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    table = {}
    for row in rows.splitlines():
        parts = row.split(None, 2)
        if len(parts) == 3 and parts[0].isdigit() and parts[1].isdigit():
            table[int(parts[0])] = (int(parts[1]), parts[2])
    for _ in range(32):
        if pid not in table:
            return None
        pid, command = table[pid]
        for label, pattern in AGENTS:
            if pattern.search(command[:512]):
                return label
    return None


class Guard:
    """Destination decisions for contained scripts. Thread-safe; bounded memory."""
    def __init__(self, directory, *, allow_private=False, ports=(80, 443)):
        self.path = Path(directory) / 'exceptions.json'
        self.allow_private, self.ports = allow_private, ports
        self.lock = threading.Lock()
        self.runs = OrderedDict()
        self.blocked = deque(maxlen=50)
        self.exceptions = set()
        try:
            for row in json.loads(self.path.read_bytes()):
                if PACKAGE.fullmatch(row['package']) and HOST.fullmatch(row['host']):
                    self.exceptions.add((row['package'], row['host']))
        except (OSError, ValueError, KeyError, TypeError):
            pass  # Missing or damaged exceptions mean fewer destinations, never more.

    def register(self, package, version, event, project, agent=None):
        token = secrets.token_hex(16)
        run = dict(package=package[:214] if PACKAGE.fullmatch(package or '') else None, version=(version or '')[:64] or None,
                   event=(event or '')[:32] or None, project=(project or '')[:1024] or None, agent=agent, started=time.monotonic())
        with self.lock:
            self.runs[token] = run
            while len(self.runs) > 512 or (self.runs and next(iter(self.runs.values()))['started'] < time.monotonic() - 7200):
                self.runs.popitem(last=False)
        return token

    def decide(self, token, host, port):
        """Return (allowed, run). Called before any upstream connection exists."""
        host = (host or '').lower().rstrip('.')
        with self.lock:
            run = self.runs.get(token)
            package = run['package'] if run else None
            allowed = port in self.ports and bool(HOST.fullmatch(host)) and (
                host in DEFAULT_HOSTS or host in PACKAGE_HOSTS.get(package, ()) or (package, host) in self.exceptions)
            if not allowed:
                self._record(run or {}, host[:253], port)
        return allowed, run

    def _record(self, run, host, port):
        key = (run.get('package'), run.get('version'), host, port)
        for item in self.blocked:
            if item['key'] == key:
                item['count'] += 1
                item['time'] = datetime.now(timezone.utc).isoformat(timespec='seconds')
                return
        name = (run['package'] + ('@' + run['version'] if run.get('version') else '')) if run.get('package') else None
        script = (run.get('event') or 'install') + ' script'
        subject = (f"{run['agent']} started an install of {name}, whose {script}" if run.get('agent') and name
                   else f"The {script} of {name}" if name else 'A package install script')
        self.blocked.appendleft(dict(key=key, id=secrets.token_hex(8), time=datetime.now(timezone.utc).isoformat(timespec='seconds'),
            package=run.get('package'), package_version=run.get('version'), event=run.get('event'), agent=run.get('agent'),
            project=run.get('project'), host=host, port=port, count=1,
            message=f'{subject} tried to connect to {host or "an unnamed destination"}. BoxCop blocked the connection because '
                    'package install scripts can only reach approved destinations.'))

    def change(self, action, package, host):
        host = host.lower().rstrip('.')
        if not PACKAGE.fullmatch(package) or not HOST.fullmatch(host):
            raise ValueError('Choose a package name and a destination hostname')
        with self.lock:
            (self.exceptions.add if action == 'allow' else self.exceptions.discard)((package, host))
            if action == 'allow':
                for item in [item for item in self.blocked if item['package'] == package and item['host'] == host]:
                    self.blocked.remove(item)
            atomic_write(self.path, canonical([dict(package=p, host=h) for p, h in sorted(self.exceptions)]))

    def snapshot(self):
        with self.lock:
            return ([{key: value for key, value in item.items() if key != 'key'} for item in self.blocked],
                    [dict(package=p, host=h) for p, h in sorted(self.exceptions)])

    def address(self, host, port):
        """Resolve here, refuse non-public targets, and connect to the checked address."""
        for *_, sockaddr in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM):
            if self.allow_private or ipaddress.ip_address(sockaddr[0]).is_global:
                return sockaddr[0]
        raise OSError('No public address')


# --- proxy and control listeners -------------------------------------------

def _relay(left, right):
    sockets = [left, right]
    while True:
        ready, _, failed = select.select(sockets, [], sockets, 120)
        if failed or not ready:
            return
        for source in ready:
            data = source.recv(65536)
            if not data:
                return
            (right if source is left else left).sendall(data)


class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.0'

    def log_message(self, *_):
        pass  # Destinations are recorded only when blocked; never payloads or credentials.

    def setup(self):
        super().setup()
        self.connection.settimeout(30)

    def _token(self):
        scheme, _, value = self.headers.get('Proxy-Authorization', '').partition(' ')
        try:
            return base64.b64decode(value, validate=True).decode().partition(':')[2] if scheme.lower() == 'basic' else None
        except ValueError:
            return None

    def _refuse(self, status, message):
        body = canonical({'error': 'BOXCOP_INSTALL_SCRIPT_NETWORK', 'message': message})
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _open(self, host, port):
        """Decide, then connect. Returns a socket holding one server slot, or None."""
        guard = self.server.guard
        if not self.server.slots.acquire(blocking=False):
            self._refuse(503, 'BoxCop install-script proxy is busy')
            return None
        upstream = None
        try:
            allowed, _ = guard.decide(self._token(), host, port)
            if not allowed:
                self._refuse(403, 'BoxCop blocked this destination for package install scripts. Approve it in BoxCop if it is expected.')
                return None
            try:
                upstream = socket.create_connection((guard.address(host, port), port), timeout=15)
            except (OSError, ValueError):
                self._refuse(502, 'Destination unavailable')
            return upstream
        finally:
            if upstream is None:
                self.server.slots.release()

    def _target(self, netloc, default):
        parts = urlsplit('//' + netloc)
        return parts.hostname, parts.port or default

    def do_CONNECT(self):
        try:
            host, port = self._target(self.path, 443)
        except ValueError:
            return self._refuse(400, 'Unsupported request target')
        upstream = self._open(host, port)
        if upstream is None:
            return
        try:
            with upstream:
                self.wfile.write(b'HTTP/1.1 200 Connection established\r\n\r\n')
                self.wfile.flush()
                _relay(self.connection, upstream)
        except OSError:
            pass
        finally:
            self.server.slots.release()

    def do_GET(self):
        try:
            parts = urlsplit(self.path)
            host, port = self._target(parts.netloc, 80)
            length = int(self.headers.get('Content-Length') or 0)
        except ValueError:
            return self._refuse(400, 'Unsupported request target')
        if parts.scheme != 'http' or not host or self.headers.get('Transfer-Encoding') or not 0 <= length <= 64 * 1024 * 1024:
            return self._refuse(400, 'Unsupported proxy request')
        upstream = self._open(host, port)
        if upstream is None:
            return
        try:
            with upstream:
                headers = ''.join(f'{name}: {value}\r\n' for name, value in self.headers.items()
                                  if name.lower() not in ('proxy-authorization', 'proxy-connection', 'connection', 'keep-alive'))
                target = (parts.path or '/') + ('?' + parts.query if parts.query else '')
                upstream.sendall(f'{self.command} {target} HTTP/1.0\r\n{headers}Connection: close\r\n\r\n'.encode('latin-1'))
                while length:
                    data = self.rfile.read(min(length, 65536))
                    if not data:
                        break
                    upstream.sendall(data)
                    length -= len(data)
                upstream.settimeout(120)
                while data := upstream.recv(65536):
                    self.wfile.write(data)
        except OSError:
            pass
        finally:
            self.server.slots.release()

    do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_GET


class ProxyServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, guard, port=PORT):
        self.guard = guard
        self.slots = threading.BoundedSemaphore(64)
        super().__init__(('127.0.0.1', port), ProxyHandler)


class ControlHandler(BaseHTTPRequestHandler):
    """Registers a contained run. Unreachable from inside the sandbox, so a
    script cannot claim another package's approved destinations."""
    def log_message(self, *_):
        pass

    def do_POST(self):
        try:
            length = int(self.headers.get('Content-Length') or 0)
            if self.path != '/run' or not 0 <= length <= 8192:
                raise ValueError
            form = {key: values[0] for key, values in parse_qs(self.rfile.read(length).decode()).items()}
            agent = None
            if sys.platform == 'darwin':
                # LOCAL_PEERPID: the wrapper's curl, a live child of the npm process tree.
                peer = struct.unpack('i', self.connection.getsockopt(0, 2, 4))[0]
                agent = self.server.initiator(peer)
            body = self.server.guard.register(form.get('package'), form.get('version'), form.get('event'), form.get('project'), agent).encode()
            self.send_response(200)
        except (ValueError, OSError):
            body = b''
            self.send_response(400)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class ControlServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True

    def __init__(self, guard, path, initiator=initiator):
        self.guard, self.initiator, path = guard, initiator, str(path)
        if len(path.encode()) > 100:
            raise ValueError('The BoxCop data folder path is too long for install-script protection')
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        super().__init__(path, ControlHandler)
        os.chmod(path, 0o600)

    def get_request(self):
        request, _ = super().get_request()
        return request, ('local', 0)


# --- engine-owned runtime --------------------------------------------------

class ScriptRuntime:
    def __init__(self, *, home=None, directory=None, port=PORT, allow_private=False, ports=(80, 443), available=sandbox_available, initiator=initiator):
        self.home = Path(home) if home is not None else Path.home()
        self.directory = Path(directory) if directory is not None else state_directory()
        self.port, self.allow_private, self.ports, self.available, self.initiator = port, allow_private, ports, available, initiator
        self.shell = self.directory / 'boxcop-script-shell'
        self.lock = threading.RLock()
        self.guard = self.proxy = self.control = None
        self.message = None
        self.initialized = self.closed = False

    def status(self):
        with self.lock:
            try:
                route = routing_status(self.home, self.shell)
            except (OSError, ValueError):
                route = {'managed': True, 'configured': False}
            listening = self.proxy is not None
            blocked, exceptions = self.guard.snapshot() if self.guard else ([], [])
            summary = self.message or (
                'Install scripts can only reach approved destinations' if listening and route['configured']
                else 'Install scripts are contained with no network until BoxCop protection starts' if route['configured']
                else 'Install-script routing needs review' if route['managed'] else 'Ready to enable')
            return dict(routed=route['managed'], active=listening and route['configured'], summary=summary,
                        blocked=blocked, exceptions=exceptions)

    def command(self, action, package='', host=''):
        with self.lock:
            if not self.closed:
                try:
                    if action != 'status':
                        self.message = None
                    if action == 'status' and not self.initialized:
                        self.initialized = True
                        # Only routing the user previously enabled is resumed.
                        if routing_status(self.home, self.shell)['managed']:
                            action = 'enable'
                    if action == 'enable':
                        self._enable()
                    elif action == 'disable':
                        # Restore plain npm behavior before stopping the listeners.
                        disable_routing(self.home, self.directory)
                        self._stop()
                        self.message = None
                    elif action in ('allow', 'revoke'):
                        (self.guard or Guard(self.directory)).change(action, package, host)
                except ValueError as error:
                    self.message = str(error)
                except OSError as error:
                    self.message = (f'Port {self.port} is already in use; close the other instance of BoxCop and retry'
                                    if error.errno in (48, 98) else 'Install-script protection failed (' + type(error).__name__ + '). Retry or disable it.')
            return self.status()

    def _enable(self):
        if not self.available():
            raise ValueError('Install-script protection needs the macOS sandbox, which is unavailable here')
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Rewritten on every start so an app update refreshes both files.
        atomic_write(self.directory / 'profile.sb', profile(self.home, self.directory, self.port).encode())
        # Executable before it is renamed into place: npm may run it at any moment.
        temporary = self.directory / ('.boxcop-script-shell.' + secrets.token_hex(4))
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(wrapper(self.directory, self.port).encode())
            os.fchmod(stream.fileno(), 0o755)
        os.replace(temporary, self.shell)
        if self.proxy is None:
            guard = Guard(self.directory, allow_private=self.allow_private, ports=self.ports)
            proxy = ProxyServer(guard, self.port)
            try:
                control = ControlServer(guard, self.directory / 'control.sock', self.initiator)
            except BaseException:
                proxy.server_close()
                raise
            self.guard, self.proxy, self.control = guard, proxy, control
            for server in (proxy, control):
                threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            enable_routing(self.home, self.directory, self.shell)
        except Exception:
            self._stop()
            raise
        self.message = None

    def _stop(self):
        proxy, control, self.proxy, self.control = self.proxy, self.control, None, None
        for server in (proxy, control):
            if server:
                server.shutdown()
                server.server_close()
        if control:
            try:
                os.unlink(self.directory / 'control.sock')
            except OSError:
                pass

    def close(self):
        # Routing stays: with BoxCop stopped, contained scripts simply have no network.
        with self.lock:
            self.closed = True
            self._stop()
