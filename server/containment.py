"""Run one command contained: `--contain [--allow-host H]... -- <command> [args...]`.

The command and everything it starts run under a macOS sandbox profile:

- Network: only this run's own loopback proxy, which connects to the hosts named
  with `--allow-host` and nothing else. With no `--allow-host` there is no network.
- Writes are denied to shell startup files, npm and git configuration, login items
  and coding-agent configuration folders, so the command cannot leave something
  behind that runs later outside the sandbox.
- Reads are denied to the usual credential folders (SSH, cloud CLIs, GnuPG, keychains).

Everything else behaves as usual, and the command's exit code is passed through.
Refused connections are recorded so they appear in the app's activity list.

Limits: the proxy only works for programs that honor the standard proxy
environment variables; other programs simply have no network. A program can
still misuse a host you allowed, and can read files outside the denied folders.
"""
import os
from pathlib import Path
import secrets
import signal
import subprocess
import sys
import tempfile
import threading

from .event_log import EventLog, private_directory
from .package_scripts import (CONTAINMENT_LOG, HOST, SANDBOX, Guard, ProxyServer, _sb, initiator, sandbox_available,
                              state_directory)

UNAVAILABLE = 126  # The shell's code for "found but could not be run".
# Relative to the home folder.
WRITE_DENIED_FILES = ('.npmrc', '.yarnrc', '.yarnrc.yml', '.gitconfig', '.zshenv', '.zshrc', '.zprofile', '.zlogin',
                      '.zlogout', '.bashrc', '.bash_profile', '.bash_login', '.bash_logout', '.profile',
                      '.claude.json')
WRITE_DENIED_FOLDERS = ('Library/LaunchAgents', '.config/fish', '.config/git', '.claude', '.codex', '.cursor',
                        '.gemini', '.config/opencode', '.ssh')
READ_DENIED_FILES = ('.netrc', '.git-credentials', '.pypirc', '.docker/config.json')
READ_DENIED_FOLDERS = ('.ssh', '.aws', '.gnupg', '.config/gcloud', '.azure', '.kube', '.config/gh',
                       'Library/Keychains')


def run_profile(home, state, port):
    """Sandbox profile for one contained run. `state` is BoxCop's own protection folder."""
    home, state = os.path.realpath(home), os.path.realpath(state)
    literal = lambda names: ['  (literal ' + _sb(home + '/' + name) + ')' for name in names]
    subpath = lambda names: ['  (subpath ' + _sb(home + '/' + name) + ')' for name in names]
    return '\n'.join([
        '(version 1)', '(allow default)', '(deny network*)',
        f'(allow network-outbound (remote ip "localhost:{port}"))',
        '(deny file-write*', *literal(WRITE_DENIED_FILES), *subpath(WRITE_DENIED_FOLDERS),
        # BoxCop's own protection state: the contained program must not approve
        # destinations for itself or replace the verified package list.
        '  (subpath ' + _sb(state) + ')',
        '  (subpath ' + _sb(os.path.join(os.path.dirname(state), 'package-protection')) + ')', ')',
        '(deny file-read*', *literal(READ_DENIED_FILES), *subpath(READ_DENIED_FOLDERS), ')', ''])


def parse_host(value):
    """`host` allows ports 80 and 443; `host:port` allows only that port."""
    host, _, port = value.strip().lower().rstrip('.').partition(':')
    if not HOST.fullmatch(host) or (port and (not port.isdigit() or not 0 < int(port) < 65536)):
        raise ValueError('Use a hostname, optionally followed by :port')
    return host, int(port) if port else None


class RunGuard(Guard):
    """Destination decisions for one contained run: its own allowlist and nothing else."""
    error = 'BOXCOP_CONTAINED_RUN_NETWORK'
    refusal = 'BoxCop blocked this destination for a contained run. Allow the host for this run if it is expected.'

    def __init__(self, allowed, *, program, agent=None, log=None, allow_private=False):
        self.allowed, self.program, self.agent, self.log = frozenset(allowed), program, agent, log
        self.allow_private = allow_private
        self.token = secrets.token_hex(16)
        self.lock = threading.Lock()
        self.blocked = []

    def decide(self, token, host, port):
        host = (host or '').lower().rstrip('.')
        allowed = (token == self.token and bool(HOST.fullmatch(host))
                   and ((host, port) in self.allowed or (port in (80, 443) and (host, None) in self.allowed)))
        if not allowed:
            host = host[:253]
            with self.lock:
                first = (host, port) not in self.blocked and len(self.blocked) < 256
                if first:
                    self.blocked.append((host, port))
            if first and self.log is not None:
                self.log.append(dict(
                    kind='run', program=self.program, agent=self.agent, host=host, port=port,
                    message=f'A contained run of {self.program} tried to connect to {host or "an unnamed destination"}. '
                            'BoxCop blocked the connection because that destination was not allowed for this run.'),
                    repeat_of='|'.join(('run', self.program, host, str(port))))
        return allowed, None


def run(command, allow_hosts=(), *, home=None, directory=None, allow_private=False, env=None, cwd=None):
    """Run `command` contained and return its exit code. Never runs it uncontained."""
    if not command:
        raise ValueError('A command is required')
    home = Path(home) if home is not None else Path.home()
    directory = Path(directory) if directory is not None else state_directory()
    if not sandbox_available():
        sys.stderr.write('BoxCop could not start the macOS sandbox here, so the command was not run.\n')
        return UNAVAILABLE
    program = os.path.basename(command[0])[:64] or 'a command'
    private_directory(directory)
    guard = RunGuard((parse_host(value) for value in allow_hosts), program=program, agent=initiator(os.getpid()),
                     log=EventLog(directory / CONTAINMENT_LOG), allow_private=allow_private)
    proxy = ProxyServer(guard, 0)
    port = proxy.server_address[1]
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory(prefix='boxcop-contain-') as temporary:
            profile_path = Path(temporary) / 'profile.sb'
            profile_path.write_text(run_profile(home, directory, port))
            address = f'http://boxcop:{guard.token}@127.0.0.1:{port}'
            environment = dict(os.environ if env is None else env)
            for name in ('NO_PROXY', 'no_proxy', 'npm_config_noproxy'):
                environment.pop(name, None)
            environment.update(HTTP_PROXY=address, HTTPS_PROXY=address, http_proxy=address, https_proxy=address,
                               ALL_PROXY=address, all_proxy=address, npm_config_proxy=address,
                               npm_config_https_proxy=address, NODE_USE_ENV_PROXY='1', BOXCOP_CONTAINED='1')
            try:
                child = subprocess.Popen([SANDBOX, '-f', str(profile_path), *command], env=environment, cwd=cwd)
            except OSError:
                sys.stderr.write('BoxCop could not start the command.\n')
                return UNAVAILABLE
            # The terminal delivers Ctrl-C to the child as well; wait for it to finish.
            previous = {number: signal.signal(number, lambda number, _: child.send_signal(number))
                        for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)} if threading.current_thread() is threading.main_thread() else {}
            try:
                code = child.wait()
            finally:
                for number, handler in previous.items():
                    signal.signal(number, handler)
            return code if code >= 0 else 128 - code
    finally:
        proxy.shutdown()
        proxy.server_close()


def main(arguments):
    hosts, index = [], 0
    while index < len(arguments) and arguments[index] != '--':
        if arguments[index] != '--allow-host' or index + 1 >= len(arguments):
            break
        hosts.append(arguments[index + 1])
        index += 2
    command = arguments[index + 1:] if index < len(arguments) and arguments[index] == '--' else []
    try:
        if not command:
            raise ValueError('Usage: --contain [--allow-host HOST[:PORT]]... -- COMMAND [ARGUMENTS...]')
        for value in hosts:
            parse_host(value)
    except ValueError as error:
        sys.stderr.write(str(error) + '\n')
        return 2
    return run(command, hosts)
