"""Registry protection owned by the app's existing engine, never by launchd."""
import base64
import os
from pathlib import Path
import plistlib
import subprocess
import threading

from . import package_routing as routing
from .local_package_policy import state_directory
from .package_channel import bundled_channel, bootstrap
from .package_intelligence import PolicyStore
from .package_proxy import Firewall, RegistryServer, refresh


def remove_legacy_agent(home):
    path = Path(home) / 'Library/LaunchAgents/com.boxcop.package-protection.plist'
    if not path.exists():
        return
    value = plistlib.loads(path.read_bytes())
    if value.get('Label') != 'com.boxcop.package-protection' or '--package-protection' not in value.get('ProgramArguments', []):
        raise ValueError('The old package startup entry was changed; review it before migrating')
    result = subprocess.run(['/bin/launchctl', 'bootout', f'gui/{os.getuid()}/com.boxcop.package-protection'],
                            capture_output=True, timeout=10)
    if result.returncode:
        # A plist left by a failed bootstrap is removable even when not loaded.
        probe = subprocess.run(['/bin/launchctl', 'print', f'gui/{os.getuid()}/com.boxcop.package-protection'],
                               capture_output=True, timeout=10)
        if probe.returncode == 0:
            raise ValueError('Could not stop the old package background service; retry migration')
    path.unlink()


class PackageRuntime:
    def __init__(self, *, home=None, directory=None, channel=None, port=8794, migrate=remove_legacy_agent):
        self.home = Path(home) if home is not None else Path.home()
        self.directory = Path(directory) if directory is not None else state_directory()
        self.channel = bundled_channel() if channel is None else channel
        self.port, self.migrate = port, migrate
        self.lock = threading.RLock()
        self.busy = False
        self.message = 'Ready to enable' if self.channel else 'Feed not configured in this build'
        self.server = None
        self.store = None
        self.updater = None
        self.closed = threading.Event()
        self.worker = None
        self.initialized = False

    def status(self):
        with self.lock:
            try:
                route = routing.status(self.home)
                routed, configured = route['managed'], route['configured']
            except (OSError, ValueError):
                routed, configured = True, False
            policy = self.store.status() if self.store else {}
            available = self.server is not None and not self.closed.is_set()
            message = self.message
            if not self.busy and available and configured:
                message = 'npm and pnpm protection enabled in BoxCop'
            elif not self.busy and routed and not available and message == 'Ready to enable':
                message = 'Package routing is enabled, but BoxCop protection needs to be started'
            return dict(configured=self.channel is not None, routed=routed, active=available and configured,
                busy=self.busy, summary=message, stale=policy.get('stale', True),
                generated_at=policy.get('generated_at'), update_error=policy.get('update_error'))

    def command(self, operation):
        with self.lock:
            if operation == 'status' and not self.initialized:
                self.initialized = True
                # Only routing that the user previously enabled is resumed.
                if routing.status(self.home)['managed']:
                    operation = 'enable'
                else:
                    operation = 'migrate'
            if operation != 'status' and not self.busy and not self.closed.is_set():
                self.busy = True
                self.message = {'enable': 'Starting package protection…', 'disable': 'Disabling package routing…',
                                'migrate': 'Checking package protection…'}[operation]
                self.worker = threading.Thread(target=self._action, args=(operation,), daemon=True)
                self.worker.start()
            return self.status()

    def _action(self, operation):
        try:
            if operation == 'disable':
                # Restore installs before stopping the listener; retain verified policy.
                routing.disable(self.home, self.directory)
                self._stop_server()
                self.migrate(self.home)
                self.message = 'Package routing disabled'
            else:
                self.migrate(self.home)
                if operation == 'enable':
                    self._enable()
                else:
                    self.message = 'Ready to enable' if self.channel else 'Feed not configured in this build'
        except Exception as error:
            with self.lock:
                self.message = str(error) if isinstance(error, ValueError) else (
                    'Port 8794 is already in use; close the other instance of BoxCop and retry' if isinstance(error, OSError) and error.errno in (48, 98)
                    else 'Package protection failed (' + type(error).__name__ + '). Retry or disable routing.')
        finally:
            with self.lock:
                self.busy = False

    def _enable(self):
        if not self.channel:
            raise ValueError('This build has no provisioned package feed')
        public = base64.b64decode(self.channel['public_key'], validate=True)
        pin = self.directory / 'public.key'
        if pin.exists() and pin.read_bytes() != public:
            raise ValueError('Package signing key changed; explicit key rotation is required')
        with self.lock:
            if self.server is not None:
                routing.enable(self.home, self.directory)
                return
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        store = self.store or PolicyStore(self.directory / 'policy.json', public)
        if not store.policy or store.policy.payload['sequence'] < self.channel['minimum_sequence']:
            self.message = 'Downloading and verifying the malware list…'
            bootstrap(self.channel, self.directory)
            store = PolicyStore(self.directory / 'policy.json', public)
        if not pin.exists():
            from .package_intelligence import atomic_write
            atomic_write(pin, public)
        key_path = self.directory / 'artifact-link.key'
        try:
            fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(os.urandom(32))
        except FileExistsError:
            pass
        secret = key_path.read_bytes()
        if len(secret) != 32:
            raise ValueError('Invalid package artifact key')
        server = RegistryServer(Firewall(store, secret), self.port)
        with self.lock:
            if self.closed.is_set():
                server.server_close()
                server.firewall.upstream.client.close()
                return
            self.server, self.store = server, store
            threading.Thread(target=server.serve_forever, daemon=True).start()
            try:
                routing.enable(self.home, self.directory)
            except Exception:
                self._stop_server()
                raise
        self.message = 'npm and pnpm protection enabled in BoxCop'
        # Cached verified policy is usable immediately. Network refresh never
        # delays readiness or the engine's inherited-pipe request loop.
        if self.updater is None:
            self.updater = threading.Thread(target=self._updates, daemon=True)
            self.updater.start()

    def _updates(self):
        while not self.closed.is_set():
            if self.server is not None:
                refresh(self.store, self.channel['url'])
            if self.closed.wait(900):
                return

    def _stop_server(self):
        with self.lock:
            server, self.server = self.server, None
        if server:
            server.shutdown()
            server.server_close()
            server.firewall.upstream.client.close()

    def close(self):
        # Keep routing in place: quitting BoxCop intentionally makes protected
        # package installs unavailable until it is running again or disabled.
        self.closed.set()
        self._stop_server()
