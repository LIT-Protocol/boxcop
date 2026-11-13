"""App-owned inference. Only pinned weights leave the bundle; evidence stays on loopback."""
from hashlib import sha256
import fcntl
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import subprocess
import sys
from threading import Event, Lock
import time
import urllib.request

MODEL = 'Qwen3.5-4B-Q4_K_M'
MODEL_REVISION = 'e87f176479d0855a907a41277aca2f8ee7a09523'
MODEL_SHA256 = '00fe7986ff5f6b463e62455821146049db6f9313603938a70800d1fb69ef11a4'
MODEL_BYTES = 2740937888
MODEL_URL = f'https://huggingface.co/unsloth/Qwen3.5-4B-GGUF/resolve/{MODEL_REVISION}/{MODEL}.gguf'
# Free space that must remain after the model is downloaded.
DISK_RESERVE_BYTES = 4 * 1000 ** 3
# One model runtime per user, whichever BoxCop process asks. RUNTIME_LOCK is held by
# the engine that owns the runtime. SERVER_LOCK is inherited by llama-server itself,
# so a runtime that outlives its engine is still seen, and is stopped before another starts.
RUNTIME_LOCK, SERVER_LOCK, INSTALL_LOCK = 'runtime.lock', 'server.lock', 'install.lock'
BUSY = 'Another copy of BoxCop is already running the triage model. Quit the other copy and try again.'
MISSING = 'The triage model runtime is missing from this copy of BoxCop.'
DOWNLOAD_FAILED = 'The triage model download failed or did not verify. BoxCop will try again in a few minutes.'
FAILED = 'The triage model could not be started. BoxCop will try again in a few minutes.'


class SetupError(RuntimeError):
    """A setup failure whose message is safe and useful to show."""


def model_directory():
    return Path.home() / 'Library/Application Support/BoxCop/models/workflow'


def _gigabytes(count):
    return f'{count / 1000 ** 3:.1f} GB'


def _lock(path):
    """An exclusive lock on `path` without waiting: the open descriptor, or None when held elsewhere."""
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        return None
    return fd


def remove_model(directory=None, *, patience=3):
    """Delete the downloaded model. Returns the bytes freed, or None when it is in use.

    Nothing is deleted while any process runs the model or is installing it. A
    runtime this process has just stopped gets `patience` seconds to let go.
    """
    directory = Path(directory) if directory else model_directory()
    if directory.is_symlink() or not directory.is_dir():
        return 0
    held, deadline = [], time.monotonic() + patience
    try:
        for name in (RUNTIME_LOCK, SERVER_LOCK, INSTALL_LOCK):
            while (fd := _lock(directory / name)) is None:
                if time.monotonic() >= deadline:
                    return None
                time.sleep(.05)
            held.append(fd)
        freed = 0
        for path in directory.iterdir():
            if (path.suffix in ('.gguf', '.part')) and not path.is_dir():
                size = path.lstat().st_size
                path.unlink()
                freed += size
        return freed
    finally:
        for fd in held:
            os.close(fd)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs): return None


class LocalInference:
    def __init__(self, *, directory=None, executable=None, reserve_bytes=DISK_RESERVE_BYTES, disk_usage=None):
        root = Path(__file__).resolve().parents[1]
        self.directory = Path(directory) if directory else model_directory()
        self.reserve_bytes, self.disk_usage = reserve_bytes, disk_usage
        self._runtime_lock = None
        self.executable = Path(executable) if executable else (
            Path(sys.executable).parent.parent / 'inference/llama-server' if getattr(sys, 'frozen', False)
            else root / '.local/inference/llama-server')
        self._closed = Event()
        self._lock = Lock()
        self._download = None
        self._server = None
        self._verified = None
        self._retry_at = 0
        self._status = {'state': 'waiting', 'downloadedBytes': 0, 'totalBytes': MODEL_BYTES, 'message': None}
        self._key = secrets.token_urlsafe(32)
        self._port = None
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def status(self):
        with self._lock: return dict(self._status)

    def _set(self, state, downloaded=0, message=None):
        with self._lock:
            self._status = {'state': state, 'downloadedBytes': downloaded, 'totalBytes': MODEL_BYTES, 'message': message}

    def close(self):
        self._closed.set()
        with self._lock:
            for process in (self._download, self._server):
                if process and process.poll() is None:
                    process.kill()
                    process.wait(timeout=2)
        self._release()

    def _release(self):
        with self._lock:
            fd, self._runtime_lock = self._runtime_lock, None
        if fd is not None:
            os.close(fd)

    def _claim(self):
        """Become the one process that runs the model. Returns the lock llama-server inherits."""
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self._lock:
            self._check()
            if self._runtime_lock is None:
                self._runtime_lock = _lock(self.directory / RUNTIME_LOCK)
            if self._runtime_lock is None:
                raise SetupError(BUSY)
        fd = _lock(self.directory / SERVER_LOCK)
        if fd is None:
            # No engine owns the runtime (this one holds that lock), yet a server still
            # runs: its engine died. Stop it rather than start a second one beside it.
            self._stop_orphan()
            deadline = time.monotonic() + 5
            while fd is None and time.monotonic() < deadline:
                self._closed.wait(.1); self._check()
                fd = _lock(self.directory / SERVER_LOCK)
            if fd is None:
                raise SetupError(BUSY)
        return fd

    def _stop_orphan(self):
        try:
            pid = int((self.directory / SERVER_LOCK).read_text()[:16])
            listing = subprocess.run(['/bin/ps', '-p', str(pid), '-o', 'uid=', '-o', 'comm='], capture_output=True,
                                     text=True, timeout=5).stdout.split(None, 1)
            # Only this user's llama-server; the number alone could now name another program.
            if len(listing) == 2 and int(listing[0]) == os.getuid() and Path(listing[1].strip()).name == self.executable.name:
                os.kill(pid, signal.SIGKILL)
        except (OSError, ValueError, subprocess.SubprocessError):
            pass

    def _check(self):
        if self._closed.is_set(): raise RuntimeError('Inference stopped')

    def _spawn(self, command, *, download=False, env=None, keep=()):
        with self._lock:
            self._check()
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE if download else subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, env=env, pass_fds=keep)
            if download: self._download = process
            else: self._server = process
            return process

    def _valid(self, path):
        if path.is_symlink() or not path.is_file() or path.stat().st_size != MODEL_BYTES: return False
        self._set('verifying')
        digest = sha256()
        with path.open('rb') as model:
            while chunk := model.read(1024 * 1024):
                self._check(); digest.update(chunk)
        return digest.hexdigest() == MODEL_SHA256

    @staticmethod
    def _identity(path):
        info = path.stat()
        return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

    def _model(self):
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if any(p.is_symlink() for p in (self.directory, *self.directory.parents)):
            raise ValueError('Invalid model directory')
        os.chmod(self.directory, 0o700)
        target = self.directory / (MODEL_SHA256 + '.gguf')
        if self._verified and target.is_file() and not target.is_symlink() and self._identity(target) == self._verified: return target
        # Serialize installers across sidecars/app instances, without blocking IPC.
        fd = os.open(self.directory / INSTALL_LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as lock:
            while True:
                try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB); break
                except BlockingIOError:
                    self._set('waiting_for_download'); self._closed.wait(.2); self._check()
            if not self._valid(target):
                partial = self.directory / 'download.part'
                partial.unlink(missing_ok=True)
                free, needed = (self.disk_usage or shutil.disk_usage)(self.directory).free, MODEL_BYTES + self.reserve_bytes
                if free < needed:
                    raise SetupError(
                        f'Not enough free disk space to download the triage model. It needs {_gigabytes(needed)} free '
                        f'(a {_gigabytes(MODEL_BYTES)} download plus {_gigabytes(self.reserve_bytes)} left over) '
                        f'and {_gigabytes(free)} is available.')
                try:
                    self._set('downloading')
                    process = self._spawn(['/usr/bin/curl', '--disable', '--fail', '--location', '--silent',
                        '--proto', '=https', '--proto-redir', '=https', '--connect-timeout', '15',
                        '--max-time', '3600', '--speed-time', '60', '--speed-limit', '1024', MODEL_URL], download=True)
                    digest = sha256(); count = 0
                    fd = os.open(partial, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
                    with os.fdopen(fd, 'wb') as output:
                        while chunk := process.stdout.read(1024 * 1024):
                            self._check(); count += len(chunk)
                            if count > MODEL_BYTES: raise SetupError(DOWNLOAD_FAILED)
                            digest.update(chunk); output.write(chunk); self._set('downloading', count)
                        output.flush(); os.fsync(output.fileno())
                    if process.wait(timeout=5) != 0 or count != MODEL_BYTES or digest.hexdigest() != MODEL_SHA256:
                        raise SetupError(DOWNLOAD_FAILED)
                    self._check(); os.replace(partial, target)
                finally:
                    if self._download:
                        if self._download.poll() is None: self._download.kill()
                        self._download.wait(); self._download.stdout.close()
                    partial.unlink(missing_ok=True)
        self._verified = self._identity(target)
        return target

    def _request(self, path, body=None, *, timeout=180):
        request = urllib.request.Request(f'http://127.0.0.1:{self._port}{path}',
            data=json.dumps(body).encode() if body is not None else None,
            headers={'Content-Type': 'application/json', 'Authorization': 'Bearer ' + self._key})
        with self._opener.open(request, timeout=timeout) as response:
            raw = response.read(16385)
        if len(raw) > 16384: raise ValueError('Oversized inference response')
        return json.loads(raw)

    def _start(self, model):
        if self._server and self._server.poll() is None: return
        inherited = self._claim()
        self._set('loading')
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0)); self._port = sock.getsockname()[1]
        # Never inherit llama configuration, loader injection or proxy settings.
        env = {k: v for k, v in os.environ.items() if not k.startswith(('LLAMA_', 'GGML_', 'DYLD_', 'LD_'))}
        env['LLAMA_API_KEY'] = self._key
        try:
            server = self._spawn([str(self.executable), '--model', str(model), '--host', '127.0.0.1',
                '--port', str(self._port), '--ctx-size', '16384', '--parallel', '1', '--threads', '4',
                '--n-gpu-layers', 'auto', '--no-webui', '--no-agent', '--no-webui-mcp-proxy', '--no-slots', '--cache-ram', '0',
                '--sleep-idle-seconds', '120', '--jinja', '--chat-template-kwargs', '{"enable_thinking":false}'],
                env=env, keep=(inherited,))
            os.ftruncate(inherited, 0); os.pwrite(inherited, str(server.pid).encode(), 0)
        finally:
            os.close(inherited)  # The server keeps its own copy for as long as it runs.
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            self._check()
            if server.poll() is not None: raise RuntimeError('Inference engine exited')
            try:
                if self._request('/health', timeout=1).get('status') == 'ok': return
            except (OSError, ValueError): pass
            self._closed.wait(.25)
        server.kill(); server.wait()
        raise TimeoutError('Inference engine startup')

    def prepare(self):
        self._check()
        if time.monotonic() < self._retry_at: raise RuntimeError('Inference retry pending')
        try:
            if not self.executable.is_file(): raise SetupError(MISSING)
            model = self._model(); self._check(); self._start(model); self._set('ready')
        except Exception as error:
            self._failed(error)
            raise

    def chat(self, messages, schema):
        self.prepare()
        try:
            envelope = self._request('/v1/chat/completions', {'messages': messages,
                'stream': False, 'temperature': 0, 'max_tokens': 900,
                'chat_template_kwargs': {'enable_thinking': False},
                'response_format': {'type': 'json_schema', 'json_schema': {'name': 'workflow', 'strict': True, 'schema': schema}}})
            choice = envelope['choices'][0]
            if choice['finish_reason'] != 'stop': raise ValueError('Incomplete inference')
            return choice['message']['content']
        except Exception:
            self._failed()
            raise

    def _failed(self, error=None):
        self._set('error', message=str(error) if isinstance(error, SetupError) else FAILED)
        self._retry_at = time.monotonic() + 300
        if self._server and self._server.poll() is None:
            self._server.kill(); self._server.wait()
        self._release()
