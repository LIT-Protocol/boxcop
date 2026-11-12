"""Offline tests of model installation, integrity, cancellation and private inference."""
from hashlib import sha256
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from server import local_inference as module


class Process:
    def __init__(self, data=b'', code=0):
        self.stdout = io.BytesIO(data); self.code = code; self.killed = False
    def poll(self): return self.code
    def wait(self, **kwargs): return self.code
    def kill(self): self.killed = True; self.code = -9


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.payload = b'synthetic weights'
        self.digest = sha256(self.payload).hexdigest()
        for name, value in [('MODEL_BYTES', len(self.payload)), ('MODEL_SHA256', self.digest)]:
            patcher = patch.object(module, name, value); patcher.start(); self.addCleanup(patcher.stop)
        executable = self.root / 'llama-server'; executable.touch()
        self.runtime = module.LocalInference(directory=self.root / 'models', executable=executable)
        self.addCleanup(self.runtime.close)
        self.target = self.runtime.directory / (self.digest + '.gguf')

    def download(self, payload, code=0):
        process = Process(payload, code)
        def spawn(command, **kwargs):
            self.assertEqual(command[:2], ['/usr/bin/curl', '--disable'])
            self.assertIn('=https', command)
            self.assertEqual(command[-1], module.MODEL_URL)
            self.runtime._download = process
            return process
        return patch.object(self.runtime, '_spawn', side_effect=spawn)

    def test_download_is_verified_atomic_and_reused(self):
        with self.download(self.payload):
            self.assertEqual(self.runtime._model(), self.target)
        self.assertEqual(self.target.read_bytes(), self.payload)
        self.assertEqual(self.target.stat().st_mode & 0o777, 0o600)
        self.assertFalse((self.runtime.directory / 'download.part').exists())
        with patch.object(self.runtime, '_spawn', side_effect=AssertionError('Must reuse')):
            self.assertEqual(self.runtime._model(), self.target)

    def test_invalid_download_never_replaces_existing_file(self):
        self.runtime.directory.mkdir(); self.target.write_bytes(b'old invalid model')
        for payload, code in [(b'truncated', 0), (b'x' * len(self.payload), 0), (self.payload * 2, 0), (self.payload, 22)]:
            with self.download(payload, code), self.assertRaises(ValueError): self.runtime._model()
            self.assertEqual(self.target.read_bytes(), b'old invalid model')
            self.assertFalse((self.runtime.directory / 'download.part').exists())

    def test_existing_file_is_hashed_before_loading(self):
        self.runtime.directory.mkdir(); self.target.write_bytes(self.payload)
        with patch.object(self.runtime, '_spawn', side_effect=AssertionError('No download')):
            self.runtime._model()
        self.target.write_bytes(b'x' * len(self.payload))
        with self.download(self.payload): self.runtime._model()
        self.assertEqual(self.target.read_bytes(), self.payload)

    def test_no_space_never_starts_download(self):
        from collections import namedtuple
        usage = namedtuple('Usage', 'free')(0)
        with patch.object(module.shutil, 'disk_usage', return_value=usage), patch.object(self.runtime, '_spawn') as spawn:
            with self.assertRaises(RuntimeError): self.runtime._model()
            spawn.assert_not_called()

    def test_symlink_lock_is_rejected(self):
        self.runtime.directory.mkdir(); marker = self.root / 'keep'; marker.write_bytes(b'untouched')
        (self.runtime.directory / 'install.lock').symlink_to(marker)
        with self.assertRaises(OSError): self.runtime._model()
        self.assertEqual(marker.read_bytes(), b'untouched')

    def test_close_stops_owned_processes_and_prevents_launch(self):
        server = Process(code=None); download = Process(code=None)
        self.runtime._server = server; self.runtime._download = download
        self.runtime.close()
        self.assertTrue(server.killed and download.killed)
        with self.assertRaises(RuntimeError): self.runtime.prepare()
        with self.assertRaises(RuntimeError): self.runtime._spawn(['unused'])

    def test_transport_is_authenticated_loopback_bounded_without_proxy_or_redirect(self):
        self.runtime._port = 12345
        reply = Process(json.dumps({'ok': True}).encode()).stdout
        class Reply:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(_, size):
                self.assertEqual(size, 16385)
                return reply.read(size)
        class Opener:
            def open(_, request, timeout):
                self.assertEqual(request.full_url, 'http://127.0.0.1:12345/v1/chat/completions')
                self.assertEqual(request.headers['Authorization'], 'Bearer ' + self.runtime._key)
                self.assertEqual(timeout, 180)
                return Reply()
        self.assertIsNone(module.NoRedirect().redirect_request())
        self.runtime._opener = Opener()
        self.assertEqual(self.runtime._request('/v1/chat/completions', {'messages': []}), {'ok': True})

    def test_server_has_no_inherited_tool_configuration(self):
        server = Process(code=None)
        def spawn(command, **kwargs):
            self.assertIn('--no-agent', command); self.assertIn('--no-webui', command)
            self.assertIn('127.0.0.1', command)
            self.assertEqual(kwargs['env']['LLAMA_API_KEY'], self.runtime._key)
            self.assertNotIn('LLAMA_ARG_MCP_SERVERS_JSON', kwargs['env'])
            self.assertNotIn('GGML_BACKEND_PATH', kwargs['env'])
            self.assertNotIn(self.runtime._key, ' '.join(command))
            self.runtime._server = server
            return server
        with patch.dict(module.os.environ, {'LLAMA_ARG_MCP_SERVERS_JSON': 'untrusted', 'GGML_BACKEND_PATH': '/untrusted'}), \
             patch.object(self.runtime, '_spawn', side_effect=spawn), patch.object(self.runtime, '_request', return_value={'status': 'ok'}):
            self.runtime._start(self.target)

    def test_failures_back_off_and_never_return_a_verdict(self):
        with patch.object(self.runtime, '_model', side_effect=ValueError('private error')) as install:
            with self.assertRaises(ValueError): self.runtime.prepare()
            with self.assertRaises(RuntimeError): self.runtime.prepare()
            self.assertEqual(install.call_count, 1)
        self.assertEqual(self.runtime.status()['state'], 'error')
        self.assertNotIn('private', json.dumps(self.runtime.status()))

if __name__ == '__main__': unittest.main()
