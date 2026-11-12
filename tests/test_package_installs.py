"""Real package-manager processes, synthetic packages, no public package downloads."""
import base64
from contextlib import contextmanager
import hashlib
import gzip
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import threading
import zipfile

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from server.package_intelligence import PolicyStore, build_payload, datadog_records, sign
from server.package_proxy import Firewall, RegistryServer


class FixtureRegistry:
    def __init__(self):
        self.files, self.npm, self.pypi, self.downloaded = {}, {}, {}, []
        for name in ('fixture', 'parent-fixture'):
            manifests, wheels = {}, []
            for version in ('1.0.0', '2.0.0'):
                manifest = dict(name=name, version=version)
                if name == 'parent-fixture':
                    manifest['dependencies'] = {'fixture': '1.0.0'}
                # If the blocked npm artifact ever executes, this marker proves it.
                if name == 'fixture' and version == '1.0.0':
                    manifest['scripts'] = {'install': 'node -e "require(\'fs\').writeFileSync(process.env.BOXCOP_TEST_MARKER,\'executed\')"'}
                output = io.BytesIO()
                with tarfile.open(fileobj=output, mode='w') as archive:
                    body = json.dumps(manifest).encode()
                    info = tarfile.TarInfo('package/package.json')
                    info.size = len(body)
                    archive.addfile(info, io.BytesIO(body))
                tarball = gzip.compress(output.getvalue(), mtime=0)
                url = f'https://registry.npmjs.org/{name}/-/{name}-{version}.tgz'
                self.files[url] = tarball
                manifest['dist'] = dict(tarball=url, integrity='sha512-' + base64.b64encode(hashlib.sha512(tarball).digest()).decode())
                manifests[version] = manifest
                wheel_name = name.replace('-', '_')
                filename = f'{wheel_name}-{version}-py3-none-any.whl'
                output = io.BytesIO()
                with zipfile.ZipFile(output, 'w') as archive:
                    prefix = f'{wheel_name}-{version}.dist-info/'
                    metadata = f'Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n'
                    if name == 'parent-fixture':
                        metadata += 'Requires-Dist: fixture==1.0.0\n'
                    archive.writestr(prefix + 'METADATA', metadata)
                    archive.writestr(prefix + 'WHEEL', 'Wheel-Version: 1.0\nGenerator: BoxCop inert fixture\nRoot-Is-Purelib: true\nTag: py3-none-any\n')
                    archive.writestr(prefix + 'RECORD', '')
                data = output.getvalue()
                url = 'https://files.pythonhosted.org/packages/' + filename
                self.files[url] = data
                wheels.append(dict(filename=filename, url=url, hashes={'sha256': hashlib.sha256(data).hexdigest()}))
            self.npm[name] = dict(name=name, versions=manifests, **{'dist-tags': {'latest': '2.0.0'}})
            self.pypi[name] = dict(name=name, files=wheels)
        self.client = httpx.Client(transport=httpx.MockTransport(self.artifact))

    def metadata(self, url):
        name = url.rstrip('/').rsplit('/', 1)[-1]
        return self.npm[name] if 'registry.npmjs.org' in url else self.pypi[name]

    def artifact(self, request):
        url = str(request.url)
        self.downloaded.append(url)
        return httpx.Response(200, content=self.files[url])


@contextmanager
def registry(tmp_path):
    key = Ed25519PrivateKey.generate()
    store = PolicyStore(tmp_path / 'policy.json', key.public_key().public_bytes_raw())
    rows = [row for eco in ('npm', 'PyPI') for row in datadog_records({'fixture': ['1.0.0']}, eco)]
    store.install(sign(build_payload(rows, 1, {}), key))
    upstream = FixtureRegistry()
    upstream.replace_policy = lambda records: store.install(sign(build_payload(records, store.policy.payload['sequence'] + 1, {}), key))
    server = RegistryServer(Firewall(store, b'x' * 32, upstream), 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{server.server_port}', upstream
    finally:
        server.shutdown()
        server.server_close()
        upstream.client.close()
        thread.join()


def npm_environment(work):
    env = {key: value for key, value in os.environ.items() if not key.lower().startswith('npm_config_')}
    env.update(npm_config_cache=str(work / 'cache'), npm_config_userconfig=str(work / 'user.npmrc'),
               npm_config_globalconfig=str(work / 'global.npmrc'))
    return env


@pytest.mark.skipif(shutil.which('npm') is None, reason='npm is not installed')
def test_npm_lockfile_portable_and_existing_lock_rechecked(tmp_path):
    work = tmp_path / 'project'
    work.mkdir()
    (work / 'package.json').write_text('{"name":"boxcop-portability-fixture","version":"1.0.0","private":true}')
    env = npm_environment(work)
    def run(base, *arguments):
        result = subprocess.run(['npm', *arguments, '--registry=' + base + '/npm/', '--no-audit', '--no-fund', '--fetch-retries=0'],
            cwd=work, env=env, text=True, capture_output=True, timeout=45)
        return result
    with registry(tmp_path / 'first') as (base, upstream):
        result = run(base, 'install', 'fixture@2.0.0')
        assert result.returncode == 0, result.stderr
        lock = (work / 'package-lock.json').read_bytes()
        assert b'127.0.0.1' not in lock and b'/artifacts/' not in lock
        assert b'https://registry.npmjs.org/fixture/-/fixture-2.0.0.tgz' in lock
        assert json.loads(lock)['packages']['node_modules/fixture']['integrity']
        shutil.rmtree(work / 'cache')
        upstream.replace_policy(list(datadog_records({'fixture': ['2.0.0']}, 'npm')))
        upstream.downloaded.clear()
        result = run(base, 'ci')
        assert result.returncode != 0
        assert not upstream.downloaded
        assert (work / 'package-lock.json').read_bytes() == lock
    # Another machine/registry with no BoxCop deny policy and no shared link key
    # can consume the unchanged public lockfile. Transport is simulated locally.
    with registry(tmp_path / 'second') as (base, upstream):
        upstream.replace_policy([])
        shutil.rmtree(work / 'cache', ignore_errors=True)
        result = run(base, 'ci')
        assert result.returncode == 0, result.stderr
        assert upstream.downloaded
        assert (work / 'package-lock.json').read_bytes() == lock


@pytest.mark.skipif(shutil.which('pnpm') is None, reason='pnpm is not installed')
def test_pnpm_lockfile_and_frozen_install(tmp_path):
    work = tmp_path / 'project'
    work.mkdir()
    (work / 'package.json').write_text('{"name":"boxcop-portability-fixture","version":"1.0.0","private":true}')
    env = npm_environment(work)
    env['CI'] = 'true'
    def run(base, *arguments):
        return subprocess.run(['pnpm', *arguments, '--registry=' + base + '/npm/', '--store-dir=' + str(work / 'store'), '--fetch-retries=0'],
            cwd=work, env=env, text=True, capture_output=True, timeout=45)
    with registry(tmp_path / 'first') as (base, upstream):
        result = run(base, 'add', 'fixture@2.0.0')
        assert result.returncode == 0, result.stdout + result.stderr
        lock = (work / 'pnpm-lock.yaml').read_bytes()
        assert b'127.0.0.1' not in lock and b'/artifacts/' not in lock
        shutil.rmtree(work / 'store', ignore_errors=True)
        shutil.rmtree(work / 'node_modules', ignore_errors=True)
        upstream.replace_policy(list(datadog_records({'fixture': ['2.0.0']}, 'npm')))
        upstream.downloaded.clear()
        result = run(base, 'install', '--frozen-lockfile')
        assert result.returncode != 0
        assert not upstream.downloaded
        assert (work / 'pnpm-lock.yaml').read_bytes() == lock
    with registry(tmp_path / 'second') as (base, upstream):
        upstream.replace_policy([])
        shutil.rmtree(work / 'store', ignore_errors=True)
        shutil.rmtree(work / 'node_modules', ignore_errors=True)
        result = run(base, 'install', '--frozen-lockfile')
        assert result.returncode == 0, result.stdout + result.stderr
        assert upstream.downloaded
        assert (work / 'pnpm-lock.yaml').read_bytes() == lock


@pytest.mark.skipif(shutil.which('uv') is None, reason='uv is not installed')
def test_uv_pip_clean_direct_and_transitive_installs(tmp_path):
    with registry(tmp_path) as (base, upstream):
        for target, allowed in [('fixture==2.0.0', True), ('fixture==1.0.0', False), ('parent-fixture==2.0.0', False)]:
            result = subprocess.run(['uv', '--no-config', '--no-cache', 'pip', 'install', target,
                '--python', sys.executable, '--index-url', base + '/pypi/simple/', '--target', str(tmp_path / target), '--only-binary=:all:'],
                text=True, capture_output=True, timeout=45)
            assert (result.returncode == 0) == allowed, result.stdout + result.stderr
        assert not any('fixture-1.0.0-' in url for url in upstream.downloaded)


@pytest.mark.skipif(shutil.which('npm') is None, reason='npm is not installed')
def test_real_npm_clean_direct_and_transitive_installs(tmp_path):
    with registry(tmp_path) as (base, upstream):
        for target, allowed in [('fixture@2.0.0', True), ('fixture@1.0.0', False), ('parent-fixture@2.0.0', False)]:
            work = tmp_path / target
            work.mkdir()
            (work / 'package.json').write_text('{"name":"boxcop-install-test","version":"1.0.0","private":true}')
            env = {key: value for key, value in os.environ.items() if not key.lower().startswith('npm_config_')}
            env.update(npm_config_cache=str(work / 'cache'), npm_config_userconfig=str(work / 'user.npmrc'),
                npm_config_globalconfig=str(work / 'global.npmrc'), BOXCOP_TEST_MARKER=str(tmp_path / 'executed'))
            result = subprocess.run(['npm', 'install', target, '--registry=' + base + '/npm/', '--no-audit', '--no-fund', '--fetch-retries=0'],
                cwd=work, env=env, text=True, capture_output=True, timeout=45)
            assert (result.returncode == 0) == allowed, result.stdout + result.stderr
        assert not (tmp_path / 'executed').exists()
        assert not any('/fixture-1.0.0.tgz' in url for url in upstream.downloaded)


@pytest.mark.skipif(importlib.util.find_spec('pip') is None, reason='pip is not installed in the test interpreter')
def test_real_pip_clean_direct_and_transitive_installs(tmp_path):
    with registry(tmp_path) as (base, upstream):
        for target, allowed in [('fixture==2.0.0', True), ('fixture==1.0.0', False), ('parent-fixture==2.0.0', False)]:
            result = subprocess.run([sys.executable, '-m', 'pip', '--isolated', 'install', target, '--index-url', base + '/pypi/simple/',
                '--target', str(tmp_path / target), '--no-cache-dir', '--disable-pip-version-check', '--only-binary=:all:', '--retries=0'],
                text=True, capture_output=True, timeout=45)
            assert (result.returncode == 0) == allowed, result.stdout + result.stderr
        assert not any('fixture-1.0.0-' in url for url in upstream.downloaded)
