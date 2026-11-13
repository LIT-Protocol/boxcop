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

from server.event_log import EventLog
from server.package_exceptions import Exceptions
from server.package_intelligence import PolicyStore, build_payload, datadog_records, report, sign
from server.package_proxy import Firewall, RegistryServer
from server.security_events import firewall_events


class FixtureRegistry:
    def __init__(self):
        self.files, self.npm, self.pypi, self.downloaded = {}, {}, {}, []
        # `mixed` has good releases and a newest one, tagged latest, that the feed reports.
        for name, versions in (('fixture', ('1.0.0', '2.0.0')), ('parent-fixture', ('1.0.0', '2.0.0')),
                               ('mixed', ('1.0.0', '1.1.0', '1.2.0'))):
            manifests, wheels = {}, []
            for version in versions:
                manifest = dict(name=name, version=version)
                if name == 'parent-fixture':
                    manifest['dependencies'] = {'fixture': '1.0.0'}
                # If the blocked npm artifact ever executes, this marker proves it.
                if (name, version) in (('fixture', '1.0.0'), ('mixed', '1.2.0')):
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
            self.npm[name] = dict(name=name, versions=manifests, **{'dist-tags': {'latest': versions[-1]}})
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
    # fixture 1.0.0 is confirmed malware; mixed 1.2.0 is reported but not confirmed.
    rows = [row for eco in ('npm', 'PyPI') for row in datadog_records({'fixture': ['1.0.0']}, eco)]
    rows += [report('github', f'GHSA-test-{eco}', eco, 'mixed', [{'kind': 'exact', 'versions': ['1.2.0']}], disposition='review')
             for eco in ('npm', 'PyPI')]
    store.install(sign(build_payload(rows, 1, {}), key))
    upstream = FixtureRegistry()
    upstream.replace_policy = lambda records: store.install(sign(build_payload(records, store.policy.payload['sequence'] + 1, {}), key))
    upstream.state = tmp_path
    upstream.exceptions = Exceptions(tmp_path)
    server = RegistryServer(Firewall(store, b'x' * 32, upstream, log=EventLog(tmp_path / 'blocks.json'),
                                     exceptions=upstream.exceptions), 0)
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


# --- A blocked release fails loudly; ranges and tags fall back to a clean release ---

REPORTED, CONFIRMED = 'BOXCOP_REPORTED_MALWARE', 'BOXCOP_KNOWN_MALWARE'


def show(tool, case, result):
    """Printed with `pytest -s`: what the real package manager said."""
    print(f'\n===== {tool}: {case} (exit {result.returncode}) =====\n{result.stdout}{result.stderr}')


def blocks(upstream):
    return {(row['ecosystem'], row['subject']): row for row in firewall_events(upstream.state, 50)}


@pytest.mark.skipif(shutil.which('npm') is None, reason='npm is not installed')
def test_real_npm_names_boxcop_for_a_blocked_version_and_falls_back_for_ranges_and_tags(tmp_path):
    with registry(tmp_path / 'state') as (base, upstream):
        def install(target):
            work = tmp_path / target.replace('^', 'caret')
            work.mkdir()
            (work / 'package.json').write_text('{"name":"boxcop-install-test","version":"1.0.0","private":true}')
            env = dict(npm_environment(work), BOXCOP_TEST_MARKER=str(tmp_path / 'executed'))
            result = subprocess.run(['npm', 'install', target, '--registry=' + base + '/npm/', '--no-audit', '--no-fund', '--fetch-retries=0'],
                cwd=work, env=env, text=True, capture_output=True, timeout=45)
            show('npm', target, result)
            installed = work / 'node_modules' / target.split('@')[0] / 'package.json'
            return result, json.loads(installed.read_text())['version'] if installed.exists() else None
        result, version = install('mixed@1.2.0')
        assert result.returncode != 0 and version is None
        assert REPORTED in result.stdout + result.stderr and 'No matching version' not in result.stdout + result.stderr
        result, version = install('fixture@1.0.0')
        assert result.returncode != 0 and CONFIRMED in result.stdout + result.stderr
        # A range whose highest match is blocked, and the `latest` tag that points at it.
        assert install('mixed@^1.0.0')[1] == '1.1.0'
        assert install('mixed')[1] == '1.1.0'
        assert install('mixed@latest')[1] == '1.1.0'
        assert not (tmp_path / 'executed').exists()
        assert not any('mixed-1.2.0' in url or '/fixture-1.0.0.tgz' in url for url in upstream.downloaded)
        rows = blocks(upstream)
        assert rows['npm', 'mixed@1.2.0']['title'] == 'Blocked install of mixed 1.2.0 (reported as malware)'
        assert rows['npm', 'mixed@1.2.0']['allowable'] is True
        assert rows['npm', 'fixture@1.0.0']['title'] == 'Blocked install of fixture 1.0.0' and not rows['npm', 'fixture@1.0.0']['allowable']
        # Allowing that exact release lets it through, with no restart.
        upstream.exceptions.change('allow', 'npm', 'mixed', '1.2.0')
        shutil.rmtree(tmp_path / 'mixed@1.2.0')
        result, version = install('mixed@1.2.0')
        assert result.returncode == 0 and version == '1.2.0', result.stderr
        assert blocks(upstream)['npm', 'mixed@1.2.0']['allowable'] is False


@pytest.mark.skipif(shutil.which('pnpm') is None, reason='pnpm is not installed')
def test_real_pnpm_names_boxcop_for_a_blocked_version_and_falls_back_for_ranges_and_tags(tmp_path):
    with registry(tmp_path / 'state') as (base, upstream):
        def install(target):
            work = tmp_path / target.replace('^', 'caret')
            work.mkdir()
            (work / 'package.json').write_text('{"name":"boxcop-install-test","version":"1.0.0","private":true}')
            env = dict(npm_environment(work), CI='true', BOXCOP_TEST_MARKER=str(tmp_path / 'executed'))
            result = subprocess.run(['pnpm', 'add', target, '--registry=' + base + '/npm/', '--store-dir=' + str(work / 'store'),
                                     '--fetch-retries=0', '--ignore-scripts'], cwd=work, env=env, text=True, capture_output=True, timeout=45)
            show('pnpm', target, result)
            installed = work / 'node_modules' / target.split('@')[0] / 'package.json'
            return result, json.loads(installed.read_text())['version'] if installed.exists() else None
        result, version = install('mixed@1.2.0')
        assert result.returncode != 0 and version is None
        assert REPORTED in result.stdout + result.stderr
        result, version = install('fixture@1.0.0')
        assert result.returncode != 0 and CONFIRMED in result.stdout + result.stderr
        assert install('mixed@^1.0.0')[1] == '1.1.0'
        assert install('mixed')[1] == '1.1.0'
        assert install('mixed@latest')[1] == '1.1.0'
        assert not any('mixed-1.2.0' in url or '/fixture-1.0.0.tgz' in url for url in upstream.downloaded)
        assert blocks(upstream)['npm', 'mixed@1.2.0']['allowable'] is True


def python_installs(tmp_path, tool, command):
    with registry(tmp_path / 'state') as (base, upstream):
        def install(target):
            where = tmp_path / target.replace('>', 'gt').replace('=', 'eq')
            result = subprocess.run([*command, target, '--index-url', base + '/pypi/simple/', '--target', str(where), '--only-binary=:all:'],
                                    text=True, capture_output=True, timeout=45)
            show(tool, target, result)
            found = sorted(path.name for path in where.glob('mixed-*.dist-info')) if where.exists() else []
            return result, found[0].split('-')[1].removesuffix('.dist') if found else None
        result, version = install('mixed==1.2.0')
        assert result.returncode != 0 and version is None
        assert REPORTED in result.stdout + result.stderr
        result, version = install('fixture==1.0.0')
        assert result.returncode != 0 and CONFIRMED in result.stdout + result.stderr
        # A range whose highest match is blocked, and an unpinned request for the newest.
        assert install('mixed>=1.0.0')[1] == '1.1.0'
        assert install('mixed')[1] == '1.1.0'
        assert not any('mixed-1.2.0' in url or 'fixture-1.0.0-' in url for url in upstream.downloaded)
        rows = blocks(upstream)
        assert rows['PyPI', 'mixed@1.2.0']['title'] == 'Blocked install of mixed 1.2.0 (reported as malware)'
        assert rows['PyPI', 'mixed@1.2.0']['allowable'] is True and rows['PyPI', 'fixture@1.0.0']['allowable'] is False


@pytest.mark.skipif(importlib.util.find_spec('pip') is None, reason='pip is not installed in the test interpreter')
def test_real_pip_names_boxcop_for_a_pinned_blocked_version_and_skips_it_otherwise(tmp_path):
    python_installs(tmp_path, 'pip', [sys.executable, '-m', 'pip', '--isolated', 'install', '--no-cache-dir',
                                      '--disable-pip-version-check', '--retries=0'])


@pytest.mark.skipif(shutil.which('uv') is None, reason='uv is not installed')
def test_real_uv_names_boxcop_for_a_pinned_blocked_version_and_skips_it_otherwise(tmp_path):
    python_installs(tmp_path, 'uv', ['uv', '--no-config', '--no-cache', 'pip', 'install', '--python', sys.executable])
