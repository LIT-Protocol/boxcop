from contextlib import contextmanager
import threading

from urllib.parse import quote

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from server.event_log import EventLog
from server.package_exceptions import Exceptions
from server.package_intelligence import PolicyStore, build_payload, datadog_records, report, sign
from server.package_proxy import Blocked, Firewall, RegistryServer, artifact_url, refresh, replacement, semver_key
from server.security_events import firewall_events


class FakeUpstream:
    def __init__(self):
        self.artifacts = []
        self.client = httpx.Client(transport=httpx.MockTransport(self.artifact))

    def artifact(self, request):
        self.artifacts.append(str(request.url))
        return httpx.Response(200, content=b'inert fixture bytes')

    def metadata(self, url):
        if 'registry.npmjs.org' in url:
            name = '@scope/fixture' if '%40scope' in url else 'fixture'
            return dict(name=name, **{'dist-tags': {'latest': '2.0.0'}}, versions={v: dict(name=name, version=v,
                dist=dict(tarball=f'https://registry.npmjs.org/{name}/-/fixture-{v}.tgz', integrity='sha512-fixture'))
                for v in ('1.0.0', '2.0.0')})
        return dict(name='fixture', files=[dict(filename=f'fixture-{v}-py3-none-any.whl',
            url=f'https://files.pythonhosted.org/packages/fixture-{v}-py3-none-any.whl', hashes={'sha256': 'abc'},
            **{'core-metadata': True, 'requires-python': '>=3.8'}) for v in ('1.0.0', '2.0.0')])


@pytest.fixture
def firewall(tmp_path):
    key = Ed25519PrivateKey.generate()
    store = PolicyStore(tmp_path / 'policy.json', key.public_key().public_bytes_raw())
    rows = list(datadog_records({'fixture': ['1.0.0'], '@scope/fixture': ['1.0.0']}, 'npm'))
    rows += list(datadog_records({'fixture': ['1.0.0']}, 'PyPI'))
    store.install(sign(build_payload(rows, 1, {}), key))
    fw = Firewall(store, b'x' * 32, FakeUpstream())
    fw.test_key = key
    yield fw
    fw.upstream.client.close()


@contextmanager
def serving(firewall):
    server = RegistryServer(firewall, 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{server.server_port}'
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_registry_filtering_and_unknown_release_allowed(firewall):
    base = 'http://127.0.0.1:8794'
    for path, name in (('/npm/fixture', 'fixture'), ('/npm/@scope%2ffixture', '@scope/fixture')):
        metadata = firewall.npm(path, base)
        # The refused release stays listed, marked, and its download lands on this listener.
        assert list(metadata['versions']) == ['1.0.0', '2.0.0']
        refused, clean = metadata['versions']['1.0.0'], metadata['versions']['2.0.0']
        assert refused['deprecated'] == 'Blocked by BoxCop: confirmed malware. Open BoxCop for details.'
        assert refused['dist']['tarball'] == f'{base}/refused/BOXCOP_KNOWN_MALWARE/npm/{quote(name, safe="")}/1.0.0/fixture-1.0.0.tgz'
        assert 'registry.npmjs.org' not in refused['dist']['tarball'] and refused['dist']['integrity'] == 'sha512-fixture'
        assert 'deprecated' not in clean and metadata['dist-tags']['latest'] == '2.0.0'
        assert clean['dist']['tarball'].startswith('https://registry.npmjs.org/')
    with pytest.raises(Blocked):
        firewall.npm('/npm/fixture/1.0.0', base)
    pypi = firewall.pypi('/pypi/simple/Fixture/', base)
    assert [item['filename'] for item in pypi['files']] == ['fixture-1.0.0-py3-none-any.whl', 'fixture-2.0.0-py3-none-any.whl']
    refused, clean = pypi['files']
    assert refused['yanked'] == 'Blocked by BoxCop: confirmed malware. Open BoxCop for details.'
    assert refused['url'] == base + '/refused/BOXCOP_KNOWN_MALWARE/PyPI/fixture/1.0.0/fixture-1.0.0-py3-none-any.whl'
    assert 'yanked' not in clean and clean['url'].startswith(base + '/artifacts/')
    assert all('core-metadata' not in item and item['hashes']['sha256'] == 'abc' for item in pypi['files'])


def test_artifact_is_rechecked_after_policy_changes(firewall):
    with serving(firewall) as base:
        with httpx.Client(trust_env=False) as client:
            manifest = client.get(base + '/npm/fixture').json()
            from urllib.parse import urlsplit
            url = base + urlsplit(manifest['versions']['2.0.0']['dist']['tarball']).path
            assert client.get(url).content == b'inert fixture bytes'
            assert len(firewall.upstream.artifacts) == 1
            firewall.store.install(sign(build_payload(list(datadog_records({'fixture': ['2.0.0']}, 'npm')), 2, {}), firewall.test_key))
            result = client.get(url)
            assert result.status_code == 403
            assert result.json()['error'] == 'BOXCOP_KNOWN_MALWARE'
            assert len(firewall.upstream.artifacts) == 1  # No artifact fetched.
            firewall.store.install(sign(build_payload([], 3, {}), firewall.test_key))
            assert client.get(url).status_code == 200


@pytest.mark.parametrize('url', [
    'http://registry.npmjs.org/a.tgz', 'https://registry.npmjs.org.evil.test/a.tgz',
    'https://user@registry.npmjs.org/a.tgz', 'https://127.0.0.1/a.tgz',
    'https://registry.npmjs.org/a/../b.tgz', 'https://registry.npmjs.org/%2e%2e/b.tgz',
    'https://registry.npmjs.org/a.tgz?token=secret',
])
def test_no_arbitrary_proxy_origin(url):
    with pytest.raises(ValueError):
        artifact_url('npm', url)


def test_artifact_links_authenticated_and_restart_stable(firewall):
    link = firewall.link('', 'npm', 'fixture', '2.0.0', 'https://registry.npmjs.org/fixture/-/fixture-2.0.0.tgz')
    restarted = Firewall(firewall.store, b'x' * 32, firewall.upstream)
    assert restarted.resolve(link)['version'] == '2.0.0'
    with pytest.raises(ValueError):
        restarted.resolve(link.replace('fixture-2.0.0.tgz', 'another.tgz'))
    with pytest.raises(ValueError):
        Firewall(firewall.store, b'y' * 32, firewall.upstream).resolve(link)


def test_browser_credentials_and_write_endpoints_refused(firewall):
    with serving(firewall) as base, httpx.Client(trust_env=False) as client:
        for headers in ({'Host': 'evil.test'}, {'Origin': 'https://evil.test'}, {'Authorization': 'Bearer secret'}, {'Cookie': 'secret'}):
            assert client.get(base + '/npm/fixture', headers=headers).status_code == 400
        assert client.post(base + '/npm/fixture', content=b'publish').status_code == 501
        assert client.get(base + '/npm/-/whoami').status_code != 200
        status = client.get(base + '/status').json()
        assert status['available'] and not status['stale']
        assert status['release_age_policy'] is None


def test_update_outage_preserves_last_good_policy(firewall, monkeypatch):
    def unavailable(*args, **kwargs):
        raise RuntimeError('private error details')
    monkeypatch.setattr('server.package_transport.download', unavailable)
    refresh(firewall.store, 'https://example.test/policy.json')
    assert firewall.verdict('npm', 'fixture', '1.0.0')['decision'] == 'block'
    assert firewall.verdict('npm', 'fixture', '3.0.0')['decision'] == 'unknown'
    assert 'private' not in firewall.store.status()['update_error']


# --- Two tiers, exact exceptions, and refusals a package manager cannot hide ---

class Releases:
    """An upstream with one package whose versions and tags a test chooses."""
    def __init__(self, versions, tags=None, name='mixed'):
        self.name, self.versions, self.tags = name, versions, tags or {'latest': versions[-1]}
        self.client = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200, content=b'inert')))

    def metadata(self, url):
        if 'registry.npmjs.org' in url:
            return {'name': self.name, 'dist-tags': dict(self.tags), 'versions': {v: {
                'name': self.name, 'version': v, 'dist': {'tarball': f'https://registry.npmjs.org/{self.name}/-/{self.name}-{v}.tgz'}}
                for v in self.versions}}
        return {'name': self.name, 'files': [{'filename': f'{self.name}-{v}.tar.gz', 'hashes': {},
                                              'url': f'https://files.pythonhosted.org/packages/{self.name}-{v}.tar.gz'} for v in self.versions]}


def tiered(tmp_path, versions, *, reported=(), confirmed=(), tags=None):
    key = Ed25519PrivateKey.generate()
    store = PolicyStore(tmp_path / 'policy.json', key.public_key().public_bytes_raw())
    rows = []
    for eco in ('npm', 'PyPI'):
        if reported:
            rows.append(report('github', 'GHSA-reported-' + eco, eco, 'mixed', [{'kind': 'exact', 'versions': list(reported)}], disposition='review'))
        if confirmed:
            rows.append(report('datadog', 'confirmed-' + eco, eco, 'mixed', [{'kind': 'exact', 'versions': list(confirmed)}]))
    store.install(sign(build_payload(rows, 1, {}), key))
    return Firewall(store, b'x' * 32, Releases(versions, tags), log=EventLog(tmp_path / 'blocks.json'), exceptions=Exceptions(tmp_path))


def test_reported_tier_is_refused_like_confirmed_with_its_own_code(tmp_path):
    firewall = tiered(tmp_path, ['1.0.0', '1.1.0', '1.2.0'], reported=['1.1.0'], confirmed=['1.2.0'])
    assert [firewall.verdict('npm', 'mixed', v)['refused'] for v in ('1.0.0', '1.1.0', '1.2.0')] == [None, 'reported', 'confirmed']
    with serving(firewall) as base, httpx.Client(trust_env=False) as client:
        document = client.get(base + '/npm/mixed').json()
        assert document['dist-tags'] == {'latest': '1.0.0'}
        assert 'not yet confirmed' in document['versions']['1.1.0']['deprecated']
        reply = client.get(document['versions']['1.1.0']['dist']['tarball'])
        assert reply.status_code == 403 and reply.json()['error'] == 'BOXCOP_REPORTED_MALWARE'
        assert reply.json()['message'] == 'Blocked by BoxCop: reported as malware, not yet confirmed. Open BoxCop for details.'
        assert reply.json()['reports'][0]['id'] == 'GHSA-reported-npm'
        reply = client.get(document['versions']['1.2.0']['dist']['tarball'])
        assert reply.status_code == 403 and reply.json()['error'] == 'BOXCOP_KNOWN_MALWARE'
        # Every other way to the same release is refused too: the exact endpoint, the
        # public tarball path npm reroutes here, and a PyPI file link.
        assert client.get(base + '/npm/mixed/1.1.0').json()['error'] == 'BOXCOP_REPORTED_MALWARE'
        assert client.get(base + '/npm/mixed/-/mixed-1.1.0.tgz').json()['error'] == 'BOXCOP_REPORTED_MALWARE'
        files = {item['filename']: item for item in client.get(base + '/pypi/simple/mixed/').json()['files']}
        assert files['mixed-1.0.0.tar.gz'].get('yanked') is None
        assert 'not yet confirmed' in files['mixed-1.1.0.tar.gz']['yanked']
        assert client.get(files['mixed-1.1.0.tar.gz']['url']).json()['error'] == 'BOXCOP_REPORTED_MALWARE'
        assert client.get(files['mixed-1.2.0.tar.gz']['url']).json()['error'] == 'BOXCOP_KNOWN_MALWARE'
        # The code in a refusal link is decoration; the verdict is recomputed.
        forged = document['versions']['1.2.0']['dist']['tarball'].replace('BOXCOP_KNOWN_MALWARE', 'anything')
        assert client.get(forged).json()['error'] == 'BOXCOP_KNOWN_MALWARE'
        assert client.get(base + '/refused/x/npm/mixed/1.0.0/mixed-1.0.0.tgz').status_code == 409
        assert client.get(base + '/refused/x/gem/mixed/1.0.0/a.tgz').status_code == 502
    rows = {(row['ecosystem'], row['version']): row for row in firewall_events(tmp_path, 50)}
    assert rows['npm', '1.1.0']['title'] == 'Blocked install of mixed 1.1.0 (reported as malware)' and rows['npm', '1.1.0']['allowable']
    assert rows['npm', '1.2.0']['title'] == 'Blocked install of mixed 1.2.0' and not rows['npm', '1.2.0']['allowable']
    assert rows['PyPI', '1.1.0']['allowable'] and not rows['PyPI', '1.2.0']['allowable']
    # Serving the version list records nothing; only a refused request does.
    assert all('Hid' not in row['title'] for row in rows.values())
    before = len(EventLog(tmp_path / 'blocks.json').read())
    firewall.npm('/npm/mixed', 'http://127.0.0.1:1'); firewall.pypi('/pypi/simple/mixed/', 'http://127.0.0.1:1')
    assert len(EventLog(tmp_path / 'blocks.json').read()) == before


def test_exception_allows_one_exact_reported_release_without_restart(tmp_path):
    firewall = tiered(tmp_path, ['1.0.0', '1.1.0', '1.2.0'], reported=['1.1.0', '1.2.0'])
    assert firewall.verdict('npm', 'mixed', '1.2.0')['refused'] == 'reported'
    firewall.exceptions.change('allow', 'npm', 'mixed', '1.2.0')
    assert firewall.verdict('npm', 'mixed', '1.2.0')['refused'] is None
    # Exactly that release: not its neighbour, and not the same name in the other ecosystem.
    assert firewall.verdict('npm', 'mixed', '1.1.0')['refused'] == 'reported'
    assert firewall.verdict('PyPI', 'mixed', '1.2.0')['refused'] == 'reported'
    document = firewall.npm('/npm/mixed', 'http://127.0.0.1:8794')
    assert 'deprecated' not in document['versions']['1.2.0'] and document['dist-tags'] == {'latest': '1.2.0'}
    assert document['versions']['1.2.0']['dist']['tarball'] == 'https://registry.npmjs.org/mixed/-/mixed-1.2.0.tgz'
    assert firewall.npm_artifact('/npm/mixed/-/mixed-1.2.0.tgz')['version'] == '1.2.0'
    firewall.exceptions.change('revoke', 'npm', 'mixed', '1.2.0')
    assert firewall.verdict('npm', 'mixed', '1.2.0')['refused'] == 'reported'
    with pytest.raises(Blocked):
        firewall.npm_artifact('/npm/mixed/-/mixed-1.2.0.tgz')


def test_exception_never_applies_to_confirmed_malware_or_the_test_package(tmp_path):
    firewall = tiered(tmp_path, ['1.0.0', '1.2.0'], confirmed=['1.2.0'])
    # Written straight to the file, as a tampering program would.
    firewall.exceptions.change('allow', 'npm', 'mixed', '1.2.0')
    firewall.exceptions.change('allow', 'npm', 'boxcop-test-malware', '1.0.0')
    assert firewall.verdict('npm', 'mixed', '1.2.0')['refused'] == 'confirmed'
    assert firewall.verdict('npm', 'boxcop-test-malware', '1.0.0')['refused'] == 'confirmed'
    with pytest.raises(Blocked):
        firewall.npm('/npm/boxcop-test-malware', 'http://127.0.0.1:8794')


@pytest.mark.parametrize('tags, expected', [
    ({'latest': '1.2.0'}, {'latest': '1.1.0'}),
    # A tag moves back, never forward past what the publisher chose, and prefers full releases.
    ({'latest': '1.2.0', 'next': '2.0.0-beta.1'}, {'latest': '1.1.0', 'next': '2.0.0-beta.1'}),
    ({'latest': '1.0.0', 'old': '0.9.0', 'gone': '9.9.9'}, {'latest': '1.0.0', 'old': '0.9.0'}),
])
def test_dist_tags_move_to_the_highest_clean_release(tmp_path, tags, expected):
    firewall = tiered(tmp_path, ['0.9.0', '1.0.0', '1.1.0', '1.1.1-rc.1', '1.2.0', '2.0.0-beta.1'], reported=['1.2.0'], tags=tags)
    assert firewall.npm('/npm/mixed', 'http://127.0.0.1:8794')['dist-tags'] == expected
    # The tag endpoint follows the moved tag.
    assert firewall.npm('/npm/mixed/latest', 'http://127.0.0.1:8794')['version'] == expected['latest']


def test_semver_order_and_replacement():
    ordered = ['1.0.0-alpha', '1.0.0-alpha.1', '1.0.0-alpha.beta', '1.0.0-beta.2', '1.0.0-beta.11', '1.0.0-rc.1', '1.0.0', '1.0.1', '1.10.0', '2.0.0+build.5']
    assert sorted(reversed(ordered), key=semver_key) == ordered
    assert semver_key('not-a-version') is None and semver_key('1.2') is None and semver_key(None) is None
    assert replacement('1.2.0', ['1.0.0', '1.10.0', '1.9.0', 'weird']) == '1.0.0'
    assert replacement('0.1.0', ['1.0.0', '1.1.0']) == '1.1.0'  # Nothing older: the highest clean release.
    assert replacement('2.0.0', ['1.0.0-rc.1', '1.0.0-rc.2']) == '1.0.0-rc.2'  # Pre-releases only when nothing else.
    assert replacement('2.0.0', ['weird']) is None and replacement('2.0.0', []) is None


def test_package_with_every_release_refused_is_refused_whole(tmp_path):
    firewall = tiered(tmp_path, ['1.0.0', '1.1.0'], reported=['1.0.0', '1.1.0'])
    for call in (lambda: firewall.npm('/npm/mixed', 'http://x'), lambda: firewall.pypi('/pypi/simple/mixed/', 'http://x')):
        with pytest.raises(Blocked) as refused:
            call()
        assert refused.value.verdict['version'] is None and refused.value.verdict['refused'] == 'reported'
    # A lone release is named, so its block can be allowed.
    single = tiered(tmp_path / 'single', ['1.0.0'], reported=['1.0.0'])
    with pytest.raises(Blocked) as refused:
        single.npm('/npm/mixed', 'http://x')
    assert refused.value.verdict['version'] == '1.0.0'
    single.exceptions.change('allow', 'npm', 'mixed', '1.0.0')
    assert list(single.npm('/npm/mixed', 'http://x')['versions']) == ['1.0.0']


def test_exceptions_file_is_private_validated_and_bounded(tmp_path):
    import json, os
    exceptions = Exceptions(tmp_path / 'state')
    assert exceptions.read() == [] and not exceptions.allows('npm', 'a', '1.0.0')
    rows = exceptions.change('allow', 'PyPI', 'Some_Package', '1.0.0')
    assert rows == exceptions.read() and set(rows[0]) == {'ecosystem', 'package', 'version', 'added'}
    assert rows[0]['package'] == 'some-package' and rows[0]['added'].endswith('Z')
    assert exceptions.allows('PyPI', 'some.package', '1.0.0') and not exceptions.allows('npm', 'some-package', '1.0.0')
    assert len(exceptions.change('allow', 'PyPI', 'some-package', '1.0.0')) == 1  # Not added twice.
    assert exceptions.path.stat().st_mode & 0o777 == 0o600 and exceptions.path.parent.stat().st_mode & 0o777 == 0o700
    for bad in (('gem', 'a', '1.0.0'), ('npm', '../a', '1.0.0'), ('npm', 'a', ''), ('npm', 'a', 'x' * 129), ('npm', 'a', 'latest')):
        with pytest.raises(ValueError):
            exceptions.change('allow', *bad)
    # Hand-edited content: only well-formed, distinct entries count.
    good = {'ecosystem': 'npm', 'package': 'ok', 'version': '1.0.0', 'added': '2026-11-12T00:00:00Z'}
    exceptions.path.write_text(json.dumps([good, dict(good), dict(good, extra=1), dict(good, ecosystem='gem'), dict(good, package='b d'),
                                           dict(good, version=7), 'text', dict(good, package='other', added=5)]))
    assert Exceptions(tmp_path / 'state').read() == [good]
    # A file other users can write, a link, or an oversized file is ignored entirely.
    os.chmod(exceptions.path, 0o666)
    assert Exceptions(tmp_path / 'state').read() == []
    os.chmod(exceptions.path, 0o600)
    exceptions.path.write_text('[' + ' ' * 200000 + ']')
    assert Exceptions(tmp_path / 'state').read() == []
    exceptions.path.unlink()
    target = tmp_path / 'elsewhere.json'; target.write_text(json.dumps([good])); os.chmod(target, 0o600)
    exceptions.path.symlink_to(target)
    assert Exceptions(tmp_path / 'state').read() == []
    exceptions.path.unlink()
    for index in range(200):
        exceptions.change('allow', 'npm', f'p{index}', '1.0.0')
    with pytest.raises(OverflowError):
        exceptions.change('allow', 'npm', 'one-too-many', '1.0.0')
    assert len(exceptions.read()) == 200
