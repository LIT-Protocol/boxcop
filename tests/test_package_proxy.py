from contextlib import contextmanager
import threading

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from server.package_intelligence import PolicyStore, build_payload, datadog_records, sign
from server.package_proxy import Blocked, Firewall, RegistryServer, artifact_url, refresh


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
    for path in ('/npm/fixture', '/npm/@scope%2ffixture'):
        metadata = firewall.npm(path, 'http://127.0.0.1:8794')
        assert set(metadata['versions']) == {'2.0.0'}
        assert metadata['dist-tags']['latest'] == '2.0.0'
        assert metadata['versions']['2.0.0']['dist']['tarball'].startswith('https://registry.npmjs.org/')
    with pytest.raises(Blocked):
        firewall.npm('/npm/fixture/1.0.0', 'http://127.0.0.1:8794')
    pypi = firewall.pypi('/pypi/simple/Fixture/', 'http://127.0.0.1:8794')
    assert [item['filename'] for item in pypi['files']] == ['fixture-2.0.0-py3-none-any.whl']
    assert 'core-metadata' not in pypi['files'][0]
    assert pypi['files'][0]['hashes']['sha256'] == 'abc'


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
