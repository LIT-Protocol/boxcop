import base64
import threading
from http.server import ThreadingHTTPServer

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from server.package_channel import bootstrap, validate_channel
from server.package_intelligence import build_payload, datadog_records, now, sign, verify
from tools.package_publisher import Publisher, REQUIRED_SOURCES, handler


def collector(manifest=None):
    def collect(**kwargs):
        rows = list(datadog_records(manifest or {'fixture': ['1.0.0']}, 'npm'))
        sources = {name: {'fetched_at': now()} for name in REQUIRED_SOURCES}
        return rows, sources, {'cursor': now(), 'documents': {}}
    return collect


def test_baseline_requires_digest_review_and_restart_retains_sequence(tmp_path):
    key = Ed25519PrivateKey.generate()
    publisher = Publisher(tmp_path, key)
    candidate = publisher.stage(collector=collector())
    assert candidate['requires_review']
    assert not publisher.status()['available']
    with pytest.raises(ValueError, match='approval'):
        publisher.promote(candidate['sha256'])
    publisher.promote(candidate['sha256'], approved=True)
    restarted = Publisher(tmp_path, key)
    assert restarted.status()['sequence'] == 1
    assert (restarted.current()['directory'] / 'github.json').is_file()
    with pytest.raises(ValueError, match='immediately follow'):
        restarted.promote(candidate['sha256'], approved=True)


def test_large_change_held_and_correction_uses_higher_sequence(tmp_path):
    key = Ed25519PrivateKey.generate()
    publisher = Publisher(tmp_path, key)
    first = publisher.stage(collector=collector())
    publisher.promote(first['sha256'], approved=True)
    spike = publisher.stage(collector=collector({f'fixture-{i}': None for i in range(101)}))
    assert spike['requires_review'] and spike['new_package_wide'] == 101
    with pytest.raises(ValueError):
        publisher.promote(spike['sha256'])
    assert publisher.status()['sequence'] == 1
    correction = publisher.stage(collector=collector({'fixture': ['2.0.0']}))
    publisher.promote(correction['sha256'])
    assert publisher.current()['policy'].assess('npm', 'fixture', '1.0.0')['decision'] == 'unknown'
    assert publisher.status()['sequence'] == 2


def test_failed_source_does_not_commit_cursor(tmp_path):
    publisher = Publisher(tmp_path, Ed25519PrivateKey.generate())
    first = publisher.stage(collector=collector())
    publisher.promote(first['sha256'], approved=True)
    before = publisher.current()['directory']
    def failure(**kwargs):
        raise OSError('upstream unavailable')
    with pytest.raises(OSError):
        publisher.stage(collector=failure)
    assert publisher.current()['directory'] == before


def test_serves_only_approved_snapshot_and_no_signing_endpoint(tmp_path):
    key = Ed25519PrivateKey.generate()
    publisher = Publisher(tmp_path, key)
    server = ThreadingHTTPServer(('127.0.0.1', 0), handler(publisher))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f'http://127.0.0.1:{server.server_port}'
    try:
        with httpx.Client(trust_env=False) as client:
            assert client.get(base + '/readyz').status_code == 503
            assert client.get(base + '/healthz').status_code == 200
            candidate = publisher.stage(collector=collector())
            assert client.get(base + '/v1/policy.json').status_code == 503
            publisher.promote(candidate['sha256'], approved=True)
            response = client.get(base + '/v1/policy.json')
            policy = verify(response.content, key.public_key().public_bytes_raw())
            assert policy.payload['sequence'] == 1
            assert client.get(base + '/readyz').status_code == 200
            assert client.get(base + '/private.key').status_code == 404
            assert client.post(base + '/promote').status_code == 501
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_release_channel_bootstrap_floor_signature_and_https(tmp_path):
    key = Ed25519PrivateKey.generate()
    channel = dict(schema='boxcop.package-channel.v1', url='https://feed.example/v1/policy.json',
        public_key=base64.b64encode(key.public_key().public_bytes_raw()).decode(), minimum_sequence=2)
    signed = sign(build_payload([], 1, {}), key)
    with pytest.raises(ValueError, match='floor'):
        bootstrap(channel, tmp_path, fetch=lambda url: signed)
    assert not (tmp_path / 'public.key').exists()
    signed = sign(build_payload([], 2, {}), key)
    bootstrap(channel, tmp_path, fetch=lambda url: signed)
    assert (tmp_path / 'public.key').read_bytes() == key.public_key().public_bytes_raw()
    for url in ('http://feed.example/policy', 'https://secret@feed.example/policy', 'https://feed.example/policy?key=secret'):
        with pytest.raises(ValueError):
            validate_channel(dict(channel, url=url))


def test_source_freshness_and_missing_sources_abort_publication(tmp_path):
    publisher = Publisher(tmp_path, Ed25519PrivateKey.generate())
    for sources in ({}, {name: {'fetched_at': '2020-01-01T00:00:00Z'} for name in REQUIRED_SOURCES}):
        with pytest.raises(ValueError):
            publisher.stage(collector=lambda **kwargs: ([], sources, {}))
    assert publisher.current() is None


def test_slow_refresh_does_not_block_serving_last_good_policy(tmp_path):
    publisher = Publisher(tmp_path, Ed25519PrivateKey.generate())
    first = publisher.stage(collector=collector())
    publisher.promote(first['sha256'], approved=True)
    entered, finish = threading.Event(), threading.Event()
    def slow(**kwargs):
        entered.set()
        assert finish.wait(10)
        return collector()(**kwargs)
    worker = threading.Thread(target=lambda: publisher.stage(collector=slow))
    server = ThreadingHTTPServer(('127.0.0.1', 0), handler(publisher))
    http_thread = threading.Thread(target=server.serve_forever)
    worker.start()
    http_thread.start()
    try:
        assert entered.wait(2)
        with httpx.Client(trust_env=False, timeout=1) as client:
            base = f'http://127.0.0.1:{server.server_port}'
            assert client.get(base + '/readyz').json()['sequence'] == 1
            assert client.get(base + '/v1/policy.json').status_code == 200
        assert worker.is_alive()
    finally:
        finish.set()
        worker.join(10)
        server.shutdown()
        server.server_close()
        http_thread.join(5)
