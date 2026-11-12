"""Release-time threat-list refresh: validation mirrors the Swift runtime and fails closed."""
import hashlib
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'desktop/macos/scripts'))
import refresh_threat_domains as refresh

REVISION = 'a' * 40
LICENSE = b'GNU GENERAL PUBLIC LICENSE\n Version 3, 29 June 2007\n'


def feed(count=1500, modified='09 Nov 2026 15:10 UTC', extra=()):
    hosts = [f'bad{i}.example' for i in range(count)] + list(extra)
    header = f'# Title: test\n# Last modified: {modified}\n# Number of entries: {len(set(hosts))}\n#\n'
    return (header + '\n'.join(hosts) + '\n').encode()


@pytest.fixture
def upstream(monkeypatch):
    files = {refresh.LIST_PATH: feed(), refresh.LICENSE_PATH: LICENSE}

    def fetch(url, accept=None, attempts=4):
        if url.startswith('https://api.github.com/'):
            return json.dumps([{'sha': REVISION}]).encode()
        assert url.startswith(f'https://raw.githubusercontent.com/{refresh.REPO}/{REVISION}/')
        return files[url.rsplit(f'{REVISION}/', 1)[1]]

    monkeypatch.setattr(refresh, 'fetch', fetch)
    return files


def test_refresh_pins_revision_and_hash(upstream, tmp_path):
    previous, manifest = refresh.refresh(tmp_path)
    assert previous == {}
    assert manifest['revision'] == REVISION and manifest['count'] == 1500
    assert manifest['publishedAt'] == '2026-11-09T15:10:00Z'
    assert manifest['sha256'] == hashlib.sha256((tmp_path / 'domains.txt').read_bytes()).hexdigest()
    assert REVISION in manifest['sourceURL']
    assert json.loads((tmp_path / 'manifest.json').read_text()) == manifest
    assert (tmp_path / 'LICENSE').read_bytes() == LICENSE


@pytest.mark.parametrize('data, message', [
    (feed(extra=['google.com']), 'common service roots'),
    (feed(extra=['*.wild.example']), 'Malformed'),
    (feed(extra=['10.0.0.1']), 'Malformed'),
    (feed(count=10), 'size'),
    (feed(modified='yesterday'), 'Last modified'),
    (feed().replace(b'entries: 1500', b'entries: 1499'), 'header says'),
])
def test_invalid_upstream_lists_fail_without_writing(upstream, tmp_path, data, message):
    upstream[refresh.LIST_PATH] = data
    with pytest.raises(refresh.RefreshError, match=message):
        refresh.refresh(tmp_path)
    assert not (tmp_path / 'manifest.json').exists()


def test_stale_shrunken_or_relicensed_lists_fail(upstream, tmp_path):
    with pytest.raises(refresh.RefreshError, match='stale'):
        refresh.refresh(tmp_path, max_age_days=-1)
    (tmp_path / 'manifest.json').write_text(json.dumps({'count': 4000}))
    with pytest.raises(refresh.RefreshError, match='shrank'):
        refresh.refresh(tmp_path)
    upstream[refresh.LICENSE_PATH] = b'MIT License'
    with pytest.raises(refresh.RefreshError, match='license'):
        refresh.refresh(tmp_path / 'other')


def test_python_normalize_matches_runtime_rules():
    assert refresh.normalize('Evil.Example.') == 'evil.example'
    assert refresh.normalize('xn--80ak6aa92e.com') == 'xn--80ak6aa92e.com'
    for bad in ['com', 'evil..example', '-evil.example', 'evil.123', 'évil.example', 'a' * 64 + '.com']:
        assert refresh.normalize(bad) is None


def test_bundled_snapshot_matches_its_manifest():
    data = (refresh.DESTINATION / 'domains.txt').read_bytes()
    manifest = json.loads((refresh.DESTINATION / 'manifest.json').read_text())
    domains, published = refresh.parse(data)
    assert hashlib.sha256(data).hexdigest() == manifest['sha256']
    assert len(domains) == manifest['count']
    assert published.strftime('%Y-%m-%dT%H:%M:%SZ') == manifest['publishedAt']
    assert manifest['revision'] in manifest['sourceURL']
