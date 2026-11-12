import io
import json
import zipfile

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from server.package_intelligence import (Policy, PolicyStore, build_payload, canonical,
    datadog_records, github_records, osv_records, sign, verify)
from tools.package_feed import github_sync, openssf_export


def payload(rows=(), sequence=1):
    return build_payload(list(rows), sequence, {})


def test_ecosystem_identity_and_fresh_packages():
    policy = Policy(payload(datadog_records({'some_pkg': ['1.0']}, 'PyPI')))
    assert policy.assess('PyPI', 'Some.Pkg', '1.0.0')['decision'] == 'block'
    assert policy.assess('npm', 'some_pkg', '1.0.0')['decision'] == 'unknown'
    assert policy.assess('PyPI', 'some-pkg', '1.0.1')['decision'] == 'unknown'
    assert policy.assess('PyPI', 'brand-new-release', '0.0.1')['decision'] == 'unknown'
    assert policy.assess('PyPI', 'some-pkg', '1.0+vendor')['decision'] == 'unknown'
    assert policy.status()['release_age_policy'] is None


def test_compromise_is_not_a_name_wide_ban():
    policy = Policy(payload(datadog_records({'compromised': ['1.0.0'], 'malicious-intent': None}, 'npm')))
    assert policy.assess('npm', 'compromised', '1.0.1')['decision'] == 'unknown'
    assert policy.assess('npm', 'compromised', '1.0.0-rc.1')['decision'] == 'unknown'
    assert policy.assess('npm', 'malicious-intent', '9.0.0')['decision'] == 'block'


def test_legacy_npm_case_is_preserved_not_lowercased():
    policy = Policy(payload(datadog_records({'LegacyName': ['1.0.0']}, 'npm')))
    assert policy.assess('npm', 'LegacyName', '1.0.0')['decision'] == 'block'
    assert policy.assess('npm', 'legacyname', '1.0.0')['decision'] == 'unknown'


def osv(**overrides):
    return dict(id='MAL-2026-1', affected=[dict(package=dict(ecosystem='npm', name='fixture'),
        versions=['1.0.0'], ranges=[dict(type='SEMVER', events=[{'introduced': '2.0.0'}, {'fixed': '2.1.0'},
            {'introduced': '3.0.0'}, {'last_affected': '3.1.0'}])])], **overrides)


def test_osv_review_and_interval_boundaries():
    assert Policy(payload(osv_records(osv()))).assess('npm', 'fixture', '1.0.0')['decision'] == 'review'
    policy = Policy(payload(osv_records(osv(), reviewed_ids={'MAL-2026-1'})))
    for candidate in ['1.0.0', '2.0.0', '2.0.1', '3.1.0']:
        assert policy.assess('npm', 'fixture', candidate)['decision'] == 'block'
    for candidate in ['1.0.1', '2.1.0', '2.9.0', '3.1.1']:
        assert policy.assess('npm', 'fixture', candidate)['decision'] == 'unknown'


def test_withdrawal_and_source_removal_replace_policy(tmp_path):
    key = Ed25519PrivateKey.generate()
    store = PolicyStore(tmp_path / 'policy.json', key.public_key().public_bytes_raw())
    store.install(sign(payload(osv_records(osv(), reviewed_ids={'MAL-2026-1'})), key))
    assert store.policy.assess('npm', 'fixture', '1.0.0')['decision'] == 'block'
    store.install(sign(payload(osv_records(osv(withdrawn='2026-01-01T00:00:00Z'), reviewed_ids={'MAL-2026-1'}), 2), key))
    assert store.policy.assess('npm', 'fixture', '1.0.0')['decision'] == 'unknown'
    store.install(sign(payload([], 3), key))
    assert store.policy.status()['records'] == 0


def test_tamper_wrong_key_and_persistent_rollback(tmp_path):
    key, wrong = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes_raw()
    signed = sign(payload(), key)
    with pytest.raises(InvalidSignature):
        verify(signed, wrong.public_key().public_bytes_raw())
    envelope = json.loads(signed)
    envelope['payload'] = envelope['payload'][:-4] + 'AAAA'
    with pytest.raises(InvalidSignature):
        verify(canonical(envelope), public)
    store = PolicyStore(tmp_path / 'policy.json', public)
    store.install(sign(payload(sequence=2), key))
    before = store.path.read_bytes()
    restarted = PolicyStore(store.path, public)
    with pytest.raises(ValueError, match='rollback'):
        restarted.install(signed)
    with pytest.raises(InvalidSignature):
        restarted.install(sign(payload(sequence=3), wrong))
    with pytest.raises(ValueError, match='sequence reused'):
        restarted.install(sign(payload(datadog_records({'fixture': None}, 'npm'), 2), key))
    assert store.path.read_bytes() == before
    assert restarted.policy.payload['sequence'] == 2


def gh(identifier='GHSA-test-test-test', **overrides):
    return dict(ghsa_id=identifier, type='malware', html_url='https://github.com/advisories/' + identifier,
        vulnerabilities=[dict(package=dict(ecosystem='npm', name='fixture'), vulnerable_version_range='>= 1.0.0, < 2.0.0')], **overrides)


def test_github_classification_and_ranges():
    policy = Policy(payload(github_records(gh())))
    assert policy.assess('npm', 'fixture', '1.9.0')['decision'] == 'block'
    assert policy.assess('npm', 'fixture', '2.0.0')['decision'] == 'unknown'
    assert policy.assess('npm', 'fixture', '1.0.0-beta.1')['decision'] == 'unknown'
    imported = gh(identifiers=[dict(type='MAL', value='MAL-2026-1')])
    assert Policy(payload(github_records(imported))).assess('npm', 'fixture', '1.0.0')['decision'] == 'review'
    ordinary = gh()
    ordinary['type'] = 'reviewed'
    assert list(github_records(ordinary)) == []


def test_reviewed_malware_exception_is_exact_and_honors_withdrawal():
    from server.package_intelligence import reviewed_github_records
    document = gh()
    document['type'] = 'reviewed'
    approval = {'reviewed_at': '2026-11-04', 'source': document['html_url'], 'npm': {'fixture': ['1.0.0']}}
    policy = Policy(payload(reviewed_github_records(document, approval)))
    assert policy.assess('npm', 'fixture', '1.0.0')['decision'] == 'block'
    assert policy.assess('npm', 'fixture', '1.0.1')['decision'] == 'unknown'
    document['withdrawn_at'] = '2026-11-04T00:00:00Z'
    policy = Policy(payload(reviewed_github_records(document, approval)))
    assert policy.assess('npm', 'fixture', '1.0.0')['decision'] == 'unknown'


def test_unrecognized_versions_and_git_ranges_never_become_blocks():
    item = osv()
    item['affected'][0]['ranges'] = [dict(type='GIT', events=[{'introduced': '0'}])]
    policy = Policy(payload(osv_records(item, reviewed_ids={'MAL-2026-1'})))
    assert policy.assess('npm', 'fixture', '1.0.0')['decision'] == 'review'
    assert Policy(payload(datadog_records({'fixture': ['not-a-version']}, 'npm'))).assess('npm', 'fixture', '1.0.0')['decision'] == 'unknown'


def test_duplicate_rows_merge_selectors_without_duplicate_votes():
    rows = list(datadog_records({'fixture': ['1.0.0']}, 'npm')) + list(datadog_records({'fixture': ['2.0.0']}, 'npm'))
    policy = Policy(payload(rows))
    assert len(policy.payload['records']) == 1
    assert policy.assess('npm', 'fixture', '2.0.0')['decision'] == 'block'


def test_github_cursor_withdrawals_and_pagination():
    calls = []
    def fetch(url, *, token, params, include_headers):
        calls.append(params)
        if params['ecosystem'] == 'npm' and params['is_withdrawn'] == 'false' and 'after' not in params:
            return canonical([gh(f'GHSA-{i}') for i in range(100)]), {'Link': '<https://api.github.com/advisories?after=opaque-cursor>; rel="next"'}
        if params['ecosystem'] == 'npm' and params['is_withdrawn'] == 'true':
            return canonical([gh('GHSA-old', withdrawn_at='2026-01-02T00:00:00Z')]), {}
        return b'[]', {}
    previous = dict(cursor='2026-01-01T00:00:00Z', documents={'GHSA-old': gh('GHSA-old')})
    result = github_sync(previous, fetch=fetch)
    assert len(calls) == 5
    assert calls[1]['after'] == 'opaque-cursor'
    assert all(call['updated'].startswith(previous['cursor'] + '..') for call in calls)
    assert result['documents']['GHSA-old']['withdrawn_at']
    assert 'withdrawn_at' not in previous['documents']['GHSA-old']


def test_osv_archive_reads_metadata_without_extracting_paths():
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w') as archive:
        archive.writestr('MAL-2026-1.json', canonical(osv()))
        archive.writestr('../../payload.py', 'raise RuntimeError()')
        archive.writestr('GHSA-example.json', '{}')
    rows = list(openssf_export('npm', fetch=lambda url, **kwargs: output.getvalue()))
    assert [row['id'] for row in rows] == ['MAL-2026-1']


def test_osv_delta_updates_withdrawals_and_review_changes_without_bulk_download():
    from tools.package_feed import openssf_sync
    modified = '2026-01-01T00:00:00Z'
    doc = osv(modified=modified)
    cached = {'_reviewed_ids': [], 'npm': {'MAL-2026-1': {'modified': modified, 'rows': list(osv_records(doc)), 'excluded': []}},
              'PyPI': {'MAL-2026-2': {'modified': modified, 'rows': [], 'excluded': []}}}
    calls = []
    def fetch(url, **kwargs):
        calls.append(url)
        if url.endswith('npm/modified_id.csv'):
            return b'2026-01-02T00:00:00Z,MAL-2026-1\n'
        if url.endswith('PyPI/modified_id.csv'):
            return b'2026-01-01T00:00:00Z,MAL-2026-2\n'
        return canonical(osv(modified='2026-01-02T00:00:00Z', withdrawn='2026-01-02T00:00:00Z'))
    result = openssf_sync(cached, fetch=fetch)
    assert len(calls) == 3
    assert not any(url.endswith('.zip') for url in calls)
    assert result['npm']['MAL-2026-1']['rows'][0]['withdrawn']
    assert cached['npm']['MAL-2026-1']['rows'][0]['withdrawn'] is None
    calls.clear()
    openssf_sync(result, fetch=fetch, reviewed_ids={'MAL-2026-1'})
    assert len(calls) == 3  # Changed review policy also needs fresh source data.


def test_osv_modification_timestamp_precision():
    from tools.package_feed import modification_key
    assert modification_key('2026-11-04T17:26:32.930560830Z') == modification_key('2026-11-04T17:26:32.93056083Z')
    assert modification_key('2026-11-04T17:26:32.930560830Z') < modification_key('2026-11-04T17:26:32.930560831Z')


def test_invalid_upstream_identity_is_quarantined_with_report_id():
    doc = osv()
    doc['affected'][0]['package'] = {'ecosystem': 'PyPI', 'name': 'invalid-name-'}
    excluded = []
    assert list(osv_records(doc, reviewed_ids={'MAL-2026-1'}, excluded=excluded)) == []
    assert excluded == [{'id': 'MAL-2026-1', 'reason': 'invalid_package_identity'}]


def test_local_command_integration_and_ecosystem_separation(tmp_path, monkeypatch):
    from tools.package_service import provision
    from server.supply_chain import command_findings
    monkeypatch.setattr('server.local_package_policy.state_directory', lambda: tmp_path)
    key = Ed25519PrivateKey.generate()
    rows = list(datadog_records({'fresh-threat': ['1.0.0']}, 'npm'))
    provision(tmp_path, sign(payload(rows), key), key.public_key().public_bytes_raw())
    assert command_findings('pnpm add fresh-threat@1.0.0')[0].policy == 'known-malicious-package'
    assert command_findings('pip install fresh-threat==1.0.0') == []
    assert command_findings('npm install litellm@1.107.0') == []
    assert command_findings('pip install php==8.3.0') == []
    assert command_findings('echo "npm install fresh-threat@1.0.0"') == []
    provision(tmp_path, sign(payload([], 2), key), key.public_key().public_bytes_raw())
    assert command_findings('npm install fresh-threat@1.0.0') == []


def test_enrollment_pins_key_and_keeps_arguments_literal(tmp_path):
    from tools.package_service import provision, service_plist
    key = Ed25519PrivateKey.generate()
    provision(tmp_path, sign(payload(), key), key.public_key().public_bytes_raw())
    other = Ed25519PrivateKey.generate()
    with pytest.raises(ValueError, match='Pinned key differs'):
        provision(tmp_path, sign(payload(sequence=2), other), other.public_key().public_bytes_raw())
    config = service_plist('/Applications/BoxCop Test.app/engine', tmp_path)
    assert config['ProgramArguments'][0] == '/Applications/BoxCop Test.app/engine'
    assert config['KeepAlive'] and config['RunAtLoad']


def test_failed_github_page_does_not_advance_cursor():
    previous = dict(cursor='2026-01-01T00:00:00Z', documents={'GHSA-old': gh('GHSA-old')})
    before = canonical(previous)
    def failing(url, **kwargs):
        raise OSError('rate limited')
    with pytest.raises(OSError):
        github_sync(previous, fetch=failing)
    assert canonical(previous) == before


def test_github_failed_sync_resumes_completed_pages(tmp_path):
    def interrupted(url, **kwargs):
        if 'after' in kwargs['params']:
            raise OSError('interrupted')
        return canonical([gh()]), {'Link': '<https://api.github.com/advisories?after=resume>; rel="next"'}
    with pytest.raises(OSError):
        github_sync(fetch=interrupted, checkpoint_path=tmp_path / 'checkpoint')
    calls = []
    def resumed(url, **kwargs):
        calls.append(kwargs['params'])
        return b'[]', {}
    result = github_sync(fetch=resumed, checkpoint_path=tmp_path / 'checkpoint')
    assert calls[0]['after'] == 'resume'
    assert 'GHSA-test-test-test' in result['documents']
    assert len(calls) == 4


@pytest.mark.parametrize('link', [
    'https://evil.test/advisories?after=cursor',
    'http://api.github.com/advisories?after=cursor',
    'https://api.github.com/advisories?page=2',
])
def test_github_rejects_unsafe_or_unsupported_pagination(link):
    def fetch(*args, **kwargs):
        return b'[]', {'Link': '<' + link + '>; rel="next"'}
    with pytest.raises(ValueError):
        github_sync(fetch=fetch)


def test_stale_policy_still_blocks_known_matches_and_carries_notices():
    rows = list(datadog_records({'fixture': ['1.0.0']}, 'npm'))
    value = build_payload(rows, 1, {}, generated_at='2020-01-01T00:00:00Z')
    policy = Policy(value)
    assert policy.status()['stale']
    assert policy.assess('npm', 'fixture', '1.0.0')['decision'] == 'block'
    assert policy.assess('npm', 'fixture', '2.0.0')['decision'] == 'unknown'
    assert 'CC-BY-4.0' in value['licenses']
    assert 'Datadog Security Labs' in value['attribution']


def test_signed_compression_is_bounded_and_encoding_authenticated(monkeypatch):
    import base64
    import zlib
    from server.package_intelligence import COMPRESSED_CONTEXT
    key = Ed25519PrivateKey.generate()
    data = zlib.compress(b'x' * 4096)
    envelope = canonical({'encoding': 'zlib', 'payload': base64.b64encode(data).decode(),
        'signature': base64.b64encode(key.sign(COMPRESSED_CONTEXT + data)).decode()})
    monkeypatch.setattr('server.package_intelligence.MAX_PAYLOAD_BYTES', 1024)
    with pytest.raises(ValueError, match='oversized'):
        verify(envelope, key.public_key().public_bytes_raw())
    parsed = json.loads(envelope)
    del parsed['encoding']
    with pytest.raises(InvalidSignature):
        verify(canonical(parsed), key.public_key().public_bytes_raw())


def test_publisher_failure_does_not_replace_snapshot_or_cursor(tmp_path, monkeypatch):
    from tools.package_feed import main
    key = Ed25519PrivateKey.generate()
    (tmp_path / 'key').write_bytes(key.private_bytes_raw())
    policy = sign(payload(), key)
    (tmp_path / 'policy').write_bytes(policy)
    (tmp_path / 'github.json').write_text('{"cursor":"previous"}')
    def failure(**kwargs):
        raise OSError('source unavailable')
    monkeypatch.setattr('tools.package_feed.collect', failure)
    with pytest.raises(OSError):
        main(['build', '--private-key', str(tmp_path / 'key'), '--state-dir', str(tmp_path),
              '--output', str(tmp_path / 'policy'), '--sequence', '2'])
    assert (tmp_path / 'policy').read_bytes() == policy
    assert (tmp_path / 'github.json').read_text() == '{"cursor":"previous"}'
