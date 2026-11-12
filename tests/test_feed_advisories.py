"""Effect and metadata-boundary checks for twelve feed coverage additions."""
import json
from pathlib import Path
import subprocess
import sys

import pytest
from server.exposure_advisories import findings
from server.software_inventory import Scan

# Real discovery route, last affected/update-needed version, first reviewed fix.
CASES = [
    ('next', 'npm', '15.5.27', '15.5.28', 'update_available'),
    ('langflow', 'python', '1.12.8', '1.13.0', 'affected_version'),
    ('lmdeploy', 'python', '0.18.0', None, 'affected_version'),
    ('sglang', 'python', '0.5.21', '0.5.22', 'update_available'),
    ('pgadmin4', 'python', '9.18', '9.19', 'update_available'),
    ('atlantis', 'homebrew', '0.48.0', '0.49.0', 'update_available'),
    ('bind', 'homebrew', '9.20.29', '9.20.30', 'affected_version'),
    ('freeswitch', 'homebrew', '1.11.2', '1.11.3', 'affected_version'),
    ('bitcoin', 'homebrew', '32.0', '32.1', 'update_available'),
    ('jenkins', 'homebrew', '2.587', '2.588', 'affected_version'),
    ('jenkins-lts', 'homebrew', '2.580.1', '2.580.2', 'affected_version'),
    ('laravel/framework', 'composer', '13.28.0', '13.29.0', 'affected_version'),
    ('drupal/core', 'composer', '11.4.9', '11.4.10', 'affected_version'),
]


def metadata(root, name, version, ecosystem):
    if ecosystem == 'python':
        path = root / (name.replace('/', '-') + '.dist-info') / 'METADATA'
        data = f'Name: {name}\nVersion: {version}\n'
    elif ecosystem == 'npm':
        path = root / 'node_modules' / name / 'package.json'
        data = json.dumps({'name': name, 'version': version})
    elif ecosystem == 'homebrew':
        path = root / 'Cellar' / name / 'installed' / 'INSTALL_RECEIPT.json'
        data = json.dumps({'source': {'tap': 'homebrew/core', 'spec': 'stable', 'versions': {'stable': version, 'head': 'HEAD'}}})
    else:
        path = root / 'vendor/composer/installed.json'
        data = json.dumps({'packages': [{'name': name, 'version': version}]})
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data)
    return path


@pytest.mark.parametrize('name,ecosystem,old,fixed,state', CASES)
def test_discovery_update_and_remediation(tmp_path, name, ecosystem, old, fixed, state):
    path = metadata(tmp_path, name, old, ecosystem)
    initial = Scan().run([tmp_path])
    assert not initial['incomplete']
    assert len(initial['records']) == 1
    record = initial['records'][0]
    assert record['name'] == name and record['path'] == str(path)
    advisory = record['advisories'][0]
    assert advisory['state'] == state
    assert advisory['enforcement'] == 'finding_only'
    assert advisory['verification'] == 'primary_reviewed'
    assert advisory['reviewed_at'] == '2026-11-03'
    assert record['running_state'] == record['configuration'] == 'unknown'
    assert record['finding'] is None  # No new launch deny or quarantine policy.
    assert record['assessment'] == 'review_required'
    if fixed:
        metadata(tmp_path, name, fixed, ecosystem)
        updated = Scan().run([tmp_path])['records'][0]
        assert updated['advisories'][0]['state'] == 'fixed_for_advisory'
        assert updated['metadata_sha256'] != record['metadata_sha256']
        assert updated['id'] == record['id']
        assert updated['running_state'] == 'unknown'
    else:
        for version in ['0.18.1', '0.19.0', '1.0.0']:
            metadata(tmp_path, name, version, ecosystem)
            assert Scan().run([tmp_path])['records'][0]['advisories'][0]['state'] == 'unresolved'


@pytest.mark.parametrize('name,ecosystem,old,fixed,state', CASES)
@pytest.mark.parametrize('version', ['', 'unknown', '9999999.0.0', '13.29.0rc1', '13.29.0-vendor', '13.29.0+patched'])
def test_ambiguous_versions_are_never_clean(tmp_path, name, ecosystem, old, fixed, state, version):
    metadata(tmp_path, name, version, ecosystem)
    report = Scan().run([tmp_path])
    assert report['records'][0]['advisories'][0]['state'] == 'unresolved'
    if not version:
        assert report['incomplete'] and 'missing_package_version' in report['issues']


@pytest.mark.parametrize('name,version,state', [
    ('next', '16.4.0', 'update_available'), ('next', '16.4.1', 'fixed_for_advisory'),
    ('next', '14.2.0', 'unresolved'), ('next', '16.3.9', 'unresolved'),
    ('next', '17.0.0', 'unresolved'),
    ('langflow', '0.9.0', 'unresolved'), ('langflow', '1.0.0', 'affected_version'),
    ('langflow', '1.12.9', 'unresolved'), ('langflow', '2.0.0', 'unresolved'),
    ('lmdeploy', '0.8.9', 'unresolved'), ('lmdeploy', '0.9.0', 'affected_version'),
    ('bind', '9.10.9', 'unresolved'), ('bind', '9.11.0', 'affected_version'),
    ('bind', '9.18.50', 'affected_version'), ('bind', '9.18.51', 'unresolved'),
    ('bind', '9.21.26', 'affected_version'), ('bind', '9.21.27', 'fixed_for_advisory'),
    ('bind', '9.22.0', 'unresolved'), ('bind', '9.20.30-S1', 'unresolved'),
    ('jenkins', '2.580.2', 'unresolved'), ('jenkins-lts', '2.588', 'unresolved'),
    ('jenkins-lts', '2.581.1', 'unresolved'), ('jenkins-lts', '2.579.1', 'affected_version'),
    ('laravel/framework', '12.67.9', 'affected_version'), ('laravel/framework', '12.68.0', 'fixed_for_advisory'),
    ('laravel/framework', '12.99.0', 'fixed_for_advisory'), ('laravel/framework', '13.0.0', 'affected_version'),
    ('laravel/framework', '14.0.0', 'unresolved'),
    ('drupal/core', '8.8.9', 'unresolved'), ('drupal/core', '8.9.0', 'affected_version'),
    ('drupal/core', '10.6.18', 'affected_version'), ('drupal/core', '10.6.19', 'fixed_for_advisory'),
    ('drupal/core', '11.3.18', 'affected_version'), ('drupal/core', '11.3.19', 'fixed_for_advisory'),
    ('drupal/core', '11.4.0', 'affected_version'), ('drupal/core', '11.5.0', 'unresolved'),
    ('drupal/core', '12.0.0-beta2', 'unresolved'), ('drupal/core', '12.0.0', 'unresolved'),
    ('bitcoin', '29.4', 'update_available'), ('bitcoin', '29.5', 'fixed_for_advisory'),
    ('bitcoin', '30.3', 'update_available'), ('bitcoin', '30.4', 'fixed_for_advisory'),
    ('bitcoin', '31.1', 'update_available'), ('bitcoin', '31.2', 'fixed_for_advisory'),
    ('bitcoin', '28.9', 'unresolved'), ('bitcoin', '33.0', 'unresolved'),
])
def test_branch_boundaries(name, version, state):
    assert findings(name, version)[0]['state'] == state


@pytest.mark.parametrize('name,ecosystem,old,fixed,state', CASES)
def test_other_ecosystems_and_similar_names_do_not_match(tmp_path, name, ecosystem, old, fixed, state):
    for other in {'python', 'npm', 'homebrew', 'composer'} - {ecosystem}:
        root = tmp_path / other
        metadata(root, name, old, other)
        assert Scan().run([root])['records'] == []
    metadata(tmp_path / 'similar', name + '-client', old, ecosystem)
    assert Scan().run([tmp_path / 'similar'])['records'] == []


@pytest.mark.parametrize('spec,tap', [('head', 'homebrew/core'), ('stable', 'someone/custom'), (None, 'homebrew/core'), ('stable', None)])
def test_homebrew_head_custom_taps_and_missing_provenance_stay_unknown(tmp_path, spec, tap):
    path = metadata(tmp_path, 'jenkins-lts', '2.580.2', 'homebrew')
    row = json.loads(path.read_text())
    row['source'].update(spec=spec, tap=tap)
    path.write_text(json.dumps(row))
    record = Scan().run([tmp_path])['records'][0]
    assert record['advisories'][0]['state'] == 'unresolved'
    assert record['channel'] == 'lts'


@pytest.mark.parametrize('modern', [True, False])
def test_composer_multiple_packages_have_distinct_stable_records(tmp_path, modern):
    path = metadata(tmp_path, 'drupal/core', '11.4.9', 'composer')
    rows = [{'name': 'drupal/core', 'version': '11.4.9'}, {'name': 'laravel/framework', 'version': 'v12.67.0'},
            {'name': 'unrelated/library', 'version': '1.0.0'}]
    path.write_text(json.dumps({'packages': rows} if modern else rows))
    records = Scan().run([tmp_path])['records']
    assert len(records) == 2 and len({r['id'] for r in records}) == 2
    assert {r['path'] for r in records} == {str(path)}
    assert all(r['advisories'][0]['state'] == 'affected_version' for r in records)
    rows[1]['version'] = 'v12.68.0'
    path.write_text(json.dumps({'packages': rows} if modern else rows))
    updated = Scan().run([tmp_path])['records']
    assert {r['id'] for r in records} == {r['id'] for r in updated}
    assert next(r for r in updated if r['name'] == 'laravel/framework')['advisories'][0]['state'] == 'fixed_for_advisory'


@pytest.mark.parametrize('data', [None, {}, {'packages': {}}, {'packages': [1]},
    {'packages': [{'name': 'drupal/core', 'version': '11.4.10'}, {'name': 'drupal/core', 'version': '11.4.9'}]},
    {'packages': [{'name': 'drupal/core', 'version': ['11.4.10']}]},
    {'packages': [{'name': f'other/{n}', 'version': '1.0.0'} for n in range(2001)]},
])
def test_malformed_or_duplicate_composer_metadata_is_incomplete(tmp_path, data):
    path = metadata(tmp_path, 'drupal/core', '11.4.9', 'composer')
    path.write_text(json.dumps(data))
    report = Scan().run([tmp_path])
    assert report['incomplete'] and report['records'] == []


def test_composer_limits_symlinks_and_desired_versions(tmp_path):
    path = metadata(tmp_path, 'drupal/core', '11.4.9', 'composer')
    assert Scan(max_entries=3).run([tmp_path])['incomplete']
    path.write_text(' ' * 262145)
    assert Scan().run([tmp_path])['incomplete']
    path.unlink()
    target = tmp_path / 'outside.json'
    target.write_text('{"packages": [{"name":"drupal/core", "version":"11.4.9"}]}')
    path.symlink_to(target)
    report = Scan().run([tmp_path])
    assert report['incomplete'] and not report['records']
    path.unlink()
    (tmp_path / 'composer.lock').write_text(target.read_text())
    (tmp_path / 'composer.json').write_text('{"require":{"drupal/core":"11.4.9"}}')
    assert Scan().run([tmp_path])['records'] == []


def test_composer_entries_obey_shared_scan_budget(tmp_path):
    path = metadata(tmp_path, 'drupal/core', '11.4.9', 'composer')
    rows = [{'name': f'other/{n}', 'version': '1.0.0'} for n in range(30)]
    rows.append({'name': 'drupal/core', 'version': '11.4.9'})
    path.write_text(json.dumps({'packages': rows}))
    report = Scan(max_entries=15).run([tmp_path])
    assert report['incomplete'] and not report['records']
    assert report['scanned_entries'] == 15


def test_cli_never_executes_package_code(tmp_path):
    marker = tmp_path / 'executed'
    metadata(tmp_path, 'langflow', '1.12.8', 'python')
    metadata(tmp_path, 'next', '15.5.27', 'npm')
    metadata(tmp_path, 'drupal/core', '11.4.9', 'composer')
    (tmp_path / 'sitecustomize.py').write_text(f'open({str(marker)!r}, "w").write("executed")')
    (tmp_path / 'vendor/composer/installed.php').write_text('<?php file_put_contents(' + json.dumps(str(marker)) + ', "executed");')
    package = tmp_path / 'node_modules/next/package.json'
    row = json.loads(package.read_text())
    row['scripts'] = {'postinstall': f'touch "{marker}"'}
    package.write_text(json.dumps(row))
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run([sys.executable, str(root / 'tools/supply_inventory.py'), str(tmp_path)],
                            cwd=root, check=True, capture_output=True, text=True)
    report = json.loads(result.stdout)
    assert len(report['records']) == 3 and not report['incomplete']
    assert not marker.exists()
    assert {r['name'] for r in report['records']} == {'langflow', 'next', 'drupal/core'}


def test_composer_declared_normalized_version_cannot_override_observed_release(tmp_path):
    path = metadata(tmp_path, 'laravel/framework', 'v12.67.0', 'composer')
    path.write_text(json.dumps({'packages': [{'name': 'laravel/framework', 'version': 'v12.67.0',
        'version_normalized': '12.68.0.0', 'install-path': '../../untrusted',
        'autoload': {'files': ['evil.php']}}]}))
    record = Scan().run([tmp_path])['records'][0]
    assert record['advisories'][0]['state'] == 'affected_version'
    assert record['version'] == '12.67.0'
    assert record['path'] == str(path)


@pytest.mark.parametrize('name', ['jenkins.lts', 'jenkins_lts'])
def test_homebrew_names_do_not_use_python_package_alias_rules(tmp_path, name):
    metadata(tmp_path, name, '2.580.1', 'homebrew')
    assert Scan().run([tmp_path])['records'] == []
