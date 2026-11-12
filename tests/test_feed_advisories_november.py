"""Offline discovery, version boundaries and non-enforcement regressions."""
import json
import plistlib
import subprocess
import sys

import pytest
from server.exposure_advisories import findings
from server.software_inventory import Scan, defaults
from server.supply_chain import command_findings
from tests.test_feed_advisories import metadata


CASES = [
    ('@better-auth/expo', 'npm', '1.7.15', '1.7.16', 'affected_version'),
    ('better-auth', 'npm', '1.7.15', '1.7.16', 'affected_version'),
    ('freerdp', 'homebrew', '3.32.1', '3.32.2', 'update_available'),
    ('tailscale', 'homebrew', '1.104.3', '1.104.4', 'update_available'),
    ('headscale', 'homebrew', '0.29.6', '0.29.7', 'update_available'),
]


@pytest.mark.parametrize('name,ecosystem,old,fixed,state', CASES)
def test_discovery_upgrade_unknown_and_wrong_ecosystem(tmp_path, name, ecosystem, old, fixed, state):
    previous = None
    for version, expected in [(old, state), (fixed, 'fixed_for_advisory'),
                              (fixed + '-vendor', 'unresolved'), ('', 'unresolved')]:
        metadata(tmp_path, name, version, ecosystem)
        report = Scan().run([tmp_path])
        assert len(report['records']) == 1
        record = report['records'][0]
        row = record['advisories'][0]
        assert row['state'] == expected
        assert row['enforcement'] == 'finding_only'
        assert row['verification'] == 'primary_reviewed'
        assert row['reviewed_at'] == report['reviewed_at'] == '2026-11-04'
        assert record['finding'] is None
        assert record['running_state'] == record['configuration'] == 'unknown'
        if previous:
            assert record['id'] == previous['id']
            assert record['metadata_sha256'] != previous['metadata_sha256']
        previous = record
        assert report['incomplete'] == (not version)
    for other in {'python', 'npm', 'homebrew', 'composer'} - {ecosystem}:
        root = tmp_path / other
        metadata(root, name, old, other)
        assert Scan().run([root])['records'] == []
    metadata(tmp_path / 'similar', name + '-client', old, ecosystem)
    assert Scan().run([tmp_path / 'similar'])['records'] == []


@pytest.mark.parametrize('name,version,state', [
    ('@better-auth/expo', '1.3.9', 'unresolved'),
    ('@better-auth/expo', '1.4.0-beta.5', 'unresolved'),
    ('@better-auth/expo', '1.4.0-beta.6', 'affected_version'),
    ('@better-auth/expo', '1.4.0', 'affected_version'),
    ('better-auth', '1.3.9', 'affected_version'),
    *[(n, v, s) for n in ('@better-auth/expo', 'better-auth') for v, s in [
        ('1.8.0-beta.0', 'affected_version'), ('1.8.0-beta.4', 'affected_version'),
        ('1.8.0-beta.5', 'fixed_for_advisory'), ('1.8.0-beta.6', 'fixed_for_advisory'),
        ('1.8.0-beta.05', 'unresolved'), ('1.8.0-rc.1', 'unresolved'),
        ('1.8.0', 'unresolved'), ('2.0.0', 'unresolved'), ('1.7.16+custom', 'unresolved')]],
    ('freerdp', '2.11.7', 'unresolved'), ('freerdp', '4.0.0', 'unresolved'),
    ('headscale', '0.30.0', 'unresolved'), ('headscale', '0.28.0', 'unresolved'),
    ('tailscale', '2.0.0', 'unresolved'), ('tailscale', '1.104.4-dev', 'unresolved'),
    ('teamviewer', '15.82', 'update_available'), ('teamviewer', '15.83', 'fixed_for_advisory'),
    ('teamviewer', '15.83.1', 'fixed_for_advisory'), ('teamviewer', '15.64.10', 'update_available'),
    ('teamviewer', '14.7.48867', 'update_available'), ('teamviewer', '14.7.48868', 'fixed_for_advisory'),
    ('teamviewer', '13.2.154006', 'update_available'), ('teamviewer', '13.2.154007', 'fixed_for_advisory'),
    ('teamviewer', '13.2.36231', 'update_available'), ('teamviewer', '16.0.0', 'unresolved'),
    ('teamviewer', '14.8.0', 'unresolved'), ('teamviewer', '15.83-custom', 'unresolved'),
])
def test_branch_and_platform_boundaries(name, version, state):
    assert findings(name, version)[0]['state'] == state


def app(root, identifier, version):
    path = root / 'Fixture.app/Contents/Info.plist'
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(plistlib.dumps({'CFBundleIdentifier': identifier, 'CFBundleShortVersionString': version}))


@pytest.mark.parametrize('identifier,name,old,fixed', [
    ('com.teamviewer.TeamViewer', 'teamviewer', '15.82.1', '15.83.1'),
    ('com.teamviewer.TeamViewerHost', 'teamviewer', '13.2.154006', '13.2.154007'),
    ('io.tailscale.ipn.macos', 'tailscale', '1.104.3', '1.104.4'),
    ('io.tailscale.ipn.macsys', 'tailscale', '1.104.3', '1.104.4'),
])
def test_app_discovery_and_unknown_identity(tmp_path, identifier, name, old, fixed):
    for version, expected in [(old, 'update_available'), (fixed, 'fixed_for_advisory'), ('', 'unresolved')]:
        app(tmp_path, identifier, version)
        record, = Scan().run([tmp_path])['records']
        assert record['name'] == name
        assert record['advisories'][0]['state'] == expected
        assert record['finding'] is None
    app(tmp_path, identifier + '.unrelated', old)
    assert not Scan().run([tmp_path])['records']


def test_chrome_november_is_separate_from_october(tmp_path):
    for version, states in [
        ('156.0.8078.78', ['update_available', 'update_available']),
        ('156.0.8078.80', ['fixed_for_advisory', 'update_available']),
        ('157.0.8103.37', ['fixed_for_advisory', 'update_available']),
        ('157.0.8103.38', ['fixed_for_advisory', 'fixed_for_advisory']),
        ('157.0.8103.39', ['fixed_for_advisory', 'fixed_for_advisory']),
        ('157.0.8103.38-vendor', ['unresolved', 'unresolved']),
        ('', ['unresolved', 'unresolved']),
    ]:
        app(tmp_path, 'com.google.Chrome', version)
        record, = Scan().run([tmp_path])['records']
        assert [a['state'] for a in record['advisories']] == states
        assert [a['id'] for a in record['advisories']] == ['chrome-october-update', 'chrome-november-update']
        assert all(a['enforcement'] == 'finding_only' for a in record['advisories'])
        assert record['running_state'] == 'unknown'
    app(tmp_path, 'org.chromium.Chromium', '156.0.8078.78')
    assert not Scan().run([tmp_path])['records']


def test_automatic_layouts_reach_new_packages_without_host_scan(tmp_path, monkeypatch):
    roots = [tmp_path / str(i) for i in range(len(defaults(home=tmp_path)))]
    for root in roots:
        root.mkdir()
    app(roots[0], 'com.teamviewer.TeamViewer', '15.82.1')
    for name in ('freerdp', 'tailscale', 'headscale'):
        path = roots[2] / name / 'installed/INSTALL_RECEIPT.json'
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps({'source': {'tap': 'homebrew/core', 'spec': 'stable', 'versions': {'stable': 'unknown'}}}))
    for name in ('@better-auth/expo', 'better-auth', 'node-red'):
        metadata(roots[8] / 'v26.12.1/lib', name, '1.7.15', 'npm')
    monkeypatch.setattr('server.software_inventory.defaults', lambda: roots)
    report = Scan().run()
    assert not report['incomplete']
    assert {r['name'] for r in report['records']} == {
        'teamviewer', 'freerdp', 'tailscale', 'headscale', '@better-auth/expo', 'better-auth', 'node-red'}


@pytest.mark.parametrize('name', ['freerdp', 'tailscale', 'headscale'])
def test_unverified_homebrew_builds(tmp_path, name):
    path = metadata(tmp_path, name, {'freerdp': '3.32.2', 'tailscale': '1.104.4', 'headscale': '0.29.7'}[name], 'homebrew')
    original = json.loads(path.read_text())
    for changes in [{'tap': 'other/custom'}, {'spec': 'head'}, {'tap': None}]:
        data = {'source': {**original['source'], **changes}}
        path.write_text(json.dumps(data))
        record, = Scan().run([tmp_path])['records']
        assert record['advisories'][0]['state'] == 'unresolved'


def test_node_red_is_configuration_review_even_after_version_update(tmp_path):
    for version in ['1.0.0', '4.3.4', '4.3.4-1', '99.0.0', '']:
        metadata(tmp_path, 'node-red', version, 'npm')
        record, = Scan().run([tmp_path])['records']
        row = record['advisories'][0]
        assert row['state'] == 'configuration_review'
        assert row['enforcement'] == 'finding_only'
        assert 'No npm version' in row['fixed_versions']
        assert record['configuration'] == 'unknown'
    metadata(tmp_path / 'unrelated', 'node-red-dashboard', '1.0.0', 'npm')
    assert not Scan().run([tmp_path / 'unrelated'])['records']


def test_cli_does_not_execute_settings_or_install_scripts(tmp_path):
    marker = tmp_path / 'executed'
    for name in ('node-red', '@better-auth/expo', 'better-auth'):
        path = metadata(tmp_path, name, '1.7.15', 'npm')
        row = json.loads(path.read_text())
        row['scripts'] = {'install': f'touch {marker}'}
        path.write_text(json.dumps(row))
    (tmp_path / 'settings.js').write_text(f'require("fs").writeFileSync({json.dumps(str(marker))}, "executed")')
    result = subprocess.run([sys.executable, '-m', 'server.software_inventory', '--root', str(tmp_path)],
                            capture_output=True, text=True, check=True)
    report = json.loads(result.stdout)
    assert len(report['records']) == 3 and not report['incomplete']
    assert not marker.exists()
    assert 'writeFileSync' not in result.stdout
    for command in ['npm install @better-auth/expo@1.7.15', 'npm install node-red', 'brew install freerdp', 'git status']:
        assert command_findings(command) == []  # Advisory additions do not create install/command deny rules.
