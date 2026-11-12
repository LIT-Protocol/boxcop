import json
from pathlib import Path
import plistlib
import pytest
from server.exposure_advisories import findings
from server.software_inventory import Scan, open_root


@pytest.mark.parametrize('name,affected,fixed', [
    ('php','8.4.26','8.4.27'), ('node','22.23.3','22.23.4'), ('node','24.22.0','24.22.1'),
    ('node','26.12.0','26.12.1'), ('pillow','12.3.0','13.0.0'), ('ruby','4.0.8','4.0.9'),
    ('ruby','3.4.11','3.4.12'), ('ruby','3.3.12','3.3.13'), ('wasmtime','36.0.18','36.0.19'),
    ('wasmtime','42.0.0','43.0.0'), ('electrum','4.8.2','4.8.3')])
def test_affected_and_fixed(name,affected,fixed):
    assert any(r['state']=='affected_version' for r in findings(name,affected))
    assert all(r['state']!='affected_version' for r in findings(name,fixed))
    assert all(r['enforcement']=='finding_only' for r in findings(name,affected))


@pytest.mark.parametrize('name', ['php','node','pillow','ruby','wasmtime','electrum','chrome','firefox'])
@pytest.mark.parametrize('version', ['', 'unknown', '8.4.27-vendor-backport', '13.0.0rc1'])
def test_ambiguous_and_backport_not_clean(name,version):
    assert any(r['state']=='unresolved' for r in findings(name,version))
    assert not any(r['state']=='fixed_for_advisory' for r in findings(name,version))


def test_wasmtime_distinct_ranges_and_architecture():
    assert findings('wasmtime','43.0.0',architecture='arm64')[0]['state']=='fixed_for_advisory'
    assert findings('wasmtime','43.0.0',architecture='arm64')[1]['state']=='affected_version'
    for version in ['36.0.19','48.0.7','49.0.4','50.0.0']:
        assert findings('wasmtime',version,architecture='arm64')[1]['state']=='fixed_for_advisory'
    assert findings('wasmtime','49.0.3',architecture='x86_64')[1]['state']=='not_applicable_architecture'
    assert findings('wasmtime','49.0.3')[1]['state']=='unresolved'


def test_context_and_unverified_versions():
    assert findings('php','8.4.27')[1]['state']=='configuration_review'
    assert findings('firefox','153.6.0')[0]['state']=='unresolved'
    assert findings('firefox','153.6.0',channel='esr')[0]['state']=='fixed_for_advisory'
    assert findings('firefox','115.44.0',channel='esr')[0]['state']=='fixed_for_advisory'
    assert findings('firefox','158.0',channel='release')[0]['state']=='update_available'
    for name in ['tailscale','teamviewer','headscale']:
        row = findings(name,'999.0.0')[0]
        assert row['verification'] == 'primary_reviewed'
        assert row['state'] == 'unresolved'
    assert findings('not-reviewed','1.0.0')==[]


def metadata(root,name='pillow',version='12.3.0'):
    path=root/(name+'.dist-info')/'METADATA';path.parent.mkdir(parents=True)
    path.write_text(f'Name: {name}\nVersion: {version}\n')
    return path


def test_scanner_does_not_execute_and_recovers_after_update(tmp_path):
    path=metadata(tmp_path)
    (tmp_path/'sitecustomize.py').write_text('raise RuntimeError("must never execute")')
    report=Scan().run([tmp_path])
    assert len(report['records'])==1 and not report['incomplete']
    assert report['records'][0]['advisories'][0]['state']=='affected_version'
    old_digest=report['records'][0]['metadata_sha256']
    path.write_text('Name: Pillow\nVersion: 13.0.0\n')
    new=Scan().run([tmp_path])['records'][0]
    assert new['advisories'][0]['state']=='fixed_for_advisory'
    assert new['metadata_sha256']!=old_digest
    assert new['running_state']=='unknown'


def test_symlink_root_ancestor_and_metadata_rejected(tmp_path):
    real=tmp_path/'real';real.mkdir();metadata(real)
    alias=tmp_path/'alias';alias.symlink_to(real,target_is_directory=True)
    assert Scan().run([alias])['incomplete']
    (real/'package.json').symlink_to(real/'pillow.dist-info/METADATA')
    assert Scan().run([real])['incomplete']
    assert Scan().run([alias/'pillow.dist-info'])['records']==[]


def test_bounds_and_malformed_metadata(tmp_path):
    metadata(tmp_path)
    assert Scan(max_entries=1).run([tmp_path])['incomplete']
    assert Scan(max_seconds=0).run([tmp_path])['incomplete']
    (tmp_path/'package.json').write_text('[]')
    assert Scan().run([tmp_path])['incomplete']
    (tmp_path/'package.json').write_text('X'*262145)
    assert Scan().run([tmp_path])['incomplete']


def test_app_and_privileged_helper_are_observations_only(tmp_path):
    app=tmp_path/'Applications/Chrome.app/Contents';app.mkdir(parents=True)
    (app/'Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier':'com.google.Chrome','CFBundleShortVersionString':'155.0.0.0'}))
    helper=tmp_path/'Library/PrivilegedHelperTools/PT.updd';helper.parent.mkdir(parents=True);helper.write_text('synthetic inert helper')
    report=Scan().run([tmp_path])
    assert len(report['records'])==2
    assert {r['name'] for r in report['records']}=={'chrome','time4popcorn-helper'}
    assert all(r['trust']=='metadata_only' for r in report['records'])
    h=next(r for r in report['records'] if r['name']=='time4popcorn-helper')
    assert h['advisories'][0]['state']=='helper_review'
    assert 'root' in h['advisories'][0]['remediation'].lower()


def test_missing_roots_are_explicit_and_no_match_not_safe(tmp_path):
    report=Scan().run([tmp_path/'absent'])
    assert report['roots'][0]['state']=='absent'
    assert 'not proof of safety' in report['trust']


@pytest.mark.parametrize('relative_path', [
    'Broken.app/Contents/Info.plist',
    'Library/LaunchDaemons/PT.updd.plist',
])
def test_malformed_xml_plist_does_not_abort_scan_or_recheck(tmp_path, relative_path):
    broken_root = tmp_path/'broken'
    path = broken_root/relative_path
    path.parent.mkdir(parents=True)
    path.write_bytes(b'<?xml version="1.0"?><plist><dict><key>Name</key><string>A & B</string></dict></plist>')
    healthy_root = tmp_path/'healthy'
    metadata(healthy_root)

    # Scan the broken root first to verify later roots still produce findings.
    for _ in range(2):
        report = Scan().run([broken_root, healthy_root])
        assert report['incomplete']
        assert 'unreadable_or_invalid_metadata' in report['issues']
        assert len(report['records']) == 1
        assert report['records'][0]['name'] == 'pillow'
        assert report['records'][0]['advisories'][0]['state'] == 'affected_version'


def test_private_cache_rejects_symlink_and_replaces_target_not_destination(tmp_path):
    from server.software_inventory import save_report
    root=tmp_path/'private';root.mkdir(mode=0o700)
    target=tmp_path/'unrelated';target.write_text('unchanged')
    (root/'software-inventory.json').symlink_to(target)
    save_report({'schema':'test'},root)
    assert target.read_text()=='unchanged'
    assert json.loads((root/'software-inventory.json').read_text())['schema']=='test'
    assert (root/'software-inventory.json').stat().st_mode & 0o777 == 0o600
    alias=tmp_path/'alias';alias.symlink_to(root,target_is_directory=True)
    with pytest.raises(OSError): save_report({},alias)
    root.chmod(0o755)
    with pytest.raises(ValueError): save_report({},root)


def automatic_roots(tmp_path, monkeypatch):
    from server import software_inventory
    roots = software_inventory.defaults(tmp_path/'home')
    roots = [tmp_path/str(i)/root.name for i, root in enumerate(roots)]
    monkeypatch.setattr(software_inventory, 'defaults', lambda: roots)
    return roots


def test_automatic_scan_skips_payloads_and_reaches_later_roots(tmp_path, monkeypatch):
    roots = automatic_roots(tmp_path, monkeypatch)
    keg = roots[2]/'node'/'26.0.0'
    keg.mkdir(parents=True)
    (keg/'INSTALL_RECEIPT.json').write_text(json.dumps({'source': {'versions': {'stable': '26.0.0'}}}))
    # A large source tree must not consume the metadata inventory budget.
    payload = keg/'include'/'deep'
    payload.mkdir(parents=True)
    for i in range(100): (payload/str(i)).write_text('source')
    (keg/'alias').symlink_to(payload, target_is_directory=True)
    metadata(roots[4]/'3.12.0'/'lib'/'python3.12'/'site-packages')
    helper = roots[12]/'PT.updd'
    helper.parent.mkdir(parents=True)
    helper.write_text('inert')
    report = Scan(max_entries=100).run()
    assert not report['incomplete']
    assert {r['name'] for r in report['records']} == {'node', 'pillow', 'time4popcorn-helper'}
    assert report['scanned_entries'] < 30
    assert report['limitations']
    assert all(r['state'] in {'scanned', 'absent'} for r in report['roots'])


def test_automatic_npm_nested_scoped_packages_and_unknown_version(tmp_path, monkeypatch):
    roots = automatic_roots(tmp_path, monkeypatch)
    packages = roots[8]/'v22.0.0'/'lib'/'node_modules'
    package = packages/'tool'/'node_modules'/'@subql'/'common'
    package.mkdir(parents=True)
    (package/'package.json').write_text('{"name":"@subql/common","version":"1.0.0"}')
    config = package/'dist'/'esm'
    config.mkdir(parents=True)
    (config/'package.json').write_text('{"type":"module"}')
    unknown = packages/'litellm'
    unknown.mkdir()
    (unknown/'package.json').write_text('{"name":"litellm"}')
    report = Scan().run()
    assert not report['incomplete']
    assert any(r['name'] == '@subql/common' for r in report['records'])
    assert any(r['name'] == 'litellm' and r['version'] == 'unknown' for r in report['records'])


def test_root_budget_reserves_capacity_for_later_software(tmp_path):
    busy = tmp_path/'busy'
    busy.mkdir()
    for i in range(100): (busy/str(i)).write_text('payload')
    healthy = tmp_path/'healthy'
    metadata(healthy)
    report = Scan(max_entries=20).run([busy, healthy])
    assert report['incomplete']
    assert report['roots'][0]['state'] == 'partial'
    assert report['roots'][1]['state'] == 'scanned'
    assert report['records'][0]['name'] == 'pillow'
    assert report['issue_details'][0]['path'] == str(busy)


def test_repeated_errors_mark_each_root_partial(tmp_path):
    roots = [tmp_path/'one', tmp_path/'two']
    for root in roots:
        root.mkdir()
        (root/'package.json').write_text('invalid JSON')
    report = Scan().run(roots)
    assert [r['state'] for r in report['roots']] == ['partial', 'partial']
    assert {r['path'] for r in report['issue_details']} == {str(root/'package.json') for root in roots}


def test_automatic_wasmtime_bin_is_observed_without_execution(tmp_path, monkeypatch):
    roots = automatic_roots(tmp_path, monkeypatch)
    binary = roots[11]/'bin'/'wasmtime'
    binary.parent.mkdir(parents=True)
    binary.write_text('never execute')
    report = Scan().run()
    assert not report['incomplete']
    assert report['records'][0]['name'] == 'wasmtime'
    assert report['records'][0]['version'] == 'unknown'


def test_automatic_malformed_app_remains_a_visible_coverage_failure(tmp_path, monkeypatch):
    roots = automatic_roots(tmp_path, monkeypatch)
    contents = roots[0]/'Broken.app'/'Contents'
    contents.mkdir(parents=True)
    (contents/'Info.plist').write_text('malformed plist')
    report = Scan().run()
    assert report['incomplete']
    assert report['roots'][0]['state'] == 'partial'
    assert report['issue_details'] == [{'reason': 'unreadable_or_invalid_metadata', 'path': str(contents.parent)}]


@pytest.mark.parametrize('artifact', ['copyright_control', 'trailing_nulls', 'both'])
def test_plist_control_character_retry_preserves_original_metadata(tmp_path, artifact):
    import hashlib
    contents = tmp_path/'Chrome.app'/'Contents'
    contents.mkdir(parents=True)
    data = plistlib.dumps({'CFBundleIdentifier': 'com.google.Chrome',
                          'CFBundleShortVersionString': '156.0.0',
                          'NSHumanReadableCopyright': 'Copyright © Vendor'})
    if artifact in {'copyright_control', 'both'}:
        data = data.replace(b'Copyright ', b'Copyright \x03')
    if artifact in {'trailing_nulls', 'both'}:
        data += b'\x00\x00'
    path = contents/'Info.plist'
    path.write_bytes(data)
    report = Scan().run([tmp_path])
    assert not report['incomplete']
    assert report['records'][0]['name'] == 'chrome'
    assert report['records'][0]['version'] == '156.0.0'
    assert report['records'][0]['metadata_sha256'] == hashlib.sha256(data).hexdigest()
    assert path.read_bytes() == data


@pytest.mark.parametrize('fmt', [plistlib.FMT_XML, plistlib.FMT_BINARY])
def test_plist_original_parse_preserves_valid_values(fmt):
    from server.software_inventory import parse_plist
    row = {'value': 'tabs\tnewlines\nreturns\r', 'bytes': b'\x00\x03'}
    data = plistlib.dumps(row, fmt=fmt)
    assert parse_plist(data) == plistlib.loads(data)


def test_plist_retry_does_not_repair_other_invalid_xml():
    from server.software_inventory import parse_plist
    from xml.parsers.expat import ExpatError
    data = b'<?xml version="1.0"?><plist><dict><key>x</key><string>A & B\x03</string></dict></plist>'
    with pytest.raises(ExpatError):
        parse_plist(data)


def test_helper_plist_uses_control_character_fallback(tmp_path):
    path = tmp_path/'LaunchDaemons'/'PT.updd.plist'
    path.parent.mkdir()
    path.write_bytes(plistlib.dumps({'Label': 'inert.fixture'}) + b'\x00\x00')
    report = Scan().run([tmp_path])
    assert not report['incomplete']
    assert report['records'][0]['name'] == 'time4popcorn-helper'


@pytest.mark.parametrize('version,state', [
    ('156.0.8078.47', 'update_available'),
    ('156.0.8078.74', 'update_available'),
    ('156.0.8078.78', 'update_available'),
    ('156.0.8078.79', 'fixed_for_advisory'),
    ('156.0.8078.80', 'fixed_for_advisory'),
    ('156.0.8078.79-vendor', 'unresolved'),
])
def test_chrome_followup_security_baseline(version, state):
    row = findings('chrome', version)[0]
    assert row['state'] == state
    assert row['reviewed_at'] == '2026-11-03'
    assert row['source'].endswith('stable-channel-update-for-desktop_02107719452.html')
    assert row['enforcement'] == 'finding_only'


def test_chrome_followup_reached_from_app_inventory(tmp_path):
    app = tmp_path / 'Chrome.app/Contents'
    app.mkdir(parents=True)
    plist = app / 'Info.plist'
    for version, state in [('156.0.8078.74', 'update_available'), ('156.0.8078.79', 'fixed_for_advisory')]:
        plist.write_bytes(plistlib.dumps({'CFBundleIdentifier': 'com.google.Chrome', 'CFBundleShortVersionString': version}))
        records = Scan().run([tmp_path])['records']
        assert len(records) == 1
        assert records[0]['advisories'][0]['state'] == state
