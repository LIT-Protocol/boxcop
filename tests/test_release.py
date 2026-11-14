"""Release safety: version ordering, signing identity, feed integrity and packaging."""
import base64
import importlib.util
import json
from pathlib import Path
import plistlib
import sys
import xml.etree.ElementTree as ET

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SCRIPTS = Path(__file__).resolve().parents[1] / 'desktop/macos/scripts'
sys.path.insert(0, str(SCRIPTS))
import release
import build_app

FEED = 'https://updates.example/boxcop/appcast.xml'


def feed_key(seed=b'u'):
    return base64.b64encode(Ed25519PrivateKey.from_private_bytes(seed * 32).public_key().public_bytes_raw()).decode()


@pytest.mark.parametrize('value', ['1.2', 'v1.2.3', '1.2.3\n', '01.2.3', '1.2.3-beta', '1.2.3;echo injected'])
def test_invalid_versions(value):
    with pytest.raises(ValueError):
        release.version_tuple(value)
    with pytest.raises(build_app.BuildError):
        build_app.release_version({'BOXCOP_VERSION': value})


def test_version_order_and_existing_drafts():
    release.validate_new_version('0.1.0', [])
    release.validate_new_version('1.10.0', [{'tagName': 'v1.9.0', 'isDraft': False}])
    for version in ['1.8.0', '1.9.0']:
        with pytest.raises(ValueError):
            release.validate_new_version(version, [{'tagName': 'v1.9.0', 'isDraft': False}])
    with pytest.raises(ValueError, match='already exists'):
        release.validate_new_version('1.10.0', [{'tagName': 'v1.10.0', 'isDraft': True}])


@pytest.mark.parametrize('value', [None, '', '   '])
def test_automatic_patch_version(value):
    assert release.resolve_version(value, []) == '0.1.0'
    releases = [{'tagName': tag, 'isDraft': draft} for tag, draft in [
        ('v1.9.20', False), ('v2.0.9', False), ('v2.0.10', False),
        ('v9.0.0', True), ('nightly', False)]]
    assert release.resolve_version(value, releases) == '2.0.11'
    assert release.resolve_version('3.0.0', releases) == '3.0.0'


def test_automatic_version_does_not_overwrite_pending_draft():
    with pytest.raises(ValueError, match='already exists'):
        release.resolve_version('', [{'tagName': 'v0.1.0', 'isDraft': False},
                                     {'tagName': 'v0.1.1', 'isDraft': True}])


def test_release_identity_is_the_boxcop_repository():
    assert release.REPO == 'LIT-Protocol/boxcop'
    assert release.REPOSITORY_ID == '1455881957'


def test_prepare_exports_resolved_version_and_configured_feed(tmp_path, monkeypatch):
    monkeypatch.setenv('GITHUB_REF', 'refs/heads/main')
    monkeypatch.setenv('GITHUB_REPOSITORY', release.REPO)
    monkeypatch.setenv('GITHUB_REPOSITORY_ID', release.REPOSITORY_ID)
    monkeypatch.setenv('GITHUB_SHA', 'fixture-sha')
    monkeypatch.setenv('BOXCOP_UPDATE_FEED_URL', FEED)
    monkeypatch.setenv('BOXCOP_UPDATE_PUBLIC_KEY', feed_key())
    env_file = tmp_path / 'env'
    monkeypatch.setenv('GITHUB_ENV', str(env_file))
    def command(*args):
        if args[:2] == ('git', 'rev-parse'):
            return 'fixture-sha'
        if args[:3] == ('gh', 'release', 'list'):
            assert args[args.index('--repo') + 1] == release.REPO
            return '[{"tagName":"v0.1.0","isDraft":false}]'
        assert args == ('git', '-c', 'credential.helper=', '-c',
                        'credential.helper=!gh auth git-credential',
                        'ls-remote', '--tags', 'origin', 'refs/tags/v0.1.1')
        return ''
    monkeypatch.setattr(release, 'command', command)
    release.prepare('')
    assert env_file.read_text().startswith('BOXCOP_VERSION=0.1.1\nBOXCOP_EXTENSION_VERSION=')
    exported = dict(line.split('=', 1) for line in env_file.read_text().splitlines())
    info = plistlib.loads((SCRIPTS.parent / 'Resources/Info.plist').read_bytes())
    info.update(build_app.release_metadata(exported))
    assert info['CFBundleShortVersionString'] == '0.1.1'
    assert info['SUFeedURL'] == FEED
    assert info['SUPublicEDKey'] == feed_key()


@pytest.mark.parametrize('missing', ['BOXCOP_UPDATE_FEED_URL', 'BOXCOP_UPDATE_PUBLIC_KEY'])
@pytest.mark.parametrize('action', ['prepare', 'publish'])
def test_release_requires_an_explicit_update_feed_before_side_effects(monkeypatch, missing, action):
    """No update domain is baked in: a release names its feed and key or does not start."""
    monkeypatch.setenv('GITHUB_REF', 'refs/heads/main')
    monkeypatch.setenv('GITHUB_REPOSITORY', release.REPO)
    monkeypatch.setenv('GITHUB_REPOSITORY_ID', release.REPOSITORY_ID)
    monkeypatch.setenv('BOXCOP_UPDATE_FEED_URL', FEED)
    monkeypatch.setenv('BOXCOP_UPDATE_PUBLIC_KEY', feed_key())
    monkeypatch.delenv(missing)
    monkeypatch.setattr(release, 'command', lambda *a, **kw: pytest.fail('Must not call GitHub'))
    with pytest.raises(ValueError, match='no default update feed'):
        getattr(release, action)('0.1.0' if action == 'prepare' else Path('/unused'))


@pytest.mark.parametrize('action', ['prepare', 'publish'])
def test_release_refuses_non_main_before_network(monkeypatch, action):
    monkeypatch.setenv('GITHUB_REF', 'refs/heads/untrusted')
    monkeypatch.setenv('GITHUB_REPOSITORY', release.REPO)
    monkeypatch.setenv('GITHUB_REPOSITORY_ID', release.REPOSITORY_ID)
    monkeypatch.setattr(release, 'command', lambda *a, **kw: pytest.fail('Must not call GitHub'))
    with pytest.raises(ValueError, match='main'):
        getattr(release, action)('0.1.0' if action == 'prepare' else Path('/unused'))


@pytest.mark.parametrize('repo,repo_id', [
    (release.REPO, '1'), ('example/other-project', '1434713741'),
    ('someone/boxcop', release.REPOSITORY_ID), (release.REPO, ''),
])
@pytest.mark.parametrize('action', ['prepare', 'publish'])
def test_release_rejects_other_repository_identity_before_side_effects(monkeypatch, repo, repo_id, action):
    monkeypatch.setenv('GITHUB_REF', 'refs/heads/main')
    monkeypatch.setenv('GITHUB_REPOSITORY', repo)
    monkeypatch.setenv('GITHUB_REPOSITORY_ID', repo_id)
    monkeypatch.setattr(release, 'command', lambda *a, **kw: pytest.fail('Must not call GitHub'))
    with pytest.raises(ValueError, match='original BoxCop repository'):
        getattr(release, action)('0.1.0' if action == 'prepare' else Path('/unused'))


@pytest.mark.parametrize('url', ['https://user:secret@updates.example/appcast.xml',
    'http://updates.example/appcast.xml', 'https://updates.example/appcast.xml\n',
    'https://updates.example/appcast.xml?channel=beta', 'https://updates.example/download', 'file:///tmp/appcast.xml'])
def test_invalid_update_feed_fails_before_build_writes(tmp_path, monkeypatch, url):
    monkeypatch.setenv('BOXCOP_UPDATE_FEED_URL', url)
    monkeypatch.setenv('BOXCOP_UPDATE_PUBLIC_KEY', feed_key())
    output = tmp_path / 'must-not-exist'
    with pytest.raises(build_app.BuildError, match='BOXCOP_UPDATE_FEED_URL'):
        build_app.build(output, host_system='Darwin', profile='limited-development')
    assert not output.exists()


def test_checkout_bakes_in_no_update_feed():
    assert build_app.release_metadata({}) == {}
    info = plistlib.loads((SCRIPTS.parent / 'Resources/Info.plist').read_bytes())
    assert 'SUFeedURL' not in info and 'SUPublicEDKey' not in info


def test_release_files_are_served_beside_the_appcast():
    assert release.download_prefix(FEED, 'v1.2.3') == 'https://updates.example/boxcop/v1.2.3/'


@pytest.fixture
def publication(tmp_path, monkeypatch):
    monkeypatch.setenv('GITHUB_REF', 'refs/heads/main')
    monkeypatch.setenv('GITHUB_REPOSITORY_ID', release.REPOSITORY_ID)
    monkeypatch.setenv('GITHUB_SHA', 'fixture-sha')
    monkeypatch.setenv('GITHUB_REPOSITORY', release.REPO)
    monkeypatch.setenv('BOXCOP_VERSION', '0.1.0')
    monkeypatch.setenv('BOXCOP_EXTENSION_VERSION', '123')
    monkeypatch.setenv('GITHUB_STEP_SUMMARY', str(tmp_path / 'summary'))
    key = Ed25519PrivateKey.generate()
    public = base64.b64encode(key.public_key().public_bytes_raw()).decode()
    monkeypatch.setenv('BOXCOP_SPARKLE_PRIVATE_KEY', base64.b64encode(key.private_bytes_raw()).decode())
    monkeypatch.setenv('BOXCOP_UPDATE_FEED_URL', FEED)
    monkeypatch.setenv('BOXCOP_UPDATE_PUBLIC_KEY', public)
    monkeypatch.setattr(release, 'ROOT', tmp_path)
    (tmp_path / 'desktop/macos/.build-artifacts/bundle-fixture/swift/artifacts/sparkle/Sparkle/bin').mkdir(parents=True)
    output = tmp_path / 'out'
    (output / 'BoxCop.app/Contents').mkdir(parents=True)
    (output / 'BoxCop.dmg').write_bytes(b'synthetic archive')
    (output / 'launch-smoke.txt').write_text('synthetic smoke')
    symbols = output / 'BoxCop.dSYM/Contents/Resources/DWARF/BoxCop'
    symbols.parent.mkdir(parents=True)
    symbols.write_bytes(b'synthetic debug symbols')
    (output / 'build-evidence.json').write_text(json.dumps(dict(
        profile='distribution', architecture='arm64', notarization='accepted_and_stapled',
        signature_verification='passed', source_commit='fixture-sha', version='0.1.0')))
    info = dict(CFBundleVersion='123', CFBundleShortVersionString='0.1.0', SUFeedURL=FEED, SUPublicEDKey=public)
    return output, info, key


@pytest.mark.parametrize('github_feed', [False, True])
def test_publication_uses_configured_feed_for_assets_and_github(publication, monkeypatch, github_feed):
    output, info, key = publication
    repo = release.REPO
    if github_feed:
        monkeypatch.setenv('BOXCOP_UPDATE_FEED_URL', release.GITHUB_FEED)
        info['SUFeedURL'] = release.GITHUB_FEED
    (output / 'BoxCop.app/Contents/Info.plist').write_bytes(plistlib.dumps(info))
    calls = []

    def command(*args, **kwargs):
        calls.append(args)
        if Path(args[0]).name == 'generate_appcast':
            prefix = args[args.index('--download-url-prefix') + 1]
            assert prefix == (f'https://github.com/{repo}/releases/download/v0.1.0/' if github_feed else 'https://updates.example/boxcop/v0.1.0/')
            assert args[args.index('--link') + 1] == 'https://github.com/LIT-Protocol/boxcop/releases'
            archive = output / 'release/BoxCop-0.1.0-arm64.dmg'
            root = ET.Element('rss')
            item = ET.SubElement(ET.SubElement(root, 'channel'), 'item')
            ET.SubElement(item, release.SPARKLE + 'version').text = '123'
            ET.SubElement(item, release.SPARKLE + 'shortVersionString').text = '0.1.0'
            ET.SubElement(item, 'enclosure', {'url': prefix + archive.name,
                'length': str(archive.stat().st_size),
                release.SPARKLE + 'edSignature': base64.b64encode(key.sign(archive.read_bytes())).decode()})
            ET.ElementTree(root).write(args[args.index('-o') + 1])
        return ''

    monkeypatch.setattr(release, 'command', command)
    release.publish(output)
    github = [c for c in calls if c[0] == 'gh']
    assert [c[2] for c in github] == ['create', 'edit']
    assert all(c[c.index('--repo') + 1] == repo for c in github)
    assert '--draft' in github[0] and '--draft=false' in github[1]
    symbols = output / 'release/BoxCop-0.1.0-arm64-symbols.zip'
    assert symbols.is_file()
    assert symbols in github[0]
    assert symbols.name in (output / 'release/SHA256SUMS').read_text()
    threats = json.loads(release.THREAT_MANIFEST.read_text())
    assert (output / 'release/threat-domains-manifest.json').is_file()
    assert threats['revision'] in (output / 'release-notes.md').read_text()
    summary = (output.parent / 'summary').read_text()
    assert f'https://github.com/{repo}/releases/tag/v0.1.0' in summary
    notes = (output / 'release-notes.md').read_text()
    assert 'BoxCop 0.1.0' in notes


def test_publication_rejects_bundle_with_wrong_feed_before_signing(publication, monkeypatch):
    output, info, _ = publication
    info['SUFeedURL'] = 'https://other.example/appcast.xml'
    (output / 'BoxCop.app/Contents/Info.plist').write_bytes(plistlib.dumps(info))
    monkeypatch.setattr(release, 'command', lambda *a, **kw: pytest.fail('Must not sign or publish'))
    with pytest.raises(ValueError, match='update feed does not match'):
        release.publish(output)
    assert not (output / 'release').exists()


def test_publication_rejects_bundle_built_with_another_update_key(publication, monkeypatch):
    output, info, _ = publication
    info['SUPublicEDKey'] = feed_key(b'x')
    (output / 'BoxCop.app/Contents/Info.plist').write_bytes(plistlib.dumps(info))
    monkeypatch.setattr(release, 'command', lambda *a, **kw: pytest.fail('Must not sign or publish'))
    with pytest.raises(ValueError, match='update feed does not match'):
        release.publish(output)


def test_key_must_match_embedded_public_key():
    key = Ed25519PrivateKey.generate()
    private = base64.b64encode(key.private_bytes_raw()).decode()
    public = base64.b64encode(key.public_key().public_bytes_raw()).decode()
    release.verify_key(private, public)
    with pytest.raises(ValueError, match='does not match'):
        release.verify_key(private, base64.b64encode(b'x' * 32).decode())


def test_feed_binds_version_url_length_and_archive_bytes(tmp_path):
    from cryptography.exceptions import InvalidSignature
    key = Ed25519PrivateKey.generate()
    archive = tmp_path / 'BoxCop.dmg'
    archive.write_bytes(b'release archive')
    info = dict(CFBundleVersion='123', CFBundleShortVersionString='0.1.0',
                SUPublicEDKey=base64.b64encode(key.public_key().public_bytes_raw()).decode())
    root = ET.Element('rss')
    item = ET.SubElement(ET.SubElement(root, 'channel'), 'item')
    ET.SubElement(item, release.SPARKLE + 'version').text = '123'
    ET.SubElement(item, release.SPARKLE + 'shortVersionString').text = '0.1.0'
    url = 'https://updates.example/boxcop/v0.1.0/BoxCop.dmg'
    enclosure = ET.SubElement(item, 'enclosure', {'url': url, 'length': str(archive.stat().st_size),
                    release.SPARKLE + 'edSignature': base64.b64encode(key.sign(archive.read_bytes())).decode()})
    feed = tmp_path / 'appcast.xml'
    ET.ElementTree(root).write(feed)
    release.verify_appcast(feed, archive, info, url)
    for attribute, value in [('url', 'https://attacker.example/update'), ('length', '1')]:
        original = enclosure.get(attribute)
        enclosure.set(attribute, value)
        ET.ElementTree(root).write(feed)
        with pytest.raises(ValueError):
            release.verify_appcast(feed, archive, info, url)
        enclosure.set(attribute, original)
    ET.ElementTree(root).write(feed)
    archive.write_bytes(b'changed archive')
    with pytest.raises(InvalidSignature):
        release.verify_appcast(feed, archive, info, url)


def test_sparkle_framework_copy_keeps_links_and_removes_unused_services(tmp_path):
    scratch = tmp_path / 'swift'
    framework = scratch / 'artifacts/sparkle/Sparkle/Sparkle.xcframework/macos-arm64_x86_64/Sparkle.framework'
    (framework / 'Versions/B/XPCServices').mkdir(parents=True)
    (framework / 'Versions/B/Sparkle').write_bytes(b'framework')
    (framework / 'Versions/Current').symlink_to('B')
    (framework / 'Sparkle').symlink_to('Versions/Current/Sparkle')
    (framework / 'XPCServices').symlink_to('Versions/Current/XPCServices')
    contents = tmp_path / 'BoxCop.app/Contents'
    contents.mkdir(parents=True)
    build_app.embed_sparkle(scratch, contents)
    embedded = contents / 'Frameworks/Sparkle.framework'
    assert (embedded / 'Sparkle').is_symlink()
    assert (embedded / 'Sparkle').read_bytes() == b'framework'
    assert not (embedded / 'Versions/B/XPCServices').exists()


def test_sparkle_helper_envelope_signed_before_framework_and_host(tmp_path, monkeypatch):
    app = tmp_path / 'BoxCop.app'
    framework = app / 'Contents/Frameworks/Sparkle.framework'
    helper = framework / 'Versions/B/Updater.app'
    executable = helper / 'Contents/MacOS/Updater'
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b'\xcf\xfa\xed\xfe')
    calls = []
    monkeypatch.setattr(build_app, 'run', lambda c: calls.append(c))
    build_app.sign_bundle(app, identity='fixture', hardened=True)
    assert [c[-1] for c in calls if '--sign' in c] == [executable, helper, framework, app]
    assert all('--timestamp' in c and '--deep' not in c for c in calls if '--sign' in c)


@pytest.mark.parametrize('verify_before_extraction', [False, True])
def test_packaged_sparkle_startup(tmp_path, verify_before_extraction):
    """Run with BOXCOP_UPDATER_TEST_EXECUTABLE pointing to a freshly built BoxCop.

    Both cases execute real Sparkle, without entering the app's GUI/event loop.
    The broken configuration must fail even though its code signature is valid.
    """
    import os
    import shutil
    import subprocess
    import uuid
    executable = os.environ.get('BOXCOP_UPDATER_TEST_EXECUTABLE')
    if sys.platform != 'darwin' or not executable:
        pytest.skip('Requires macOS and an explicitly supplied freshly built executable')
    executable = Path(executable).resolve()
    app = tmp_path / 'BoxCop.app'
    contents = app / 'Contents'
    (contents / 'MacOS').mkdir(parents=True)
    shutil.copy2(executable, contents / 'MacOS/BoxCop')
    shutil.copytree(executable.parent / 'Sparkle.framework', contents / 'Frameworks/Sparkle.framework', symlinks=True)
    info = plistlib.loads((SCRIPTS.parent / 'Resources/Info.plist').read_bytes())
    info.update(SUFeedURL=FEED, SUPublicEDKey=feed_key())
    info['CFBundleIdentifier'] = 'local.boxcop.updater-test.' + uuid.uuid4().hex
    info['SUEnableAutomaticChecks'] = False
    assert info['SURequireSignedFeed'] is True
    assert info['SUVerifyUpdateBeforeExtraction'] is True
    if not verify_before_extraction:
        del info['SUVerifyUpdateBeforeExtraction']
    (contents / 'Info.plist').write_bytes(plistlib.dumps(info))
    build_app.sign_bundle(app)
    result = subprocess.run([str(contents / 'MacOS/BoxCop'), '--check-updater-startup'],
                            capture_output=True, text=True, timeout=10)
    if verify_before_extraction:
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == 'UPDATER_STARTUP_PASS'
    else:
        assert result.returncode == 1
        assert 'SUVerifyUpdateBeforeExtraction' in result.stderr
        assert 'SURequireSignedFeed' in result.stderr
