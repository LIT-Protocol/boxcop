#!/usr/bin/env python3
"""Main-only release preflight and publication of an already-qualified macOS build."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import time
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_app import BuildError, validate_update_feed  # noqa: E402

REPO = 'LIT-Protocol/boxcop'
# GitHub repository IDs survive a rename or transfer; forks have different IDs.
REPOSITORY_ID = '1455881957'
ROOT = Path(__file__).resolve().parents[3]
THREAT_MANIFEST = ROOT / 'desktop/macos/Resources/ThreatDomains/manifest.json'
SPARKLE = '{http://www.andymatuschak.org/xml-namespaces/sparkle}'


def command(*args, **kwargs):
    return subprocess.check_output(list(map(str, args)), text=True, **kwargs).strip()


def release_repository():
    repo = os.environ.get('GITHUB_REPOSITORY')
    if (os.environ.get('GITHUB_REF') != 'refs/heads/main'
            or os.environ.get('GITHUB_REPOSITORY_ID') != REPOSITORY_ID
            or repo != REPO):
        raise ValueError('Releases must be dispatched from main in the original BoxCop repository')
    return repo


def update_feed(source=None):
    """The release's update feed and public key. Both are explicit inputs.

    BoxCop bakes in no update domain. A release without a feed could never
    update itself, so publication stops until both values are configured.
    """
    source = os.environ if source is None else source
    feed = source.get('BOXCOP_UPDATE_FEED_URL') or ''
    key = source.get('BOXCOP_UPDATE_PUBLIC_KEY') or ''
    if not feed or not key:
        raise ValueError('Set BOXCOP_UPDATE_FEED_URL and BOXCOP_UPDATE_PUBLIC_KEY; BoxCop has no default update feed')
    try:
        validate_update_feed(feed, key)
    except BuildError as exc:
        raise ValueError(str(exc)) from exc
    return feed, key


def download_prefix(feed, tag):
    """Release files are served beside the appcast, in a directory named after the tag."""
    return feed.rsplit('/', 1)[0] + '/' + tag + '/'


def version_tuple(version):
    if not re.fullmatch(r'(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)', version):
        raise ValueError('Version must be numeric major.minor.patch, without a v prefix')
    return tuple(map(int, version.split('.')))


def validate_new_version(version, releases):
    requested = version_tuple(version)
    for release in releases:
        tag = release['tagName']
        if tag == 'v' + version:
            raise ValueError('This release already exists (possibly as a draft); inspect it before retrying')
        if not release['isDraft'] and re.fullmatch(r'v\d+\.\d+\.\d+', tag):
            if requested <= version_tuple(tag[1:]):
                raise ValueError('Version must be newer than every published version')


def resolve_version(version, releases):
    if version is None or not version.strip():
        published = [version_tuple(row['tagName'][1:]) for row in releases
                     if not row['isDraft'] and re.fullmatch(r'v\d+\.\d+\.\d+', row['tagName'])]
        if published:
            major, minor, patch = max(published)
            version = f'{major}.{minor}.{patch + 1}'
        else:
            version = '0.1.0'
    validate_new_version(version, releases)
    return version


def prepare(version):
    repo = release_repository()
    feed, key = update_feed()
    if command('git', 'rev-parse', 'HEAD') != os.environ['GITHUB_SHA']:
        raise ValueError('Checkout does not match the main commit selected by this run')
    releases = json.loads(command('gh', 'release', 'list', '--repo', repo, '--limit', '1000', '--json', 'tagName,isDraft'))
    version = resolve_version(version, releases)
    # Checkout deliberately does not persist credentials. Let gh supply GH_TOKEN
    # through Git's credential protocol for this private-repository read only.
    if command('git', '-c', 'credential.helper=', '-c',
               'credential.helper=!gh auth git-credential',
               'ls-remote', '--tags', 'origin', 'refs/tags/v' + version):
        raise ValueError('Tag already exists; release tags are never overwritten')
    with open(os.environ['GITHUB_ENV'], 'a') as stream:
        stream.write(f'BOXCOP_VERSION={version}\nBOXCOP_EXTENSION_VERSION={int(time.time())}\n')
        stream.write(f'BOXCOP_UPDATE_FEED_URL={feed}\nBOXCOP_UPDATE_PUBLIC_KEY={key}\n')
    print(f'Release version: {version}')


def verify_key(private_key, public_key):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    seed = base64.b64decode(private_key, validate=True)
    actual = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()
    if actual != base64.b64decode(public_key, validate=True):
        raise ValueError('Sparkle signing key does not match the public key embedded in the app')


def verify_appcast(feed, archive, info, download_url):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    items = ET.parse(feed).findall('./channel/item')
    if len(items) != 1:
        raise ValueError('Expected one update in the release appcast')
    item = items[0]
    enclosure = item.find('enclosure')
    if (item.findtext(SPARKLE + 'version') != info['CFBundleVersion']
            or item.findtext(SPARKLE + 'shortVersionString') != info['CFBundleShortVersionString']
            or enclosure is None or enclosure.get('url') != download_url
            or int(enclosure.get('length', '0')) != archive.stat().st_size):
        raise ValueError('Appcast version, URL or archive size does not match this build')
    key = Ed25519PublicKey.from_public_bytes(base64.b64decode(info['SUPublicEDKey'], validate=True))
    key.verify(base64.b64decode(enclosure.get(SPARKLE + 'edSignature', ''), validate=True), archive.read_bytes())


def publish(output):
    repo = release_repository()
    feed_url, public_key = update_feed()
    version = os.environ['BOXCOP_VERSION']
    version_tuple(version)
    tag = 'v' + version
    sha = os.environ['GITHUB_SHA']
    info = plistlib.loads((output / 'BoxCop.app/Contents/Info.plist').read_bytes())
    evidence = json.loads((output / 'build-evidence.json').read_text())
    required = dict(profile='distribution', architecture='arm64', notarization='accepted_and_stapled',
                    signature_verification='passed', source_commit=sha, version=version)
    if any(evidence.get(k) != v for k, v in required.items()):
        raise ValueError('Build evidence is not qualified for this release')
    if info['CFBundleShortVersionString'] != version or info['CFBundleVersion'] != os.environ['BOXCOP_EXTENSION_VERSION']:
        raise ValueError('Bundle version does not match this release')
    if info.get('SUFeedURL') != feed_url or info.get('SUPublicEDKey') != public_key:
        raise ValueError('Bundle update feed does not match the feed configured for this release')
    symbols = output / 'BoxCop.dSYM'
    if not (symbols / 'Contents/Resources/DWARF/BoxCop').is_file():
        raise ValueError('Matching crash symbols are required for release')
    private_key = os.environ.pop('BOXCOP_SPARKLE_PRIVATE_KEY').strip()
    verify_key(private_key, info['SUPublicEDKey'])
    # The tools come from the same checksum-verified SPM artifact as the framework.
    candidates = list((ROOT / 'desktop/macos/.build-artifacts').glob('bundle-*/swift/artifacts/sparkle/Sparkle/bin'))
    if len(candidates) != 1:
        raise ValueError('Expected one clean CI build with pinned Sparkle tools')
    tools = candidates[0]
    assets = output / 'release'
    assets.mkdir()
    archive = assets / f'BoxCop-{version}-arm64.dmg'
    shutil.copy2(output / 'BoxCop.dmg', archive)
    prefix = download_prefix(feed_url, tag)
    feed = assets / 'appcast.xml'
    command(tools / 'generate_appcast', '--ed-key-file', '-', '--maximum-deltas', '0',
            '--download-url-prefix', prefix, '--link', f'https://github.com/{repo}/releases',
            '-o', feed, assets, input=private_key)
    verify_appcast(feed, archive, info, prefix + archive.name)
    command(tools / 'sign_update', '--verify', '--ed-key-file', '-', feed, input=private_key)
    shutil.copy2(output / 'build-evidence.json', assets)
    shutil.copy2(output / 'launch-smoke.txt', assets)
    # The release job refreshes this snapshot before building, so record what actually shipped.
    threats = json.loads(THREAT_MANIFEST.read_text())
    shutil.copy2(THREAT_MANIFEST, assets / 'threat-domains-manifest.json')
    # Archive after feed generation: debug symbols must never be an update enclosure.
    shutil.make_archive(str(assets / f'BoxCop-{version}-arm64-symbols'), 'zip', output, 'BoxCop.dSYM')
    checksums = assets / 'SHA256SUMS'
    checksums.write_text(''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n'
                                 for p in sorted(assets.iterdir()) if p.is_file()))
    notes = output / 'release-notes.md'
    notes.write_text(f'''BoxCop {version} for Apple silicon, macOS 14 or later (beta).

Download `{archive.name}`, open it, and drag BoxCop into Applications.

Later releases arrive through **Check for Updates** in the app. Updates are signed,
and installing one always requires your action.

Threat-domain list: {threats['source']}, {threats['count']:,} hostnames, published
{threats['publishedAt']} (upstream `{threats['revision']}`). See `threat-domains-manifest.json`.

Build: `{sha}`. Developer ID signed and notarized. CI verifies packaging and first
launch. It does not exercise the protections interactively.
''')
    # Stage all assets as a draft before publishing. Never clobber releases.
    command('gh', 'release', 'create', tag, '--repo', repo, '--target', sha, '--draft',
            '--title', f'BoxCop {version}', '--notes-file', notes, '--generate-notes',
            *sorted(p for p in assets.iterdir() if p.is_file()))
    command('gh', 'release', 'edit', tag, '--repo', repo, '--draft=false', '--latest')
    url = f'https://github.com/{repo}/releases/tag/{tag}'
    with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as stream:
        stream.write(f'Published [BoxCop {version}]({url}) from `{sha}`.\n')
    print(url)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['prepare', 'publish'])
    parser.add_argument('--version')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.action == 'prepare':
        prepare(args.version)
    else:
        publish(args.output)
