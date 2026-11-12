#!/usr/bin/env python3
"""Refresh the bundled HaGeZi threat-domain snapshot and its pinned manifest.

Resolves the newest upstream commit of the list, downloads the list and LICENSE at
that exact revision, validates them with the same host rules the Swift runtime
uses, and rewrites desktop/macos/Resources/ThreatDomains. Run locally to commit a
new snapshot, or in the release job so every release ships the current list.
Standard library only.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import sys
import time
import urllib.request

SOURCE = 'HaGeZi Threat Intelligence Feeds Mini'
REPO = 'hagezi/dns-blocklists'
LIST_PATH = 'wildcard/tif.mini-onlydomains.txt'
LICENSE_PATH = 'LICENSE'
DESTINATION = Path(__file__).resolve().parents[1] / 'Resources/ThreatDomains'
# Must match NetworkThreatPolicy / NetworkThreatProtection limits.
MAX_BYTES = 8 * 1024 * 1024
MAX_DOMAINS = 500_000
MIN_DOMAINS = 1_000
# A sudden collapse usually means a broken upstream build, not a safer internet.
MIN_RATIO_OF_PREVIOUS = 0.5
NEVER_LISTED = ['apple.com', 'google.com', 'github.com', 'cloudflare.com',
                'anthropic.com', 'openai.com', 'example.com', 'getallay.ai']
LABEL = re.compile(r'[a-z0-9-]{1,63}')
SHA = re.compile(r'[0-9a-f]{40}')


class RefreshError(Exception):
    pass


def tls_context():
    # python.org macOS builds ship without a CA bundle until "Install Certificates" runs.
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


def fetch(url, accept=None, attempts=4):
    headers = {'User-Agent': 'boxcop-release-threat-refresh'}
    if accept:
        headers['Accept'] = accept
    token = os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN')
    if token and url.startswith('https://api.github.com/'):
        headers['Authorization'] = f'Bearer {token}'
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=60,
                                        context=tls_context()) as response:
                return response.read(MAX_BYTES + 1)
        except OSError as error:
            if attempt == attempts - 1:
                raise RefreshError(f'Could not download {url}: {error}') from error
            time.sleep(2 ** attempt)


def normalize(value):
    """Python mirror of NetworkThreatPolicy.normalize."""
    if len(value.encode()) > 254 or not value.isascii():
        return None
    host = value[:-1] if value.endswith('.') else value
    host = host.lower()
    labels = host.split('.')
    if (len(labels) < 2 or len(host) > 253 or not re.search('[a-z]', labels[-1])
            or not all(LABEL.fullmatch(label) and label[0] != '-' and label[-1] != '-' for label in labels)):
        return None
    return host


def parse(data):
    if len(data) > MAX_BYTES:
        raise RefreshError('Threat list exceeds the runtime size limit')
    text = data.decode('utf-8')
    domains, header = set(), {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith('#'):
            key, _, value = line[1:].partition(':')
            header.setdefault(key.strip().lower(), value.strip())
            continue
        host = normalize(line)
        if host is None:
            raise RefreshError(f'Malformed threat list entry: {line[:80]!r}')
        domains.add(host)
    if not MIN_DOMAINS <= len(domains) <= MAX_DOMAINS:
        raise RefreshError(f'Unexpected threat list size: {len(domains)}')
    listed = sorted(set(NEVER_LISTED) & domains)
    if listed:
        raise RefreshError(f'Threat list blocks common service roots: {", ".join(listed)}')
    try:
        published = datetime.strptime(header['last modified'], '%d %b %Y %H:%M %Z')
    except (KeyError, ValueError) as error:
        raise RefreshError('Threat list has no parseable "Last modified" header') from error
    expected = header.get('number of entries')
    if expected is not None and int(expected) != len(domains):
        raise RefreshError(f'Threat list header says {expected} entries but {len(domains)} parsed')
    return domains, published.replace(tzinfo=timezone.utc)


def refresh(destination=DESTINATION, revision=None, max_age_days=None):
    if revision is None:
        commits = json.loads(fetch(f'https://api.github.com/repos/{REPO}/commits?path={LIST_PATH}&per_page=1',
                                   accept='application/vnd.github+json'))
        if not commits:
            raise RefreshError('Upstream has no commits for the threat list')
        revision = commits[0]['sha']
    if not SHA.fullmatch(revision):
        raise RefreshError('Upstream revision must be a full commit SHA')
    raw = f'https://raw.githubusercontent.com/{REPO}/{revision}/'
    data = fetch(raw + LIST_PATH)
    license_data = fetch(raw + LICENSE_PATH)
    if b'GNU GENERAL PUBLIC LICENSE' not in license_data or b'Version 3' not in license_data:
        raise RefreshError('Upstream license is no longer GPL-3.0; review before shipping')
    domains, published = parse(data)
    if max_age_days is not None and (datetime.now(timezone.utc) - published).days > max_age_days:
        raise RefreshError(f'Newest upstream list was published {published.isoformat()}; refusing a stale release list')

    manifest_path = destination / 'manifest.json'
    previous = json.loads(manifest_path.read_text()) if manifest_path.is_file() else {}
    if previous.get('count') and len(domains) < previous['count'] * MIN_RATIO_OF_PREVIOUS:
        raise RefreshError(f'Threat list shrank from {previous["count"]} to {len(domains)} entries')
    manifest = {
        'source': SOURCE,
        'revision': revision,
        'retrievedAt': datetime.now(timezone.utc).isoformat(),
        'publishedAt': published.strftime('%Y-%m-%dT%H:%M:%SZ'),
        'sourceURL': raw + LIST_PATH,
        'sha256': hashlib.sha256(data).hexdigest(),
        'license': 'GPL-3.0',
        'matching': 'exact hostname only',
        'count': len(domains),
    }
    if previous.get('sha256') == manifest['sha256']:
        manifest['retrievedAt'] = previous.get('retrievedAt', manifest['retrievedAt'])
    destination.mkdir(parents=True, exist_ok=True)
    (destination / 'domains.txt').write_bytes(data)
    (destination / 'LICENSE').write_bytes(license_data)
    manifest_path.write_text(json.dumps(manifest, indent=2) + '\n')
    return previous, manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--revision', help='Pin a specific upstream commit SHA instead of the newest one')
    parser.add_argument('--max-age-days', type=int,
                        help='Fail if the newest upstream list is older than this (release guard)')
    args = parser.parse_args()
    try:
        previous, manifest = refresh(revision=args.revision, max_age_days=args.max_age_days)
    except RefreshError as error:
        print(f'error: {error}', file=sys.stderr)
        return 1
    summary = (f'Threat list: {manifest["count"]:,} hostnames, published {manifest["publishedAt"]} '
               f'(`{manifest["revision"][:12]}`); previously {previous.get("count", 0):,} '
               f'published {previous.get("publishedAt", "never")}.')
    print(summary)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as stream:
            stream.write(summary + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
