"""Offline, ecosystem-aware malware policy and authenticated snapshot storage.

Absence is unknown, never a safety verdict. No release-age policy. Feed prose is
never executable policy; only typed, validated selectors reach the matcher.
"""
from __future__ import annotations

import base64
from collections import defaultdict
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import tempfile
import zlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from packaging.version import Version as PythonVersion
from packaging.specifiers import SpecifierSet
from semantic_version import Version as NpmVersion, NpmSpec

SCHEMA = 'allay.package-policy.v1'
MAX_BYTES = 128 * 1024 * 1024
MAX_PAYLOAD_BYTES = 512 * 1024 * 1024
MAX_RECORDS = 1_000_000
# Signature domain of the existing publisher. Like SCHEMA, it is fixed by the feed BoxCop consumes.
COMPRESSED_CONTEXT = b'allay.package-policy.zlib.v1\x00'
SOURCES = {
    'openssf': ('Apache-2.0', 'https://github.com/ossf/malicious-packages'),
    'github': ('CC-BY-4.0', 'https://github.com/github/advisory-database'),
    'datadog': ('Apache-2.0', 'https://github.com/DataDog/malicious-software-packages-dataset'),
}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()


def timestamp(value):
    date = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if date.tzinfo is None:
        raise ValueError('Timestamp must include timezone')
    return date


def now():
    return datetime.now(timezone.utc).isoformat()


def package_name(ecosystem, name):
    if not isinstance(name, str) or len(name) > 214:
        raise ValueError('Invalid package name')
    if ecosystem == 'PyPI':
        if not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?', name):
            raise ValueError('Invalid Python package name')
        return re.sub(r'[-_.]+', '-', name).lower()
    if ecosystem == 'npm':
        # Historical npm packages can have uppercase names. Preserve case;
        # lowercasing would conflate distinct registry identities.
        if not re.fullmatch(r'(?:@[A-Za-z0-9._-]+/)?[A-Za-z0-9._-]+', name):
            raise ValueError('Invalid npm package name')
        return name
    raise ValueError('Unsupported ecosystem')


def version(ecosystem, value):
    if not isinstance(value, str) or not 0 < len(value) <= 128:
        raise ValueError('Invalid version')
    return PythonVersion(value) if ecosystem == 'PyPI' else NpmVersion(value)


def specifier(ecosystem, value):
    if not isinstance(value, str) or not 0 < len(value) <= 2048:
        raise ValueError('Invalid version range')
    if ecosystem == 'PyPI':
        return SpecifierSet(value)
    # GitHub uses ">= 1.0.0, < 2.0.0"; NpmSpec expects ">=1.0.0 <2.0.0".
    normalized = re.sub(r'([<>=~^]+)\s+', r'\1', value.replace(',', ' '))
    return NpmSpec(' '.join(normalized.split()))


def validate_selector(ecosystem, selector):
    kind = selector.get('kind')
    if kind == 'all' and set(selector) == {'kind'}:
        return
    if kind == 'exact' and set(selector) == {'kind', 'versions'}:
        if not isinstance(selector['versions'], list) or not selector['versions']:
            raise ValueError('Empty exact selector')
        for item in selector['versions']:
            version(ecosystem, item)
        return
    if kind == 'range' and set(selector) == {'kind', 'value'}:
        specifier(ecosystem, selector['value'])
        return
    if kind == 'interval' and set(selector) == {'kind', 'introduced', 'end', 'inclusive'}:
        start, end = selector['introduced'], selector['end']
        if start is not None:
            version(ecosystem, start)
        if end is not None:
            version(ecosystem, end)
        if type(selector['inclusive']) is not bool:
            raise ValueError('Invalid interval')
        if start is not None and end is not None and version(ecosystem, start) > version(ecosystem, end):
            raise ValueError('Reversed interval')
        return
    raise ValueError('Unsupported selector')


def matches(ecosystem, selector, candidate):
    parsed = version(ecosystem, candidate)
    kind = selector['kind']
    if kind == 'all':
        return True
    if kind == 'exact':
        return any(parsed == version(ecosystem, item) for item in selector['versions'])
    if kind == 'range':
        spec = specifier(ecosystem, selector['value'])
        return spec.contains(parsed, prereleases=True) if ecosystem == 'PyPI' else spec.match(parsed)
    start, end = selector['introduced'], selector['end']
    return (start is None or parsed >= version(ecosystem, start)) and (
        end is None or (parsed <= version(ecosystem, end) if selector['inclusive'] else parsed < version(ecosystem, end)))


class Policy:
    def __init__(self, payload):
        if payload.get('schema') != SCHEMA or type(payload.get('sequence')) is not int or payload['sequence'] < 1:
            raise ValueError('Invalid policy schema or sequence')
        timestamp(payload['generated_at'])
        if timestamp(payload['generated_at']).timestamp() > datetime.now(timezone.utc).timestamp() + 300:
            raise ValueError('Policy is from the future')
        records = payload['records']
        if not isinstance(records, list) or len(records) > MAX_RECORDS:
            raise ValueError('Invalid record count')
        self.payload = payload
        self.index = defaultdict(list)
        seen = set()
        for row in records:
            eco, name = row['ecosystem'], row['name']
            if package_name(eco, name) != name or row['source'] not in SOURCES:
                raise ValueError('Invalid package or source')
            if row['disposition'] not in {'block', 'review'} or not isinstance(row['id'], str) or not row['id']:
                raise ValueError('Invalid disposition or identity')
            if row['license'] != SOURCES[row['source']][0] or not row['url'].startswith('https://'):
                raise ValueError('Missing provenance')
            if row['withdrawn'] is not None:
                timestamp(row['withdrawn'])
            if not isinstance(row['selectors'], list):
                raise ValueError('Invalid selectors')
            for selector in row['selectors']:
                validate_selector(eco, selector)
            if row['disposition'] == 'block' and not row['selectors'] and row['withdrawn'] is None:
                raise ValueError('A blocking report needs a selector')
            identity = (row['source'], row['id'], eco, name)
            if identity in seen:
                raise ValueError('Duplicate report')
            seen.add(identity)
            if row['withdrawn'] is None:
                self.index[eco, name].append(row)

    def assess(self, ecosystem, name, candidate):
        """Return source records; mirrored reports do not become confidence votes."""
        try:
            name = package_name(ecosystem, name)
            version(ecosystem, candidate)
        except ValueError:
            return {'decision': 'unknown', 'reports': []}
        reports = [row for row in self.index.get((ecosystem, name), [])
                   if any(matches(ecosystem, selector, candidate) for selector in row['selectors'])]
        decision = 'block' if any(row['disposition'] == 'block' for row in reports) else 'review' if reports else 'unknown'
        return {'decision': decision, 'reports': reports}

    def status(self):
        age = max(0, datetime.now(timezone.utc).timestamp() - timestamp(self.payload['generated_at']).timestamp())
        return {'sequence': self.payload['sequence'], 'generated_at': self.payload['generated_at'],
                'records': len(self.payload['records']), 'stale': age > 86400,
                'sources': self.payload.get('sources', {}), 'unknown_policy': 'allow', 'release_age_policy': None}


def sign(payload, private_key):
    Policy(payload)
    data = canonical(payload)
    if len(data) > MAX_PAYLOAD_BYTES:
        raise ValueError('Expanded policy exceeds size limit')
    compressed = zlib.compress(data, level=6)
    return canonical({'encoding': 'zlib', 'payload': base64.b64encode(compressed).decode(),
                      'signature': base64.b64encode(private_key.sign(COMPRESSED_CONTEXT + compressed)).decode()})


def verify(data, public_key):
    if len(data) > MAX_BYTES:
        raise ValueError('Policy exceeds size limit')
    envelope = json.loads(data)
    payload = base64.b64decode(envelope['payload'], validate=True)
    key = Ed25519PublicKey.from_public_bytes(public_key)
    signature = base64.b64decode(envelope['signature'], validate=True)
    if envelope.get('encoding') == 'zlib':
        key.verify(signature, COMPRESSED_CONTEXT + payload)
        decoder = zlib.decompressobj()
        payload = decoder.decompress(payload, MAX_PAYLOAD_BYTES + 1)
        if len(payload) > MAX_PAYLOAD_BYTES or not decoder.eof or decoder.unused_data:
            raise ValueError('Invalid or oversized expanded policy')
    elif 'encoding' not in envelope:
        key.verify(signature, payload)  # Read earlier uncompressed development snapshots.
    else:
        raise ValueError('Unsupported policy encoding')
    return Policy(json.loads(payload))


def atomic_write(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


class PolicyStore:
    """Caller supplies a pinned key, never a key supplied by the downloaded feed.

    A single updater owns a store. The signed last-good file is the persistent
    sequence floor; deleting local state deliberately resets that protection.
    """
    def __init__(self, path, public_key):
        self.path, self.public_key = Path(path), public_key
        self.policy = None
        self.error = None
        if self.path.exists():
            with self.path.open('rb') as stream:
                self.policy = verify(stream.read(MAX_BYTES + 1), self.public_key)

    def install(self, data):
        candidate = verify(data, self.public_key)
        if self.policy:
            current, proposed = self.policy.payload, candidate.payload
            if proposed['sequence'] < current['sequence'] or timestamp(proposed['generated_at']) < timestamp(current['generated_at']):
                raise ValueError('Policy rollback refused')
            if proposed['sequence'] == current['sequence']:
                if canonical(proposed) != canonical(current):
                    raise ValueError('Policy sequence reused')
                return
        atomic_write(self.path, data)
        self.policy = candidate
        self.error = None

    def status(self):
        return {'available': self.policy is not None, 'update_error': self.error,
                **(self.policy.status() if self.policy else {'unknown_policy': 'allow', 'stale': True})}


def report(source, identifier, ecosystem, name, selectors, *, disposition='block', withdrawn=None, aliases=(), url=None, published=None, modified=None):
    return dict(source=source, id=identifier, ecosystem=ecosystem, name=package_name(ecosystem, name),
                selectors=selectors, disposition=disposition, withdrawn=withdrawn, aliases=sorted(set(aliases)),
                license=SOURCES[source][0], url=url or SOURCES[source][1], published=published, modified=modified)


def datadog_records(manifest, ecosystem):
    if not isinstance(manifest, dict) or not manifest:
        raise ValueError('Invalid or empty Datadog manifest')
    for name, versions in manifest.items():
        selector = {'kind': 'all'} if versions is None else {'kind': 'exact', 'versions': versions}
        disposition = 'block'
        try:
            validate_selector(ecosystem, selector)
        except ValueError:
            selector, disposition = None, 'review'
        yield report('datadog', f'{ecosystem}:{name}', ecosystem, name,
                     [selector] if selector else [], disposition=disposition)


def osv_records(document, *, reviewed_ids=frozenset(), excluded=None):
    """OpenSSF includes research/spam. Unreviewed reports are advisory-only.

    An operator can approve IDs after checking the primary report. Corroborating
    GitHub/Datadog selectors independently block their own affected versions.
    """
    identifier = document['id']
    if not identifier.startswith('MAL-'):
        return
    for affected in document.get('affected', []):
        package = affected['package']
        eco = package['ecosystem']
        if eco not in {'npm', 'PyPI'}:
            continue
        try:
            package_name(eco, package['name'])
        except ValueError:
            if excluded is not None:
                excluded.append({'id': identifier, 'reason': 'invalid_package_identity'})
            continue
        selectors = []
        unsupported = False
        if affected.get('versions'):
            selectors.append({'kind': 'exact', 'versions': affected['versions']})
        for interval in affected.get('ranges', []):
            if interval['type'] not in ({'SEMVER', 'ECOSYSTEM'} if eco == 'npm' else {'ECOSYSTEM'}):
                unsupported = True
                continue
            start, opened = None, False
            for event in interval['events']:
                if len(event) != 1:
                    unsupported = True
                    break
                if 'introduced' in event and not opened:
                    start, opened = (None if event['introduced'] == '0' else event['introduced']), True
                elif opened and set(event) & {'fixed', 'last_affected', 'limit'}:
                    key = next(iter(event))
                    selectors.append({'kind': 'interval', 'introduced': start, 'end': event[key], 'inclusive': key == 'last_affected'})
                    opened = False
                else:
                    unsupported = True
                    break
            if opened and not unsupported:
                selectors.append({'kind': 'interval', 'introduced': start, 'end': None, 'inclusive': False})
        try:
            for selector in selectors:
                validate_selector(eco, selector)
        except ValueError:
            selectors, unsupported = [], True
        yield report('openssf', identifier, eco, package['name'], selectors,
                     disposition='block' if identifier in reviewed_ids and selectors and not unsupported else 'review',
                     withdrawn=document.get('withdrawn'), aliases=document.get('aliases', []),
                     published=document.get('published'), modified=document.get('modified'),
                     url='https://osv.dev/vulnerability/' + identifier)


def github_records(document):
    if document.get('type') != 'malware':
        return
    for affected in document.get('vulnerabilities', []):
        package = affected['package']
        eco = {'npm': 'npm', 'pip': 'PyPI'}.get(package['ecosystem'])
        if eco is None:
            continue
        selector = {'kind': 'range', 'value': affected['vulnerable_version_range']}
        try:
            validate_selector(eco, selector)
            selectors, disposition = [selector], 'block'
        except ValueError:
            selectors, disposition = [], 'review'
        # Imported OpenSSF reports keep the conservative review policy, rather
        # than acquiring stronger confidence just by appearing in another feed.
        aliases = [item['value'] for item in document.get('identifiers', [])]
        references = document.get('references', [])
        if any(value.startswith('MAL-') for value in aliases) or any('ossf/malicious-packages' in value or 'osv.dev/vulnerability/MAL-' in value for value in references):
            disposition = 'review'
        yield report('github', document['ghsa_id'], eco, package['name'], selectors,
                     disposition=disposition, withdrawn=document.get('withdrawn_at'), aliases=aliases,
                     published=document.get('published_at'), modified=document.get('updated_at'),
                     url=document['html_url'])


def reviewed_github_records(document, approval):
    """Explicit, repository-reviewed malware exceptions; never general CVE blocking."""
    for row in github_records(dict(document, type='malware')):
        versions = approval.get(row['ecosystem'], {}).get(row['name'], [])
        supported = [candidate for candidate in versions if any(
            matches(row['ecosystem'], selector, candidate) for selector in row['selectors'])]
        if supported:
            row['selectors'] = [{'kind': 'exact', 'versions': supported}]
            row['disposition'] = 'block'
            row['classification_review'] = {'reviewed_at': approval['reviewed_at'], 'source': approval['source']}
            yield row


def build_payload(records, sequence, sources, generated_at=None):
    # Some upstream reports repeat the same package with disjoint selectors.
    grouped = {}
    for row in records:
        key = row['source'], row['id'], row['ecosystem'], row['name']
        if key in grouped:
            previous = grouped[key]
            previous['selectors'] += [s for s in row['selectors'] if s not in previous['selectors']]
            if row['disposition'] == 'review':
                previous['disposition'] = 'review'
        else:
            grouped[key] = dict(row, selectors=list(row['selectors']))
    payload = dict(schema=SCHEMA, sequence=sequence, generated_at=generated_at or now(), sources=sources,
                   records=[grouped[key] for key in sorted(grouped)])
    notices = Path(__file__).parent / 'assets/package-intelligence'
    payload['licenses'] = {name: (notices / (name + '.txt')).read_text() for name in ('Apache-2.0', 'CC-BY-4.0')}
    payload['attribution'] = (notices / 'NOTICE.txt').read_text()
    Policy(payload)
    return payload
