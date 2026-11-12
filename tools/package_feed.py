"""Publisher-side metadata ingestion and signing. Never downloads package code.

Run with ``python -m tools.package_feed --help``. Private signing keys stay on
the publisher; the endpoint needs only the public key and signed policy file.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import csv
from datetime import datetime, timezone
import hashlib
import io
import json
import os
import re
import shutil
import time
from pathlib import Path
import zipfile
from urllib.parse import urlsplit, parse_qs

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from server.package_intelligence import (SOURCES, atomic_write, build_payload,
    canonical, datadog_records, github_records, now, osv_records, reviewed_github_records, sign, timestamp)
from server.package_transport import download


def modification_key(value):
    """Compare RFC3339 nanoseconds without treating trailing zeroes as changes."""
    date = timestamp(value)
    match = re.search(r'T\d{2}:\d{2}:\d{2}\.(\d+)', value)
    fraction = match.group(1) if match else ''
    if len(fraction) > 9:
        raise ValueError('Unsupported timestamp precision')
    return int(date.replace(microsecond=0).timestamp()) * 1_000_000_000 + int(fraction.ljust(9, '0'))


def github_sync(previous=None, *, fetch=download, token=None, checkpoint_path=None):
    """Inclusive cursor and id upserts preserve withdrawals. Commit after success.

    Both active and withdrawn records are explicitly requested. A bounded upper
    timestamp avoids pagination drifting as advisories change during ingestion.
    """
    previous = previous or {'cursor': None, 'documents': {}}
    started = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    documents = dict(previous['documents'])
    checkpoint = Path(checkpoint_path) if checkpoint_path else None
    if checkpoint:
        header = checkpoint / 'run.json'
        if header.exists():
            saved = json.loads(header.read_bytes())
            age = time.time() - datetime.fromisoformat(saved['started']).timestamp()
            if saved['base_cursor'] == previous['cursor'] and 0 <= age < 23 * 3600:
                started = saved['started']
            else:
                shutil.rmtree(checkpoint)
        if not header.exists():
            atomic_write(header, canonical({'base_cursor': previous['cursor'], 'started': started}))
    updated = f'{previous["cursor"]}..{started}' if previous['cursor'] else '<=' + started
    for ecosystem in ('npm', 'pip'):
        for withdrawn in ('false', 'true'):
            after, cursors = None, set()
            for page_number in range(10000):
                saved_page = checkpoint / f'{ecosystem}-{withdrawn}-{page_number:05d}.json' if checkpoint else None
                if saved_page and saved_page.exists():
                    saved = json.loads(saved_page.read_bytes())
                    if saved['after'] != after:
                        raise ValueError('Inconsistent ingestion checkpoint')
                    for document in saved['batch']:
                        documents[document['ghsa_id']] = document
                    if saved['next'] is None:
                        break
                    if saved['next'] in cursors:
                        raise ValueError('Repeated checkpoint cursor')
                    after = saved['next']
                    cursors.add(after)
                    continue
                params = {
                    'type': 'malware', 'ecosystem': ecosystem, 'is_withdrawn': withdrawn,
                    'updated': updated, 'sort': 'updated', 'direction': 'asc', 'per_page': 100}
                if after:
                    params['after'] = after
                data, headers = fetch('https://api.github.com/advisories', token=token, params=params, include_headers=True)
                batch = json.loads(data)
                if not isinstance(batch, list):
                    raise ValueError('Invalid GitHub page')
                for document in batch:
                    documents[document['ghsa_id']] = document
                link = httpx.Response(200, headers=headers).links.get('next', {}).get('url')
                if not link:
                    if saved_page:
                        atomic_write(saved_page, canonical({'after': after, 'next': None, 'batch': batch}))
                    break
                parsed = urlsplit(link)
                if parsed.scheme != 'https' or parsed.netloc != 'api.github.com' or parsed.path != '/advisories':
                    raise ValueError('Untrusted GitHub pagination link')
                values = parse_qs(parsed.query).get('after', [])
                if len(values) != 1 or values[0] in cursors:
                    raise ValueError('Invalid or repeated GitHub cursor')
                if saved_page:
                    atomic_write(saved_page, canonical({'after': after, 'next': values[0], 'batch': batch}))
                after = values[0]
                cursors.add(after)
            else:
                raise ValueError('GitHub pagination limit reached; snapshot not published')
    return {'cursor': started, 'documents': documents}


def openssf_export(ecosystem, *, fetch=download):
    """Consume OpenSSF MAL records from the public OSV mirror, without extraction."""
    data = fetch(f'https://storage.googleapis.com/osv-vulnerabilities/{ecosystem}/all.zip', limit=512 * 1024 * 1024)
    total = 0
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        if len(archive.infolist()) > 500_000:
            raise ValueError('Too many OSV entries')
        for entry in archive.infolist():
            if not entry.filename.startswith('MAL-') or not entry.filename.endswith('.json'):
                continue
            total += entry.file_size
            if entry.file_size > 2 * 1024 * 1024 or total > 2 * 1024 * 1024 * 1024:
                raise ValueError('OSV expansion limit reached')
            document = json.loads(archive.read(entry))
            yield document


def openssf_sync(previous=None, *, fetch=download, reviewed_ids=frozenset(), checkpoint_dir=None):
    """Bootstrap bulk metadata once, then apply OSV's modification index deltas."""
    result = {'_reviewed_ids': sorted(reviewed_ids)}
    review_changes = set(previous.get('_reviewed_ids', [])) ^ set(reviewed_ids) if previous else set()
    def normalize(document):
        excluded = []
        rows = list(osv_records(document, reviewed_ids=reviewed_ids, excluded=excluded))
        return {'modified': document['modified'], 'rows': rows, 'excluded': excluded}
    for ecosystem in ('npm', 'PyPI'):
        index = {}
        data = fetch(f'https://storage.googleapis.com/osv-vulnerabilities/{ecosystem}/modified_id.csv', limit=64 * 1024 * 1024)
        for modified, identifier in csv.reader(io.StringIO(data.decode())):
            if not identifier.startswith('MAL-'):
                continue
            if not re.fullmatch(r'MAL-[0-9]{4}-[0-9]+', identifier):
                raise ValueError('Invalid OSV index identity')
            timestamp(modified)
            index[identifier] = modified
        if not index:
            raise ValueError('Empty OpenSSF modification index')
        if previous and ecosystem in previous:
            cached = dict(previous[ecosystem])
        else:
            def bulk_fetch(url, **kwargs):
                path = Path(checkpoint_dir) / f'openssf-{ecosystem}.zip' if checkpoint_dir else None
                if path and path.exists() and time.time() - path.stat().st_mtime < 23 * 3600:
                    return path.read_bytes()
                content = fetch(url, **kwargs)
                if path:
                    atomic_write(path, content)
                return content
            cached = {document['id']: normalize(document) for document in openssf_export(ecosystem, fetch=bulk_fetch)}
        changed = [identifier for identifier, modified in index.items()
                   if identifier not in cached or modification_key(cached[identifier]['modified']) != modification_key(modified) or identifier in review_changes]
        def update(identifier):
            document = json.loads(fetch('https://api.osv.dev/v1/vulns/' + identifier, limit=2 * 1024 * 1024))
            if document['id'] != identifier or modification_key(document['modified']) < modification_key(index[identifier]):
                raise ValueError('OSV API has not caught up with modification index')
            return identifier, normalize(document)
        with ThreadPoolExecutor(max_workers=4) as executor:
            for identifier, normalized in executor.map(update, changed):
                cached[identifier] = normalized
        # Removed/withdrawn exports do not remain permanent name bans.
        result[ecosystem] = {identifier: cached[identifier] for identifier in index}
    return result


def collect(*, state_dir, openssf_dir=None, reviewed_ids=frozenset(), fetch=download, token=None, full_github_refresh=False, checkpoint_dir=None):
    state_dir = Path(state_dir)
    records, metadata = [], {}
    for ecosystem, folder in [('npm', 'npm'), ('PyPI', 'pypi')]:
        url = f'https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/main/samples/{folder}/manifest.json'
        data = fetch(url)
        records.extend(datadog_records(json.loads(data), ecosystem))
        metadata['datadog-' + ecosystem] = dict(url=url, fetched_at=now(), sha256=hashlib.sha256(data).hexdigest(), license='Apache-2.0')
    github_path = state_dir / 'github.json'
    previous = json.loads(github_path.read_bytes()) if github_path.exists() else None
    github = github_sync(None if full_github_refresh else previous, fetch=fetch, token=token,
                         checkpoint_path=Path(checkpoint_dir or state_dir) / 'github-progress')
    approvals = json.loads((Path(__file__).resolve().parents[1] / 'server/assets/package-intelligence/reviewed-malware.json').read_bytes())
    for identifier in approvals:
        document = json.loads(fetch('https://api.github.com/advisories/' + identifier, token=token))
        if document['ghsa_id'] != identifier:
            raise ValueError('Reviewed advisory identity mismatch')
        github['documents'][identifier] = document
    for document in github['documents'].values():
        if document['ghsa_id'] in approvals:
            records.extend(reviewed_github_records(document, approvals[document['ghsa_id']]))
        else:
            records.extend(github_records(document))
    metadata['github'] = dict(url=SOURCES['github'][1], fetched_at=github['cursor'], license='CC-BY-4.0',
                              sha256=hashlib.sha256(canonical(github)).hexdigest())
    digest, count, excluded = hashlib.sha256(), 0, []
    if openssf_dir:
        documents = (json.loads(path.read_bytes()) for path in sorted(Path(openssf_dir).rglob('MAL-*.json')))
        for document in documents:
            digest.update(canonical(document))
            count += 1
            records.extend(osv_records(document, reviewed_ids=reviewed_ids, excluded=excluded))
    else:
        cache = openssf_sync(previous.get('openssf') if previous else None, fetch=fetch, reviewed_ids=reviewed_ids,
                             checkpoint_dir=Path(checkpoint_dir or state_dir))
        github['openssf'] = cache
        for ecosystem in ('npm', 'PyPI'):
            for document in cache[ecosystem].values():
                digest.update(canonical(document))
                count += 1
                records.extend(document['rows'])
                excluded.extend(document['excluded'])
    if not count:
        raise ValueError('Empty OpenSSF source; refusing to clear its records')
    metadata['openssf'] = dict(url=SOURCES['openssf'][1], fetched_at=now(), license='Apache-2.0',
        transport='local OSV files' if openssf_dir else 'OSV bulk and modification-index deltas',
        sha256=digest.hexdigest(), excluded_records=len(excluded), excluded=excluded)
    return records, metadata, github


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    keys = sub.add_parser('keygen', help='Create development/publisher Ed25519 keys; never overwrites')
    keys.add_argument('--private-key', type=Path, required=True)
    keys.add_argument('--public-key', type=Path, required=True)
    build = sub.add_parser('build', help='Fetch all three metadata sources and sign a full replacement policy')
    build.add_argument('--private-key', type=Path, required=True)
    build.add_argument('--state-dir', type=Path, required=True)
    build.add_argument('--output', type=Path, required=True)
    build.add_argument('--sequence', type=int, required=True)
    build.add_argument('--openssf-dir', type=Path, help='Use a local OpenSSF OSV directory instead of OSV bulk exports')
    build.add_argument('--reviewed-ids', type=Path, help='JSON list of explicitly reviewed OpenSSF MAL IDs')
    build.add_argument('--full-github-refresh', action='store_true', help='Reconcile deleted reports as well as withdrawals; run periodically')
    args = parser.parse_args(argv)
    if args.command == 'keygen':
        if args.private_key.exists() or args.public_key.exists():
            parser.error('Key files already exist')
        key = Ed25519PrivateKey.generate()
        for path, data in [(args.private_key, key.private_bytes_raw()), (args.public_key, key.public_key().public_bytes_raw())]:
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
        return
    reviewed = json.loads(args.reviewed_ids.read_bytes()) if args.reviewed_ids else []
    if not isinstance(reviewed, list) or any(not isinstance(item, str) or not item.startswith('MAL-') for item in reviewed):
        parser.error('reviewed-ids must be a list of MAL IDs')
    key = Ed25519PrivateKey.from_private_bytes(args.private_key.read_bytes())
    # Refuse sequence reuse before fetching. An output file is the publisher's
    # durable sequence floor; production CI must preserve it between invocations.
    from server.package_intelligence import PolicyStore
    store = PolicyStore(args.output, key.public_key().public_bytes_raw())
    if store.policy and args.sequence <= store.policy.payload['sequence']:
        parser.error('Sequence must increase')
    records, sources, github = collect(state_dir=args.state_dir, openssf_dir=args.openssf_dir,
        reviewed_ids=frozenset(reviewed), token=os.environ.get('GITHUB_TOKEN'), full_github_refresh=args.full_github_refresh)
    payload = build_payload(records, args.sequence, sources)
    store.install(sign(payload, key))
    # Cursor commits after publication, so a crash cannot skip unpublished data.
    atomic_write(args.state_dir / 'github.json', canonical(github))
    print(json.dumps(store.status(), indent=2))


if __name__ == '__main__':
    main()
