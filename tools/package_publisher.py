"""Durable feed publisher: stage, inspect, promote; serve only verified releases.

One mounted state directory and one pinned signing identity per deployment.
Snapshots and ingestion cursors commit together through an atomic release pointer.
"""
import argparse
import base64
from contextlib import contextmanager
import fcntl
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import threading
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from server.package_intelligence import (MAX_BYTES, atomic_write, build_payload, canonical,
                                         sign, timestamp, verify)
from tools.package_feed import collect

REQUIRED_SOURCES = {'github', 'openssf', 'datadog-npm', 'datadog-PyPI'}


def active_blocks(policy):
    return {(row['source'], row['id'], row['ecosystem'], row['name']): row
            for row in policy.payload['records'] if row['disposition'] == 'block' and not row['withdrawn']}


def review_changes(previous, candidate):
    """Deterministic publication guard, not an upstream confidence score."""
    old, new = active_blocks(previous) if previous else {}, active_blocks(candidate)
    added, removed = set(new) - set(old), set(old) - set(new)
    changed = {key for key in set(old) & set(new) if old[key]['selectors'] != new[key]['selectors']}
    broad = [key for key in added | changed if any(s['kind'] == 'all' or (
        s['kind'] == 'interval' and s['introduced'] is None and s['end'] is None) for s in new[key]['selectors'])]
    reasons = []
    if previous is None:
        reasons.append('Initial baseline requires review')
    elif len(added) + len(changed) > max(100, len(old) * .20):
        reasons.append('Large increase or change in blocking records')
    if previous and len(removed) > max(25, len(old) * .10):
        reasons.append('Large removal of blocking records')
    if len(broad) > 25:
        reasons.append('Many new package-wide blocks')
    # Source collapse is significant even if the records were review-only.
    for source in ('github', 'openssf', 'datadog'):
        before = sum(row['source'] == source for row in previous.payload['records']) if previous else 0
        after = sum(row['source'] == source for row in candidate.payload['records'])
        if before and after < before * .8:
            reasons.append('Source record count collapsed: ' + source)
    return dict(added=len(added), removed=len(removed), changed=len(changed), new_package_wide=len(broad),
                requires_review=bool(reasons), reasons=reasons)


class Publisher:
    def __init__(self, directory, key):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.key = key
        self.public = key.public_key().public_bytes_raw()
        self.error = None
        self.lock = threading.RLock()
        self.update_lock = threading.RLock()
        self.cached = None
        self.current()  # Invalid durable state must not silently become a new baseline.

    @contextmanager
    def exclusive(self):
        # Source collection may take minutes. Readers must keep serving the
        # approved immutable snapshot while this writer lock is held.
        with self.update_lock, (self.directory / 'publisher.lock').open('a+b') as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(stream, fcntl.LOCK_UN)

    def current(self):
        pointer = self.directory / 'current.json'
        if not pointer.exists():
            return None
        value = json.loads(pointer.read_bytes())
        with self.lock:
            if self.cached is None or self.cached['digest'] != value['sha256']:
                self.cached = self.release(value['sha256'])
            return self.cached

    def release(self, digest):
        if len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
            raise ValueError('Invalid candidate digest')
        directory = self.directory / 'candidates' / digest
        with (directory / 'policy.json').open('rb') as stream:
            data = stream.read(MAX_BYTES + 1)
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError('Candidate digest mismatch')
        policy = verify(data, self.public)
        return dict(digest=digest, directory=directory, data=data, policy=policy)

    def stage(self, *, collector=collect, token=None, full=False):
        with self.exclusive():
            current = self.current()
            previous = current['policy'] if current else None
            source_state = current['directory'] if current else self.directory / 'initial-source-state'
            last_full = json.loads((source_state / 'publisher.json').read_bytes()).get('last_full', 0) if current else 0
            full = full or time.time() - last_full > 7 * 86400
            records, sources, github = collector(state_dir=source_state, token=token, full_github_refresh=full,
                                                  checkpoint_dir=self.directory / 'ingest')
            if set(sources) != REQUIRED_SOURCES:
                raise ValueError('Required source is missing')
            for source in sources.values():
                age = time.time() - timestamp(source['fetched_at']).timestamp()
                if not -300 <= age < 86400:
                    raise ValueError('Source timestamp is stale or in the future')
            sequence = previous.payload['sequence'] + 1 if previous else 1
            payload = build_payload(records, sequence, sources)
            data = sign(payload, self.key)
            policy = verify(data, self.public)
            review = review_changes(previous, policy)
            digest = hashlib.sha256(data).hexdigest()
            directory = self.directory / 'candidates' / digest
            atomic_write(directory / 'github.json', canonical(github))
            atomic_write(directory / 'publisher.json', canonical({'last_full': time.time() if full else last_full}))
            atomic_write(directory / 'review.json', canonical(review))
            atomic_write(directory / 'policy.json', data)
            if review['requires_review']:
                atomic_write(self.directory / 'pending.json', canonical({'sha256': digest}))
            self.prune()
            return dict(sha256=digest, sequence=sequence, **review)

    def prune(self):
        protected = set()
        for name in ('current.json', 'pending.json'):
            path = self.directory / name
            if path.exists():
                protected.add(json.loads(path.read_bytes())['sha256'])
        candidates = sorted((self.directory / 'candidates').iterdir(), key=lambda path: path.stat().st_mtime, reverse=True)
        for directory in candidates[8:]:
            if directory.name not in protected and not directory.is_symlink():
                shutil.rmtree(directory)

    def promote(self, digest, *, approved=False):
        with self.exclusive():
            release = self.release(digest)
            current = self.current()
            sequence = current['policy'].payload['sequence'] if current else 0
            if release['policy'].payload['sequence'] != sequence + 1:
                raise ValueError('Candidate must immediately follow current sequence; restage it')
            if release['policy'].status()['stale']:
                raise ValueError('Candidate is stale; restage it')
            review = review_changes(current['policy'] if current else None, release['policy'])
            if review['requires_review'] and not approved:
                raise ValueError('Candidate requires explicit digest approval')
            # Only this pointer makes both the snapshot and its cursors current.
            atomic_write(self.directory / 'current.json', canonical({'sha256': digest}))
            (self.directory / 'pending.json').unlink(missing_ok=True)
            self.error = None
            atomic_write(self.directory / 'status.json', canonical({'last_success': time.time(), 'error': None}))
            return release['policy'].status()

    def cycle(self):
        # Competing promotions are rejected by the sequence check. Only one
        # worker deployment should own this state volume.
        try:
            pending = self.directory / 'pending.json'
            if pending.exists():
                candidate = self.release(json.loads(pending.read_bytes())['sha256'])
                if not candidate['policy'].status()['stale']:
                    self.error = 'Candidate held for review: ' + candidate['digest']
                    return self.status()
            candidate = self.stage(token=os.environ.get('GITHUB_TOKEN'))
            if candidate['requires_review']:
                self.error = 'Candidate held for review: ' + candidate['sha256']
            else:
                self.promote(candidate['sha256'])
        except Exception as error:
            self.error = 'Publisher update failed: ' + type(error).__name__
        if self.error:
            atomic_write(self.directory / 'status.json', canonical({'last_failure': time.time(), 'error': self.error}))
        return self.status()

    def status(self):
        current = self.current()
        persisted = json.loads((self.directory / 'status.json').read_bytes()) if (self.directory / 'status.json').exists() else {}
        return {'available': current is not None, 'error': self.error or persisted.get('error'),
                **(current['policy'].status() if current else {'stale': True})}


def handler(publisher):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            if self.path == '/v1/policy.json':
                current = publisher.current()
                data, status = (current['data'], 200) if current else (canonical({'error': 'No approved baseline'}), 503)
            elif self.path in {'/healthz', '/readyz'}:
                value = publisher.status()
                data = canonical(value)
                status = 200 if self.path == '/healthz' or (value['available'] and not value['stale']) else 503
            else:
                data, status = b'{}', 404
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.end_headers()
            self.wfile.write(data)
    return Handler


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state-dir', type=Path, default=Path('/data'))
    parser.add_argument('--private-key', type=Path, help='Otherwise read BOXCOP_FEED_SIGNING_KEY_BASE64')
    sub = parser.add_subparsers(dest='command', required=True)
    stage = sub.add_parser('stage')
    stage.add_argument('--full', action='store_true')
    promote = sub.add_parser('promote')
    promote.add_argument('--sha256', required=True, help='Exact reviewed candidate digest')
    sub.add_parser('serve')
    args = parser.parse_args(argv)
    raw = args.private_key.read_bytes() if args.private_key else base64.b64decode(os.environ['BOXCOP_FEED_SIGNING_KEY_BASE64'], validate=True)
    publisher = Publisher(args.state_dir, Ed25519PrivateKey.from_private_bytes(raw))
    if args.command == 'stage':
        print(json.dumps(publisher.stage(token=os.environ.get('GITHUB_TOKEN'), full=args.full), indent=2))
    elif args.command == 'promote':
        print(json.dumps(publisher.promote(args.sha256, approved=True), indent=2))
    else:
        interval = int(os.environ.get('BOXCOP_FEED_INTERVAL_SECONDS', '900'))
        if interval < 60:
            parser.error('Update interval must be at least 60 seconds')
        def worker():
            while True:
                print(json.dumps(publisher.cycle()), flush=True)
                time.sleep(interval)
        threading.Thread(target=worker, daemon=True).start()
        # External HTTPS termination is supplied by the hosting platform. This
        # server exposes only public signed metadata, never signing operations.
        ThreadingHTTPServer((os.environ.get('BOXCOP_FEED_BIND_HOST', '127.0.0.1'),
                             int(os.environ.get('PORT', '8080'))), handler(publisher)).serve_forever()


if __name__ == '__main__':
    main()
