"""Run the package publisher against a disposable checkout of the feed branch."""
import base64
import gzip
import json
import os
from pathlib import Path
import shutil

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tools.package_publisher import Publisher


def update(directory, key, approval):
    publisher = Publisher(directory, key)
    pending = directory / 'pending.json'
    pending_digest = json.loads(pending.read_bytes())['sha256'] if pending.exists() else None
    if approval:
        if pending_digest != approval:
            raise ValueError('Approval must match the pending candidate digest')
        publisher.promote(approval, approved=True)
    elif not pending_digest or publisher.release(pending_digest)['policy'].status()['stale']:
        current = publisher.current()
        if current:
            source = current['directory']
            with (source / 'github.json').open('wb') as out:
                for part in sorted(source.glob('cursor-*.gz')):
                    with gzip.open(part, 'rb') as stream:
                        shutil.copyfileobj(stream, out)
        candidate = publisher.stage(token=os.environ.get('GITHUB_TOKEN'))
        if current:
            (current['directory'] / 'github.json').unlink()
        if not candidate['requires_review']:
            publisher.promote(candidate['sha256'])

    current = publisher.current()
    keep = set()
    if current:
        keep.add(current['digest'])
        shutil.copyfile(current['directory'] / 'policy.json', directory / 'policy.json')
    if pending.exists():
        digest = json.loads(pending.read_bytes())['sha256']
        keep.add(digest)
        print('Pending review:', digest)
        print((directory / 'candidates' / digest / 'review.json').read_text())
    for candidate in (directory / 'candidates').iterdir():
        if candidate.name not in keep:
            shutil.rmtree(candidate)
            continue
        # Preserve ingestion cursors without exceeding GitHub's blob size limit.
        state = candidate / 'github.json'
        if state.exists():
            with state.open('rb') as source:
                for index, chunk in enumerate(iter(lambda: source.read(32 << 20), b'')):
                    (candidate / f'cursor-{index:05}.gz').write_bytes(gzip.compress(chunk, mtime=0))
            state.unlink()
    shutil.rmtree(directory / 'ingest', ignore_errors=True)
    (directory / 'publisher.lock').unlink(missing_ok=True)


def main():
    directory = Path(os.environ['FEED_DIRECTORY'])
    raw = base64.b64decode(os.environ['BOXCOP_FEED_SIGNING_KEY_BASE64'], validate=True)
    key = Ed25519PrivateKey.from_private_bytes(raw)
    pin = Path('desktop/macos/Resources/package-feed-public-key.txt').read_text().strip()
    if key.public_key().public_bytes_raw() != base64.b64decode(pin, validate=True):
        raise ValueError('Signing key does not match the bundled public key')
    update(directory, key, os.environ.get('APPROVE_DIGEST'))


if __name__ == '__main__':
    main()
