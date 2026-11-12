"""Small, bounded, durable log of blocked actions.

One JSON file per protection layer, rewritten atomically under a lock so the
long-lived engine and one-shot contained runs can both append. Entries hold
package names and hostnames only, never payloads, credentials or file content.
"""
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import secrets

from .package_intelligence import atomic_write, canonical

LIMIT = 200


def private_directory(path):
    """Create missing folders owner-only at every level, whatever the umask allows.

    The engine refuses a data folder that other users can read, so a helper that
    creates a subfolder first must not leave the parent world-readable.
    """
    path, missing = Path(path), []
    while not path.exists():
        missing.append(path)
        path = path.parent
    for folder in reversed(missing):
        try:
            os.mkdir(folder, 0o700)
        except FileExistsError:
            pass


def now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


class EventLog:
    def __init__(self, path, *, limit=LIMIT):
        self.path, self.limit = Path(path), limit

    def read(self):
        """Oldest first. A missing or damaged log reads as empty."""
        try:
            with self.path.open('rb') as stream:
                rows = json.loads(stream.read(4 * 1024 * 1024))
            return [row for row in rows if isinstance(row, dict) and isinstance(row.get('id'), str)
                    and isinstance(row.get('time'), str)][-self.limit:]
        except (OSError, ValueError, TypeError):
            return []

    def append(self, entry, *, repeat_of=None):
        """Add one entry. A repeat of the newest matching entry only raises its count.

        Logging is best-effort: a failure here must never change a block decision.
        """
        try:
            private_directory(self.path.parent)
            fd = os.open(self.path.with_name(self.path.name + '.lock'), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
                rows = self.read()
                previous = next((row for row in reversed(rows[-20:]) if repeat_of and row.get('key') == repeat_of), None)
                if previous:
                    previous['count'] = int(previous.get('count', 1)) + 1
                    previous['time'] = now()
                    rows.remove(previous)
                    rows.append(previous)
                else:
                    rows.append(dict(entry, id=secrets.token_hex(8), time=now(), count=1,
                                     **({'key': repeat_of} if repeat_of else {})))
                atomic_write(self.path, canonical(rows[-self.limit:]))
            finally:
                os.close(fd)
        except (OSError, ValueError, TypeError):
            pass
