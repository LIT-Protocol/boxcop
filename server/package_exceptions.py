"""Releases the user chose to install although the feed reports them as malware.

One exact release each: ecosystem, package and version. Only the "reported, not
yet confirmed" tier can be allowed; the firewall checks the tier again on every
request, so an entry stops working if the feed later confirms the release.

The file lives in the package-protection folder, which contained install scripts
and contained runs cannot write. Anything unexpected in it reads as no exceptions.
"""
import fcntl
import json
import os
from pathlib import Path
import stat
import threading

from .event_log import now, private_directory
from .package_intelligence import atomic_write, canonical, package_name, version

FILE = 'exceptions.json'
LIMIT = 200
MAX_BYTES = 128 * 1024
ECOSYSTEMS = ('npm', 'PyPI')


def release(ecosystem, name, candidate):
    """The normalized identity of one release, or ValueError."""
    if ecosystem not in ECOSYSTEMS:
        raise ValueError('Unsupported ecosystem')
    name = package_name(ecosystem, name)
    version(ecosystem, candidate)
    return ecosystem, name, candidate


class Exceptions:
    def __init__(self, directory):
        self.path = Path(directory) / FILE
        self._lock = threading.Lock()
        self._identity = self._rows = None

    def read(self):
        """Valid entries, oldest first. Cached until the file changes."""
        try:
            fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except OSError:
            return []
        try:
            with os.fdopen(fd, 'rb') as stream:
                info = os.fstat(stream.fileno())
                # Another user's file, a link or a writable-by-others file is not ours to trust.
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
                        or stat.S_IMODE(info.st_mode) & 0o077 or info.st_size > MAX_BYTES):
                    return []
                identity = (info.st_ino, info.st_mtime_ns, info.st_size)
                with self._lock:
                    if identity == self._identity:
                        return [dict(row) for row in self._rows]
                value = json.loads(stream.read(MAX_BYTES + 1))
        except (OSError, ValueError, RecursionError):
            return []
        rows, seen = [], set()
        for row in value if isinstance(value, list) else []:
            try:
                if not isinstance(row, dict) or set(row) != {'ecosystem', 'package', 'version', 'added'}:
                    continue
                key = release(row['ecosystem'], row['package'], row['version'])
                if key in seen or key[1] != row['package'] or not isinstance(row['added'], str) or len(row['added']) > 32:
                    continue
            except (ValueError, TypeError):
                continue
            seen.add(key)
            rows.append({'ecosystem': key[0], 'package': key[1], 'version': key[2], 'added': row['added']})
        rows = rows[-LIMIT:]
        with self._lock:
            self._identity, self._rows = identity, rows
        return [dict(row) for row in rows]

    def allows(self, ecosystem, name, candidate):
        try:
            key = release(ecosystem, name, candidate)
        except (ValueError, TypeError):
            return False
        return any((row['ecosystem'], row['package'], row['version']) == key for row in self.read())

    def change(self, action, ecosystem, name, candidate):
        """Add or remove one release. Returns the new list."""
        key = release(ecosystem, name, candidate)
        private_directory(self.path.parent)
        fd = os.open(self.path.with_name(FILE + '.lock'), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            rows = self.read()
            present = any((row['ecosystem'], row['package'], row['version']) == key for row in rows)
            if action == 'allow' and not present:
                if len(rows) >= LIMIT:
                    raise OverflowError('Too many exceptions')
                rows.append({'ecosystem': key[0], 'package': key[1], 'version': key[2], 'added': now()})
            elif action == 'revoke' and present:
                rows = [row for row in rows if (row['ecosystem'], row['package'], row['version']) != key]
            else:
                return rows
            atomic_write(self.path, canonical(rows))  # mkstemp creates it owner-only.
            return rows
        finally:
            os.close(fd)
