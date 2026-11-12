"""Private, bounded live snapshots; reading a console never takes the updater lock."""
import codecs
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import stat
import time
import uuid

from .software_inventory import open_root


class ConsoleLog:
    limit = 128 * 1024

    def __init__(self, item_id, redact):
        if not re.fullmatch('[a-f0-9]{24}', item_id):
            raise ValueError('Invalid console identifier')
        self.item_id = item_id
        self.redact = redact
        self.text = ''
        self.truncated = False
        self.status = 'running'
        self.updated_at = datetime.now(timezone.utc).isoformat()
        self.last_write = 0
        self.decoders = {key: codecs.getincrementaldecoder('utf-8')(errors='replace') for key in ('stdout', 'stderr')}
        self.append('Starting update; checking the approved plan…\n')
        self.publish(force=True)

    def append(self, text):
        self.text += text
        if len(self.text) > self.limit:
            self.text = self.text[-self.limit:]
            # Avoid retaining partial leading lines/credentials when truncating.
            self.text = self.text.partition('\n')[2] or ''
            self.truncated = True
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def feed(self, stream, data):
        self.append(self.decoders[stream].decode(data))

    def publish(self, force=False):
        if not force and time.monotonic() - self.last_write < .5:
            return
        self.last_write = time.monotonic()
        directory = None
        temporary = '.console-' + uuid.uuid4().hex
        try:
            parent = open_root(Path.home() / 'Library/Application Support/BoxCop')
            try:
                info = os.fstat(parent)
                if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                    return
                try: os.mkdir('software-console', 0o700, dir_fd=parent)
                except FileExistsError: pass
                directory = os.open('software-console', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            finally:
                os.close(parent)
            info = os.fstat(directory)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                return
            # Bound total storage as well as each snapshot. Never follow entries.
            files = sorted((os.stat(name, dir_fd=directory, follow_symlinks=False).st_mtime, name)
                           for name in os.listdir(directory) if re.fullmatch('[a-f0-9]{24}\\.json', name))
            for _, name in files[:-127]:
                if name != self.item_id + '.json': os.unlink(name, dir_fd=directory)
            data = json.dumps(dict(text=self.redact(self.text), status=self.status,
                                   updated_at=self.updated_at, truncated=self.truncated), ensure_ascii=False).encode()
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
            os.replace(temporary, self.item_id + '.json', src_dir_fd=directory, dst_dir_fd=directory)
        except (OSError, ValueError):
            # Console IO failure must not terminate an installation.
            pass
        finally:
            if directory is not None:
                try: os.unlink(temporary, dir_fd=directory)
                except FileNotFoundError: pass
                except OSError: pass
                os.close(directory)

    def finish(self, status, detail):
        for decoder in self.decoders.values(): self.append(decoder.decode(b'', final=True))
        self.status = status
        self.append('\n' + detail + '\n')
        self.publish(force=True)
