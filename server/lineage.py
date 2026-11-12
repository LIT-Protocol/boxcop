"""Ephemeral exact-copy correlation. Nothing here is serialized to SQLite."""
from collections import OrderedDict, deque
import hashlib
import hmac
import secrets
from threading import RLock
from typing import NamedTuple


class CopyEntry(NamedTuple):
    content_hash: bytes
    created_at: float  # Monotonic seconds, never an audit timestamp.
    event_id: str
    sensitive: bool


class LineageTracker:
    TTL = 300.0
    MAX_SESSIONS = 256
    MAX_PER_SESSION = 32
    MAX_ENTRIES = 8192
    MAX_RESULTS = 20

    def __init__(self):
        self._key = secrets.token_bytes(32)
        self._sessions: OrderedDict[bytes, deque[CopyEntry]] = OrderedDict()
        self._lock = RLock()

    def _fingerprint(self, value: str, domain: str) -> bytes:
        return hmac.new(self._key, (domain + "\0" + value).encode("utf-8"), hashlib.sha256).digest()

    def _expire(self, now: float) -> None:
        cutoff = now - self.TTL
        for session, entries in list(self._sessions.items()):
            # Filter every entry, including out-of-order injected timestamps.
            retained = deque(entry for entry in entries if entry.created_at >= cutoff)
            if retained:
                self._sessions[session] = retained
            else:
                del self._sessions[session]

    def remember(self, session_id: str, content: str, event_id: str,
                 now: float, *, sensitive: bool) -> None:
        with self._lock:
            self._expire(now)
            if not content:
                return
            session = self._fingerprint(session_id, "session")
            entries = self._sessions.setdefault(session, deque())
            entries.append(CopyEntry(self._fingerprint(content, "content"), now, event_id, sensitive))
            while len(entries) > self.MAX_PER_SESSION:
                entries.popleft()
            self._sessions.move_to_end(session)
            while len(self._sessions) > self.MAX_SESSIONS:
                self._sessions.popitem(last=False)
            # Keep an explicit aggregate bound even if individual limits change.
            while sum(map(len, self._sessions.values())) > self.MAX_ENTRIES:
                oldest = next(iter(self._sessions))
                self._sessions[oldest].popleft()
                if not self._sessions[oldest]:
                    del self._sessions[oldest]

    def lookup(self, session_id: str, content: str, now: float) -> list[str]:
        with self._lock:
            self._expire(now)
            if not content:
                return []
            session = self._fingerprint(session_id, "session")
            entries = self._sessions.get(session)
            if not entries:
                return []
            self._sessions.move_to_end(session)
            content_hash = self._fingerprint(content, "content")
            return [entry.event_id for entry in reversed(entries)
                    if entry.sensitive and entry.created_at <= now
                    and entry.content_hash == content_hash][:self.MAX_RESULTS]
