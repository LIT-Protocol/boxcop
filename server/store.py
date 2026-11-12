"""SQLite audit persistence. Raw action content is never stored."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import sqlite3

from .models import POLICIES, Record
from .classifier_usage import BACKENDS, COUNTERS, empty_counts


NOT_RETAINED = "[not retained]"
SCHEMA_VERSION = 1


class Store:
    def __init__(self, path, *, timeout=10):
        self.path = Path(path)
        self.timeout = timeout
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.fchmod(fd, 0o600)
        os.close(fd)
        with self.connection() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("BEGIN IMMEDIATE")
            db.execute("""CREATE TABLE IF NOT EXISTS events (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                id TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                decision TEXT NOT NULL,
                latency_ms REAL NOT NULL,
                action TEXT NOT NULL,
                record TEXT NOT NULL
            )""")
            db.execute("CREATE INDEX IF NOT EXISTS events_filter ON events(decision, sequence)")
            db.execute("CREATE TABLE IF NOT EXISTS policies (id TEXT PRIMARY KEY, enabled INTEGER NOT NULL CHECK(enabled IN (0,1)))")
            db.execute("""CREATE TABLE IF NOT EXISTS classifier_usage (
                backend TEXT NOT NULL, counter TEXT NOT NULL,
                count INTEGER NOT NULL CHECK(typeof(count) = 'integer' AND count >= 0),
                PRIMARY KEY(backend, counter)
            )""")
            db.executemany("INSERT OR IGNORE INTO policies(id, enabled) VALUES (?, 1)", [(p["id"],) for p in POLICIES])
            db.execute(f"PRAGMA user_version={SCHEMA_VERSION}")

    @contextmanager
    def connection(self, *, timeout=None):
        db = sqlite3.connect(self.path, timeout=self.timeout if timeout is None else timeout)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA secure_delete=ON")
        try:
            with db:
                yield db
        finally:
            db.close()

    def classifier_usage(self):
        counts = empty_counts()
        with self.connection(timeout=0.1) as db:
            for backend, counter, count in db.execute("SELECT backend, counter, count FROM classifier_usage"):
                if backend not in BACKENDS or counter not in COUNTERS or type(count) is not int or count < 0:
                    raise ValueError("Invalid classifier usage totals")
                counts[backend][counter] = count
        if any(sum(row[name] for name in COUNTERS if name != 'attempts') > row['attempts'] for row in counts.values()):
            raise ValueError("Classifier outcomes exceed attempts")
        return counts

    def record_classifier_usage(self, backend, counter):
        if backend not in BACKENDS or counter not in COUNTERS:
            raise ValueError("Invalid classifier usage counter")
        # Aggregate increments remain safe across engine restarts/connections.
        # Do not keep the model worker waiting behind action audit writes.
        with self.connection(timeout=0.1) as db:
            db.execute("""INSERT INTO classifier_usage(backend, counter, count) VALUES (?, ?, 1)
                ON CONFLICT(backend, counter) DO UPDATE SET count=count+1""", (backend, counter))

    def save(self, record: Record) -> None:
        if record.event.content != NOT_RETAINED:
            raise ValueError("Content must be removed before persistence")
        with self.connection() as db:
            db.execute("INSERT INTO events(id, created_at, decision, latency_ms, action, record) VALUES (?, ?, ?, ?, ?, ?)",
                       (record.id, record.created_at, record.decision.action, record.decision.latency_ms, record.event.action, record.model_dump_json()))

    def get_event(self, event_id: str):
        with self.connection() as db:
            row = db.execute("SELECT record FROM events WHERE id=?", (event_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def list_events(self, limit=100, offset=0, decision="all"):
        """Newest first. `decision` is all, allow, warn, block, or held (warn and block)."""
        if type(limit) is not int or not 1 <= limit <= 500 or type(offset) is not int or not 0 <= offset <= 1_000_000:
            raise ValueError("Pagination out of bounds")
        if decision not in {"all", "allow", "warn", "block", "held"}:
            raise ValueError("Invalid event filter")
        where, params = "", []
        if decision == "held":
            where = " WHERE decision IN ('warn','block')"
        elif decision != "all":
            where, params = " WHERE decision=?", [decision]
        with self.connection() as db:
            # SQLite's implicit transaction mode does not begin on SELECT.
            # Keep count and page in one snapshot despite concurrent writers.
            db.execute("BEGIN")
            total = db.execute("SELECT COUNT(*) FROM events" + where, params).fetchone()[0]
            rows = db.execute("SELECT record FROM events" + where + " ORDER BY sequence DESC LIMIT ? OFFSET ?", [*params, limit, offset]).fetchall()
        return {"items": [json.loads(row[0]) for row in rows], "total": total}

    def stats(self):
        with self.connection() as db:
            row = db.execute("SELECT COUNT(*) AS total, COALESCE(SUM(decision='allow'),0) AS allow, COALESCE(SUM(decision='warn'),0) AS warn, COALESCE(SUM(decision='block'),0) AS block, COALESCE(AVG(latency_ms),0.0) AS average_latency_ms FROM events").fetchone()
        return dict(row)

    def policies(self):
        with self.connection() as db:
            enabled = {row[0]: bool(row[1]) for row in db.execute("SELECT id, enabled FROM policies")}
        return [{**policy, "enabled": enabled[policy["id"]]} for policy in POLICIES]

    def set_policy(self, policy_id: str, enabled: bool):
        if type(enabled) is not bool:
            raise ValueError("enabled must be a boolean")
        if policy_id not in {p["id"] for p in POLICIES}:
            return None
        with self.connection() as db:
            db.execute("UPDATE policies SET enabled=? WHERE id=?", (int(enabled), policy_id))
        return next(p for p in self.policies() if p["id"] == policy_id)
