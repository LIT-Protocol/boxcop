"""SQLite audit persistence; raw content and lineage fingerprints are not stored."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import sqlite3

from .models import POLICIES, Record
from .classifier_usage import BACKENDS, COUNTERS, LEGACY_BACKENDS, empty_counts


NOT_RETAINED = "[not retained]"
SCHEMA_VERSION = 2
EVENT_SCHEMA = """
    CREATE TABLE IF NOT EXISTS events (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        id TEXT NOT NULL UNIQUE,
        created_at TEXT NOT NULL,
        synthetic INTEGER NOT NULL,
        decision TEXT NOT NULL,
        latency_ms REAL NOT NULL,
        action TEXT NOT NULL,
        record TEXT NOT NULL
    )
"""


def _scrub_legacy_record(serialized: str) -> str:
    record = json.loads(serialized)
    event, decision = record["event"], record["decision"]
    # Earlier sanitizers could destroy credential structure while leaving secret
    # fragments. Re-sanitizing that lossy representation cannot prove removal.
    # Drop legacy free text, including version-1 rows already migrated once.
    # Keep event IDs/timestamps, enum fields, labels and decisions for auditing.
    for field in ("session_id", "app", "source", "destination", "declared_intent"):
        event[field] = NOT_RETAINED
    event["content"] = decision["redacted_content"] = NOT_RETAINED
    return json.dumps(record, ensure_ascii=True)


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
            exists = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='events'").fetchone()
            columns = {row[1] for row in db.execute("PRAGMA table_info(events)")}
            metadata_exists = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='metadata'").fetchone()
            has_key = metadata_exists and db.execute("SELECT 1 FROM metadata WHERE key='hash-key'").fetchone()
            has_index = db.execute("SELECT 1 FROM sqlite_master WHERE type='index' AND name='events_lineage'").fetchone()
            version = db.execute("PRAGMA user_version").fetchone()[0]
            legacy = bool(has_key or has_index or exists and (
                version < SCHEMA_VERSION or columns.intersection({"session_hash", "content_hash"})))
            if legacy and exists:
                self._migrate_events(db)
            db.execute(EVENT_SCHEMA)
            db.execute("CREATE INDEX IF NOT EXISTS events_filter ON events(decision, synthetic, sequence)")
            db.execute("CREATE TABLE IF NOT EXISTS policies (id TEXT PRIMARY KEY, enabled INTEGER NOT NULL CHECK(enabled IN (0,1)))")
            db.execute("""CREATE TABLE IF NOT EXISTS classifier_usage (
                backend TEXT NOT NULL, counter TEXT NOT NULL,
                count INTEGER NOT NULL CHECK(typeof(count) = 'integer' AND count >= 0),
                PRIMARY KEY(backend, counter)
            )""")
            db.executemany("INSERT OR IGNORE INTO policies(id, enabled) VALUES (?, 1)", [(p["id"],) for p in POLICIES])
            if metadata_exists:
                db.execute("DELETE FROM metadata WHERE key='hash-key'")
            # A crash during cleanup must leave a version that retries the purge.
            db.execute(f"PRAGMA user_version={0 if legacy else SCHEMA_VERSION}")
        if legacy:
            with self.connection() as db:
                self._checkpoint(db)
                db.execute("VACUUM")
                self._checkpoint(db)
                db.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
                self._checkpoint(db)

    @staticmethod
    def _migrate_events(db) -> None:
        sequence = db.execute("SELECT seq FROM sqlite_sequence WHERE name='events'").fetchone()
        db.execute(EVENT_SCHEMA.replace("IF NOT EXISTS events", "events_migrated"))
        for row in db.execute("SELECT * FROM events ORDER BY sequence"):
            db.execute("INSERT INTO events_migrated(sequence, id, created_at, synthetic, decision, latency_ms, action, record) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                       (row["sequence"], row["id"], row["created_at"], row["synthetic"], row["decision"], row["latency_ms"], row["action"], _scrub_legacy_record(row["record"])))
        db.execute("DROP TABLE events")
        db.execute("ALTER TABLE events_migrated RENAME TO events")
        if sequence:
            db.execute("UPDATE sqlite_sequence SET seq=MAX(seq, ?) WHERE name='events'", (sequence[0],))

    @staticmethod
    def _checkpoint(db) -> None:
        if db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0]:
            raise RuntimeError("Legacy audit cleanup blocked by another database reader")

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
                # Preserve old text-fallback totals on disk, but never relabel them as workflow reviews.
                if backend in LEGACY_BACKENDS: continue
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

    def save(self, record: Record, *, retain_preview: bool = False) -> None:
        if retain_preview and not (record.synthetic and record.event.synthetic):
            raise ValueError("Preview retention requires an internal synthetic record")
        if not retain_preview and (record.event.content != NOT_RETAINED or record.decision.redacted_content != NOT_RETAINED):
            raise ValueError("Content must be removed before persistence without internal preview permission")
        with self.connection() as db:
            db.execute("INSERT INTO events(id, created_at, synthetic, decision, latency_ms, action, record) VALUES (?, ?, ?, ?, ?, ?, ?)",
                       (record.id, record.created_at, int(record.synthetic), record.decision.action, record.decision.latency_ms, record.event.action, record.model_dump_json()))

    def get_event(self, event_id: str):
        with self.connection() as db:
            row = db.execute("SELECT record FROM events WHERE id=?", (event_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def list_events(self, limit=100, offset=0, decision="all", synthetic="all", *, desktop_only=False):
        if type(limit) is not int or not 1 <= limit <= 500 or type(offset) is not int or not 0 <= offset <= 1_000_000:
            raise ValueError("Pagination out of bounds")
        if decision not in {"all", "allow", "warn", "block"} or synthetic not in {"all", "true", "false"}:
            raise ValueError("Invalid event filter")
        clauses, params = [], []
        if desktop_only:
            # The native clipboard wire decoder accepts human copy/paste only.
            # Filter before pagination so agent traffic cannot hide its history.
            clauses.extend(["json_extract(record, '$.event.actor')='human'", "action IN ('copy','paste')", "synthetic=0"])
        if decision != "all":
            clauses.append("decision=?")
            params.append(decision)
        if synthetic != "all":
            clauses.append("synthetic=?")
            params.append(int(synthetic == "true"))
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        with self.connection() as db:
            # SQLite's implicit transaction mode does not begin on SELECT.
            # Keep count and page in one snapshot despite concurrent writers.
            db.execute("BEGIN")
            total = db.execute("SELECT COUNT(*) FROM events" + where, params).fetchone()[0]
            rows = db.execute("SELECT record FROM events" + where + " ORDER BY sequence DESC LIMIT ? OFFSET ?", [*params, limit, offset]).fetchall()
        return {"items": [json.loads(row[0]) for row in rows], "total": total}

    def stats(self):
        with self.connection() as db:
            row = db.execute("SELECT COUNT(*) AS total, COALESCE(SUM(decision='allow'),0) AS allow, COALESCE(SUM(decision='warn'),0) AS warn, COALESCE(SUM(decision='block'),0) AS block, COALESCE(SUM(synthetic=1),0) AS synthetic, COALESCE(SUM(synthetic=0),0) AS live, COALESCE(AVG(latency_ms),0.0) AS average_latency_ms FROM events").fetchone()
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
