"""Regression fixtures contain only FAKE residues from historical sanitizers."""
import sqlite3

import pytest

from server.engine import Engine
from server.models import Decision, EventInput, Record
from server.store import NOT_RETAINED, Store


FIELDS = ("session_id", "app", "source", "destination", "declared_intent")


def database_bytes(path):
    return b"\n".join(file.read_bytes() for file in path.parent.glob(path.name + "*"))


def seed_legacy(path, version, wal):
    """Seed old stored representations, NOT fresh raw input for today's sanitizer."""
    old = sqlite3.connect(path)
    if wal:
        old.execute("PRAGMA journal_mode=WAL")
        old.execute("PRAGMA wal_autocheckpoint=0")
    hashes = "session_hash TEXT NOT NULL, content_hash TEXT NOT NULL," if version == 0 else ""
    old.executescript(f"""
        CREATE TABLE events (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            id TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL,
            synthetic INTEGER NOT NULL, decision TEXT NOT NULL,
            latency_ms REAL NOT NULL, {hashes}
            action TEXT NOT NULL, record TEXT NOT NULL);
        CREATE INDEX events_filter ON events(decision, synthetic, sequence);
        CREATE TABLE policies (id TEXT PRIMARY KEY, enabled INTEGER NOT NULL);
        CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        INSERT INTO policies VALUES ('secret-egress', 0);
        INSERT INTO metadata VALUES ('unrelated-setting', 'preserve-control');
    """)
    markers = []
    if version == 0:
        old.execute("CREATE INDEX events_lineage ON events(session_hash, content_hash, synthetic, created_at)")
        old.execute("INSERT INTO metadata VALUES ('hash-key', 'FAKE_OLD_HASH_KEY')")
        markers.extend(["FAKE_OLD_HASH_KEY", "FAKE_OLD_SESSION_HASH", "FAKE_OLD_CONTENT_HASH"])
    original = []
    for index, synthetic in enumerate((False, True)):
        metadata = {}
        for field in FIELDS:
            user = f"FAKE_RESIDUE_{field.upper()}_USER_{index}"
            password = f"FAKE_RESIDUE_{field.upper()}_PASSWORD_{index}"
            token = f"fake-residue-{field}-token-{index}"
            markers.extend([user, password, token])
            # The old sanitizer could redact the suffix of bare userinfo, or
            # turn malformed URL userinfo into a host-like token. The original
            # structure cannot be recovered reliably by re-sanitizing this.
            metadata[field] = f"db {user}:{password}![email redacted] https://{token}"
        preview = f"FAKE_OLD_BODY_{index}" if version == 0 else NOT_RETAINED
        if version == 0:
            markers.append(preview)
        event = EventInput(actor="human", role="engineering", action="paste",
                           content=preview, synthetic=synthetic, **metadata)
        record = Record(
            id=f"old-{index}", created_at="2026-01-01T00:00:00+00:00",
            synthetic=synthetic, event=event,
            decision=Decision(action="block", risk_score=98, summary="Static legacy decision",
                              reasons=["Static legacy reason"], policy_ids=["secret-egress"],
                              labels=["secret"], redacted_content=preview, latency_ms=1.0,
                              context_event_ids=[]),
        )
        fields = "id, created_at, synthetic, decision, latency_ms, action, record"
        values = [record.id, record.created_at, int(synthetic), "block", 1.0, "paste", record.model_dump_json()]
        if version == 0:
            fields += ", session_hash, content_hash"
            values.extend(["FAKE_OLD_SESSION_HASH", "FAKE_OLD_CONTENT_HASH"])
        old.execute(f"INSERT INTO events ({fields}) VALUES ({','.join('?' for _ in values)})", values)
        original.append(record.model_dump())
    old.execute(f"PRAGMA user_version={version}")
    old.commit()
    raw = database_bytes(path)
    assert all(marker.encode() in raw for marker in markers)
    if wal:
        assert path.with_name(path.name + "-wal").stat().st_size > 0
    return old, markers, original


@pytest.mark.parametrize("version", [0, 1])
@pytest.mark.parametrize("wal", [False, True])
def test_old_sanitizer_residues_are_discarded_including_previously_migrated_v1(tmp_path, version, wal):
    path = tmp_path / "legacy.db"
    old, markers, original = seed_legacy(path, version, wal)
    try:
        store = Store(path)
        rows = store.list_events()
        assert rows["total"] == len(original)
        for source in original:
            migrated = store.get_event(source["id"])
            assert migrated is not None
            assert all(migrated["event"][field] == NOT_RETAINED for field in FIELDS)
            assert migrated["event"]["content"] == NOT_RETAINED
            assert migrated["decision"]["redacted_content"] == NOT_RETAINED
            for field in ("id", "created_at", "synthetic"):
                assert migrated[field] == source[field]
            for field in ("action", "policy_ids", "labels", "summary", "reasons"):
                assert migrated["decision"][field] == source["decision"][field]
        raw = database_bytes(path)
        assert all(marker.encode() not in raw for marker in markers)
        with store.connection() as db:
            assert db.execute("PRAGMA user_version").fetchone()[0] == 2
            assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
            assert db.execute("SELECT value FROM metadata WHERE key='unrelated-setting'").fetchone()[0] == "preserve-control"
            assert db.execute("SELECT value FROM metadata WHERE key='hash-key'").fetchone() is None
            assert {row[1] for row in db.execute("PRAGMA table_info(events)")}.isdisjoint({"session_hash", "content_hash"})
            assert db.execute("SELECT 1 FROM sqlite_master WHERE name='events_lineage'").fetchone() is None
        assert not next(policy for policy in store.policies() if policy["id"] == "secret-egress")["enabled"]
        assert Store(path).list_events() == rows
    finally:
        old.close()


@pytest.mark.parametrize("version", [0, 1])
def test_interrupted_cleanup_keeps_retry_version_and_completes_on_reopen(tmp_path, monkeypatch, version):
    path = tmp_path / "retry.db"
    old, markers, _ = seed_legacy(path, version, wal=True)
    old.close()
    with monkeypatch.context() as scope:
        def interrupted(db):
            raise RuntimeError("simulated checkpoint interruption")
        scope.setattr(Store, "_checkpoint", staticmethod(interrupted))
        with pytest.raises(RuntimeError, match="simulated checkpoint interruption"):
            Store(path)
    with sqlite3.connect(path) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 0
    recovered = Store(path)
    assert recovered.stats()["total"] == 2
    assert all(marker.encode() not in database_bytes(path) for marker in markers)
    with recovered.connection() as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 2


def test_current_records_keep_metadata_and_internal_previews_on_reopen(tmp_path):
    path = tmp_path / "current.db"
    store = Store(path)
    event = EventInput(session_id="current-control", actor="human", role="engineering",
                       action="copy", app="Notes", source="work-notes", destination="clipboard",
                       declared_intent="Keep safe metadata", content="Fictional demonstration", synthetic=True)
    record = Engine(store).evaluate(event, retain_preview=True)
    before = store.get_event(record.id)
    assert before is not None
    assert before["event"]["source"] == "work-notes"
    assert before["event"]["content"] == "Fictional demonstration"
    assert Store(path).get_event(record.id) == before
