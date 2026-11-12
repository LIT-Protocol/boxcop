"""Content retention and legacy migration use only temporary fake audit data."""
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from threading import Event, RLock
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from server.engine import Engine
from server.models import Decision, EventInput, Record
from server.store import Store

NOT_RETAINED = "[not retained]"
METADATA_FIELDS = ("session_id", "app", "source", "destination", "declared_intent")


def event(**updates):
    data = dict(session_id="retention-session", actor="human", role="engineering",
                action="paste", app="Browser", destination="https://example.invalid",
                content="FAKE_CONTENT_RETENTION_MARKER")
    data.update(updates)
    return EventInput(**data)


def record(**updates):
    sample = event(**updates)
    return Record(id="fake-record", created_at="2026-01-01T00:00:00+00:00",
                  synthetic=sample.synthetic, event=sample,
                  decision=Decision(action="allow", risk_score=0.0, summary="Static summary",
                                    reasons=["Static reason"], policy_ids=[], labels=[],
                                    redacted_content=sample.content, latency_ms=0.0,
                                    context_event_ids=[]))


def assert_absent_from_database_files(path, markers):
    files = list(path.parent.glob(path.name + "*"))
    assert files
    for file in files:
        contents = file.read_bytes()
        for marker in markers:
            assert marker.encode() not in contents, (file.name, marker)


@pytest.mark.parametrize("synthetic", [False, True])
def test_evaluate_discards_content_by_default_including_metadata(tmp_path, synthetic):
    store = Store(tmp_path / "events.db")
    marker = "FAKE_UNRECOGNIZABLE_PRIVATE_BODY"
    sample = event(content=marker, synthetic=synthetic,
                   **{field: f"prefix {marker} suffix {marker}" for field in METADATA_FIELDS})
    result = Engine(store).evaluate(sample)
    assert result.event.content == result.decision.redacted_content == NOT_RETAINED
    assert marker not in result.model_dump_json()
    assert marker not in json.dumps(store.get_event(result.id))
    assert_absent_from_database_files(store.path, [marker])


def test_explicit_internal_synthetic_preview_is_redacted_and_persisted(tmp_path):
    store = Store(tmp_path / "events.db")
    sample = event(synthetic=True, content="Fictional example api_key=FAKE_CREDENTIAL_123456789")
    result = Engine(store).evaluate(sample, retain_preview=True)
    assert "Fictional example" in result.event.content
    assert result.decision.redacted_content == result.event.content
    assert "FAKE_CREDENTIAL_123456789" not in result.model_dump_json()
    assert store.get_event(result.id)["event"]["content"] == result.event.content
    # Opening a current-schema store must not treat authorized new previews as legacy.
    assert Store(store.path).get_event(result.id)["event"]["content"] == result.event.content


def test_internal_preview_opt_in_requires_synthetic(tmp_path):
    store = Store(tmp_path / "events.db")
    with pytest.raises(ValueError, match="synthetic"):
        Engine(store).evaluate(event(), retain_preview=True)
    assert store.stats()["total"] == 0


def test_caller_cannot_inject_preview_permission():
    with pytest.raises(ValidationError):
        event(synthetic=True, retain_preview=True)


@pytest.mark.parametrize("synthetic", [False, True])
@pytest.mark.parametrize("field", ["content", "redacted_content"])
def test_store_independently_refuses_all_non_opted_in_previews(tmp_path, synthetic, field):
    store = Store(tmp_path / "events.db")
    sample = record(synthetic=synthetic, content=NOT_RETAINED)
    if field == "content":
        sample.event.content = "FAKE_FORBIDDEN_STORE_PREVIEW"
    else:
        sample.decision.redacted_content = "FAKE_FORBIDDEN_STORE_PREVIEW"
    with pytest.raises(ValueError, match="(?i)(content|preview)"):
        store.save(sample)
    assert store.stats()["total"] == 0
    assert_absent_from_database_files(store.path, ["FAKE_FORBIDDEN_STORE_PREVIEW"])


@pytest.mark.parametrize("outer,inner", [(False, False), (True, False), (False, True)])
def test_store_preview_requires_both_synthetic_flags(tmp_path, outer, inner):
    store = Store(tmp_path / "events.db")
    sample = record(synthetic=inner)
    sample.synthetic = outer
    with pytest.raises(ValueError, match="synthetic"):
        store.save(sample, retain_preview=True)
    assert store.stats()["total"] == 0


def test_store_accepts_only_explicit_internal_synthetic_preview(tmp_path):
    store = Store(tmp_path / "events.db")
    sample = record(synthetic=True, content="Fictional redacted sample")
    store.save(sample, retain_preview=True)
    assert store.get_event(sample.id)["event"]["content"] == sample.event.content


def test_new_database_has_no_fingerprints_or_hash_key(tmp_path):
    store = Store(tmp_path / "events.db")
    Engine(store).evaluate(event(action="copy"))
    with store.connection() as db:
        columns = {row[1] for row in db.execute("PRAGMA table_info(events)")}
        schema = " ".join(row[0] or "" for row in db.execute("SELECT sql FROM sqlite_master"))
        metadata_exists = db.execute("SELECT 1 FROM sqlite_master WHERE name='metadata'").fetchone()
        if metadata_exists:
            assert db.execute("SELECT value FROM metadata WHERE key='hash-key'").fetchone() is None
    assert "session_hash" not in columns
    assert "content_hash" not in columns
    assert "events_lineage" not in schema
    assert not hasattr(store, "_hash_key")
    assert not hasattr(store, "fingerprint")


@pytest.mark.parametrize("wal", [False, True])
def test_legacy_migration_scrubs_every_preview_metadata_hash_and_key(tmp_path, wal):
    path = tmp_path / "legacy.db"
    old = sqlite3.connect(path)
    if wal:
        old.execute("PRAGMA journal_mode=WAL")
        old.execute("PRAGMA wal_autocheckpoint=0")
    old.executescript("""
        CREATE TABLE events (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL, synthetic INTEGER NOT NULL,
            decision TEXT NOT NULL, latency_ms REAL NOT NULL,
            session_hash TEXT NOT NULL, content_hash TEXT NOT NULL,
            action TEXT NOT NULL, record TEXT NOT NULL);
        CREATE INDEX events_lineage ON events(session_hash, content_hash, synthetic, created_at);
        CREATE INDEX events_filter ON events(decision, synthetic, sequence);
        CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE policies (id TEXT PRIMARY KEY, enabled INTEGER NOT NULL);
    """)
    fake_key = "ab" * 32
    markers = [fake_key, "FAKE_STORED_SESSION_HASH", "FAKE_STORED_CONTENT_HASH"]
    old.execute("INSERT INTO metadata VALUES ('hash-key', ?)", (fake_key,))
    old.execute("INSERT INTO metadata VALUES ('keep-unrelated-setting', 'safe')")
    old.execute("INSERT INTO policies VALUES ('secret-egress', 0)")
    raw_metadata = 'https://fake-user:fake-password@example.invalid/path?query=FAKE_QUERY#FAKE_FRAGMENT\napi_key=FAKE_METADATA_CREDENTIAL'
    markers.extend(["fake-user", "fake-password", "FAKE_QUERY", "FAKE_FRAGMENT", "FAKE_METADATA_CREDENTIAL"])
    for index, synthetic in enumerate([False, True, True]):
        marker = f"FAKE_LEGACY_BODY_MARKER_{index}"
        preview_marker = f"FAKE_LEGACY_PREVIEW_MARKER_{index}"
        markers.extend([marker, preview_marker])
        sample = record(synthetic=synthetic, content=marker)
        sample.id = f"legacy-{index}"
        sample.decision.redacted_content = preview_marker
        # A caller could have impersonated the old 'synthetic-' session prefix.
        sample.event.session_id = f"synthetic-fake-{index}" if index == 1 else "legacy-session"
        for field in ("app", "source", "destination", "declared_intent"):
            setattr(sample.event, field, raw_metadata + " " + marker + " " + preview_marker)
        old.execute("INSERT INTO events(id, created_at, synthetic, decision, latency_ms, session_hash, content_hash, action, record) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (sample.id, sample.created_at, int(synthetic), "allow", 0.0,
                     "FAKE_STORED_SESSION_HASH", "FAKE_STORED_CONTENT_HASH", "paste", sample.model_dump_json()))
    old.commit()
    assert any(b"FAKE_LEGACY_BODY_MARKER_1" in file.read_bytes() for file in tmp_path.glob("legacy.db*"))
    try:
        store = Store(path)
        migrated = store.list_events()
        assert migrated["total"] == 3
        assert [item["id"] for item in migrated["items"]] == ["legacy-2", "legacy-1", "legacy-0"]
        for item in migrated["items"]:
            assert item["event"]["content"] == item["decision"]["redacted_content"] == NOT_RETAINED
            for field in METADATA_FIELDS:
                assert item["event"][field] == NOT_RETAINED
        with store.connection() as db:
            assert db.execute("SELECT value FROM metadata WHERE key='hash-key'").fetchone() is None
            assert db.execute("SELECT value FROM metadata WHERE key='keep-unrelated-setting'").fetchone()[0] == "safe"
            assert {row[1] for row in db.execute("PRAGMA table_info(events)")}.isdisjoint({"session_hash", "content_hash"})
            assert db.execute("SELECT 1 FROM sqlite_master WHERE name='events_lineage'").fetchone() is None
            assert db.execute("PRAGMA secure_delete").fetchone()[0] == 1
            assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert not next(p for p in store.policies() if p["id"] == "secret-egress")["enabled"]
        assert_absent_from_database_files(path, markers)
        assert Store(path).list_events() == migrated
    finally:
        old.close()


def tracker():
    from server.lineage import LineageTracker
    return LineageTracker()


NOW = 1000.0


def test_lineage_remembers_only_hashed_session_content_and_minimal_facts():
    first, second = tracker(), tracker()
    first.remember("FAKE_RAW_SESSION", "FAKE_RAW_CONTENT", "audit-id", NOW, sensitive=True)
    assert first.lookup("FAKE_RAW_SESSION", "FAKE_RAW_CONTENT", NOW) == ["audit-id"]
    state = repr(first._sessions)
    assert "FAKE_RAW_SESSION" not in state and "FAKE_RAW_CONTENT" not in state
    assert first._key != second._key
    assert isinstance(first._lock, type(RLock()))
    for session_hash, entries in first._sessions.items():
        assert isinstance(session_hash, bytes) and len(session_hash) == 32
        for entry in entries:
            assert set(entry._fields) == {"content_hash", "created_at", "event_id", "sensitive"}
            assert isinstance(entry.content_hash, bytes) and len(entry.content_hash) == 32
            assert isinstance(entry.created_at, float)
    assert second.lookup("FAKE_RAW_SESSION", "FAKE_RAW_CONTENT", NOW) == []


def test_lineage_only_matches_sensitive_exact_content_within_one_session():
    history = tracker()
    history.remember("s1", "body", "sensitive-copy", NOW, sensitive=True)
    history.remember("s1", "benign", "benign-copy", NOW, sensitive=False)
    assert history.lookup("s1", "body", NOW) == ["sensitive-copy"]
    assert history.lookup("s2", "body", NOW) == []
    assert history.lookup("s1", "body changed", NOW) == []
    assert history.lookup("s1", "benign", NOW) == []


@pytest.mark.parametrize("age,expected", [(299, ["copy"]), (300, ["copy"]), (301, [])])
def test_lineage_five_minute_boundary(age, expected):
    history = tracker()
    history.remember("s1", "body", "copy", NOW, sensitive=True)
    assert history.lookup("s1", "body", NOW + age) == expected


def test_lineage_never_matches_future_timestamps():
    history = tracker()
    history.remember("s1", "body", "future", NOW + 1.0, sensitive=True)
    assert history.lookup("s1", "body", NOW) == []
    assert history.lookup("s1", "body", NOW + 1.0) == ["future"]


@pytest.mark.parametrize("operation", ["lookup", "remember"])
def test_lineage_expires_all_sessions_on_each_operation(operation):
    history = tracker()
    history.remember("old-session", "body", "expired", NOW, sensitive=True)
    later = NOW + 360.0
    if operation == "lookup":
        history.lookup("unrelated", "body", later)
        assert len(history._sessions) == 0
    else:
        history.remember("new-session", "body", "fresh", later, sensitive=True)
        assert len(history._sessions) == 1
    assert "expired" not in repr(history._sessions)


def test_lineage_is_bounded_per_session_and_returns_twenty_newest():
    history = tracker()
    for index in range(40):
        history.remember("s1", "body", f"copy-{index}", NOW, sensitive=True)
    assert sum(map(len, history._sessions.values())) == 32
    assert history.lookup("s1", "body", NOW) == [f"copy-{index}" for index in range(39, 19, -1)]
    state = repr(history._sessions)
    assert "event_id='copy-0'" not in state
    assert "event_id='copy-8'" in state


def test_lineage_session_lru_evicts_oldest_not_recently_accessed():
    history = tracker()
    for index in range(256):
        history.remember(f"session-{index}", "body", f"copy-{index}", NOW, sensitive=True)
    assert history.lookup("session-0", "body", NOW) == ["copy-0"]
    history.remember("new-session", "body", "new", NOW, sensitive=True)
    assert len(history._sessions) == 256
    assert history.lookup("session-1", "body", NOW) == []
    assert history.lookup("session-0", "body", NOW) == ["copy-0"]


def test_lineage_global_cap_under_many_full_sessions():
    history = tracker()
    for session in range(260):
        for entry in range(33):
            history.remember(f"s-{session}", f"body-{entry}", f"id-{session}-{entry}", NOW, sensitive=True)
    assert len(history._sessions) == 256
    assert all(len(entries) <= 32 for entries in history._sessions.values())
    assert sum(map(len, history._sessions.values())) == 8192
    assert history.lookup("s-0", "body-32", NOW) == []
    assert history.lookup("s-259", "body-0", NOW) == []
    assert history.lookup("s-259", "body-32", NOW) == ["id-259-32"]


def test_lineage_concurrent_remember_and_lookup():
    history = tracker()

    def roundtrip(index):
        session = f"thread-session-{index % 16}"
        content = f"thread-content-{index}"
        identifier = f"thread-copy-{index}"
        history.remember(session, content, identifier, NOW, sensitive=True)
        return history.lookup(session, content, NOW) == [identifier]

    with ThreadPoolExecutor(max_workers=16) as pool:
        assert all(pool.map(roundtrip, range(128)))
    assert sum(map(len, history._sessions.values())) == 128


def test_engine_restart_discards_lineage_not_audit_records(tmp_path):
    store = Store(tmp_path / "events.db")
    first = Engine(store)
    secret = "api_key=FAKE_LINEAGE_TOKEN_123456"
    copied = first.evaluate(event(action="copy", content=secret))
    assert first.evaluate(event(content=secret)).decision.context_event_ids == [copied.id]
    for restarted in (Engine(store), Engine(Store(store.path))):
        assert restarted.evaluate(event(content=secret)).decision.context_event_ids == []
    assert store.get_event(copied.id)["id"] == copied.id


def test_engine_serializes_copy_save_and_paste_lookup(tmp_path, monkeypatch):
    store = Store(tmp_path / "events.db")
    engine = Engine(store)
    entered, release, paste_started = Event(), Event(), Event()
    original_save = store.save
    secret = "api_key=FAKE_LINEAGE_TOKEN_123456"

    def waiting_save(item, *args, **kwargs):
        if item.event.action == "copy":
            entered.set()
            assert release.wait(5)
        return original_save(item, *args, **kwargs)

    def paste():
        paste_started.set()
        return engine.evaluate(event(content=secret))

    monkeypatch.setattr(store, "save", waiting_save)
    with ThreadPoolExecutor(max_workers=2) as pool:
        copied = pool.submit(engine.evaluate, event(action="copy", content=secret))
        try:
            assert entered.wait(5)
            pasted = pool.submit(paste)
            assert paste_started.wait(5)
            with pytest.raises(TimeoutError):
                pasted.result(timeout=0.05)
        finally:
            release.set()
        assert pasted.result(timeout=5).decision.context_event_ids == [copied.result(timeout=5).id]


def test_failed_copy_save_does_not_create_lineage(tmp_path):
    store = Store(tmp_path / "events.db")
    engine = Engine(store)
    secret = "api_key=FAKE_LINEAGE_TOKEN_123456"
    with patch.object(store, "save", side_effect=sqlite3.OperationalError("fake failure")):
        with pytest.raises(sqlite3.OperationalError):
            engine.evaluate(event(action="copy", content=secret))
    assert engine.evaluate(event(content=secret)).decision.context_event_ids == []
