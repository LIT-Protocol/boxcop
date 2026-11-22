"""Content retention uses only temporary fake audit data."""
import json

import pytest

from server.engine import Engine
from server.models import Decision, EventInput, Record
from server.store import Store

NOT_RETAINED = "[not retained]"
METADATA_FIELDS = ("session_id", "app", "source", "destination", "declared_intent")


def event(**updates):
    data = dict(session_id="retention-session", action="command", app="claude", destination="local-shell",
                content="FAKE_CONTENT_RETENTION_MARKER")
    data.update(updates)
    return EventInput(**data)


def record(**updates):
    sample = event(**updates)
    return Record(id="fake-record", created_at="2026-01-01T00:00:00+00:00", event=sample,
                  decision=Decision(action="allow", risk_score=0.0, summary="Static summary",
                                    reasons=["Static reason"], policy_ids=[], labels=[], latency_ms=0.0))


def assert_absent_from_database_files(path, markers):
    files = list(path.parent.glob(path.name + "*"))
    assert files
    for file in files:
        contents = file.read_bytes()
        for marker in markers:
            assert marker.encode() not in contents, (file.name, marker)


@pytest.mark.parametrize("action", ["command", "read", "write"])
def test_evaluate_discards_content_including_metadata_copies(tmp_path, action):
    store = Store(tmp_path / "events.db")
    marker = "FAKE_UNRECOGNIZABLE_PRIVATE_BODY"
    sample = event(content=marker, action=action,
                   **{field: f"prefix {marker} suffix {marker}" for field in METADATA_FIELDS})
    result = Engine(store).evaluate(sample)
    assert result.event.content == NOT_RETAINED
    assert marker not in result.model_dump_json()
    assert marker not in json.dumps(store.get_event(result.id))
    assert_absent_from_database_files(store.path, [marker])


def test_store_independently_refuses_content(tmp_path):
    store = Store(tmp_path / "events.db")
    sample = record(content="FAKE_FORBIDDEN_STORE_CONTENT")
    with pytest.raises(ValueError, match="(?i)content"):
        store.save(sample)
    assert store.stats()["total"] == 0
    assert_absent_from_database_files(store.path, ["FAKE_FORBIDDEN_STORE_CONTENT"])


def test_store_accepts_a_record_without_content(tmp_path):
    store = Store(tmp_path / "events.db")
    sample = record(content=NOT_RETAINED)
    store.save(sample)
    assert store.get_event(sample.id)["event"]["content"] == NOT_RETAINED
    assert Store(store.path).get_event(sample.id)["id"] == sample.id


def test_command_reviews_are_separate_from_decision_records(tmp_path):
    store = Store(tmp_path / "events.db")
    Engine(store).evaluate(event())
    with store.connection() as db:
        columns = {row[1] for row in db.execute("PRAGMA table_info(events)")}
        review_columns = {row[1] for row in db.execute("PRAGMA table_info(command_reviews)")}
        assert db.execute("SELECT COUNT(*) FROM command_reviews").fetchone()[0] == 0
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
    assert columns == {"sequence", "id", "created_at", "decision", "latency_ms", "action", "record"}
    assert tables == {"events", "policies", "classifier_usage", "command_reviews"}
    assert review_columns == {"event_id", "command", "fingerprint", "approved_until", "consumed"}


def test_database_file_is_private(tmp_path):
    store = Store(tmp_path / "events.db")
    assert store.path.stat().st_mode & 0o777 == 0o600


def test_failed_save_is_not_reported_as_a_decision(tmp_path, monkeypatch):
    store = Store(tmp_path / "events.db")
    engine = Engine(store)
    def fail(record):
        raise OSError("disk unavailable")
    monkeypatch.setattr(store, "save", fail)
    with pytest.raises(OSError):
        engine.evaluate(event())
    assert store.stats()["total"] == 0
