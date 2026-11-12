"""Suppress full metadata copies, not arbitrary fragments or encodings."""
from pathlib import Path

import pytest

from server.classify import sanitize_metadata
from server.engine import Engine
from server.models import EventInput
from server.store import NOT_RETAINED, Store


METADATA_FIELDS = ("session_id", "app", "source", "destination", "declared_intent")
CONTENT = "FAKE_NORMALIZED X"


def event(**updates):
    data = dict(session_id="fake-metadata-session", action="command", app="claude",
                destination="local-shell", content=CONTENT)
    data.update(updates)
    return EventInput(**data)


def assert_absent_from_database_and_wal(path, marker):
    # The caller holds a connection open so WAL inspection is not vacuous.
    wal = Path(str(path) + "-wal")
    assert wal.is_file() and wal.stat().st_size > 0
    for file in path.parent.glob(path.name + "*"):
        assert marker.encode() not in file.read_bytes(), file.name


@pytest.mark.parametrize("field", METADATA_FIELDS)
@pytest.mark.parametrize("separator", ["\t", "\n", "   "], ids=["tab", "newline", "spaces"])
def test_full_content_whitespace_copies_are_not_retained(tmp_path, field, separator):
    store = Store(tmp_path / "audit.db")
    sample = event(**{field: CONTENT.replace(" ", separator)})
    with store.connection() as keeper:
        assert keeper.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        keeper.execute("PRAGMA wal_autocheckpoint=0")
        result = Engine(store).evaluate(sample)
        assert getattr(result.event, field) == NOT_RETAINED
        assert result.event.content == NOT_RETAINED
        assert "FAKE_NORMALIZED" not in result.model_dump_json()
        assert store.get_event(result.id)["event"][field] == NOT_RETAINED
        assert_absent_from_database_and_wal(store.path, "FAKE_NORMALIZED")
    database_files = list(store.path.parent.glob(store.path.name + "*"))
    assert database_files
    for file in database_files:
        assert b"FAKE_NORMALIZED" not in file.read_bytes()


@pytest.mark.parametrize("content", [
    "FAKE_SANITIZED X https://fake-user:fake-password@example.invalid/path?hidden=FAKE_QUERY#FAKE_FRAGMENT api_key=FAKE_CREDENTIAL_123456",
    "FAKE_NORMALIZED [x] (a+b)? . *",
], ids=["sanitized-url-and-credential", "literal-regex-metacharacters"])
def test_repeated_sanitized_normalized_copies_are_removed_inside_all_metadata(tmp_path, content):
    store = Store(tmp_path / "audit.db")
    rendered = sanitize_metadata(content).replace(" ", "\t  \n")
    sample = event(content=content,
                   **{field: f"prefix {rendered} middle {rendered} suffix" for field in METADATA_FIELDS})
    with store.connection() as keeper:
        assert keeper.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        keeper.execute("PRAGMA wal_autocheckpoint=0")
        result = Engine(store).evaluate(sample)
        stored = store.get_event(result.id)
        for field in METADATA_FIELDS:
            assert getattr(result.event, field) == f"prefix {NOT_RETAINED} middle {NOT_RETAINED} suffix"
            assert stored["event"][field] == getattr(result.event, field)
        assert_absent_from_database_and_wal(store.path, content.split()[0])


def test_normalized_copy_replacement_remains_within_metadata_limits(tmp_path):
    metadata = "X\tY " * 200
    sample = event(content="X Y",
                   **{field: metadata for field in METADATA_FIELDS})
    result = Engine(Store(tmp_path / "audit.db")).evaluate(sample)
    for field in METADATA_FIELDS:
        assert getattr(result.event, field) == ((NOT_RETAINED + " ") * 200)[:1024]


def test_content_whitespace_is_normalized_as_well_as_metadata(tmp_path):
    sample = event(content="\t FAKE_NORMALIZED \n  X  ",
                   **{field: f"prefix {CONTENT} suffix" for field in METADATA_FIELDS})
    result = Engine(Store(tmp_path / "audit.db")).evaluate(sample)
    for field in METADATA_FIELDS:
        assert getattr(result.event, field) == f"prefix {NOT_RETAINED} suffix"


@pytest.mark.parametrize("body", [
    " " * 1100 + "FAKE_COMPLETE_BODY X",
    "FAKE_COMPLETE_BODY" + " " * 1100 + "X",
    "\t\n" * 600 + "FAKE_COMPLETE_BODY X",
    "\u2003" * 1100 + "FAKE_COMPLETE_BODY X",
    " " * 32000 + "FAKE_COMPLETE_BODY X",
    "FAKE_COMPLETE_BODY X" + " " * 1100,
], ids=["leading", "internal", "control-whitespace", "unicode-whitespace", "near-body-limit", "trailing-control"])
def test_complete_normalized_body_is_matched_before_storage_truncation(tmp_path, body):
    normalized = "FAKE_COMPLETE_BODY X"
    assert " ".join(body.split()) == normalized
    store = Store(tmp_path / "audit.db")
    sample = event(content=body,
                   **{field: f"prefix {normalized} suffix" for field in METADATA_FIELDS})
    with store.connection() as keeper:
        assert keeper.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        keeper.execute("PRAGMA wal_autocheckpoint=0")
        result = Engine(store).evaluate(sample)
        stored = store.get_event(result.id)
        assert stored is not None
        for field in METADATA_FIELDS:
            assert getattr(result.event, field) == f"prefix {NOT_RETAINED} suffix"
            assert stored["event"][field] == getattr(result.event, field)
        assert_absent_from_database_and_wal(store.path, "FAKE_COMPLETE_BODY")
        assert_absent_from_database_and_wal(store.path, "BODY X")
    assert Store(store.path).get_event(result.id) == stored
    for file in store.path.parent.glob(store.path.name + "*"):
        assert b"FAKE_COMPLETE_BODY" not in file.read_bytes()


def test_raw_suppression_precedes_context_changing_sanitizer(tmp_path):
    # Sanitizing first would consume the benign prefix as part of the email.
    content = "FAKE_RAW_CONTEXT@example.invalid"
    metadata = "prefix" + content + " suffix"
    sample = event(content=content,
                   **{field: metadata for field in METADATA_FIELDS})
    store = Store(tmp_path / "audit.db")
    result = Engine(store).evaluate(sample)
    for field in METADATA_FIELDS:
        assert getattr(result.event, field) == f"prefix{NOT_RETAINED} suffix"
        assert store.get_event(result.id)["event"][field] == getattr(result.event, field)


@pytest.mark.parametrize("content", [CONTENT, "", " \t\n"], ids=["nonempty", "empty", "whitespace"])
def test_unrelated_metadata_is_preserved_with_existing_pattern_sanitization(tmp_path, content):
    metadata = dict(session_id="safe-session", app="Fake  browser\tui",
                    source="Public notes\napi_key=FAKE_METADATA_CREDENTIAL_123456",
                    destination="https://fake-user:fake-password@example.invalid/path?hidden=FAKE_QUERY#FAKE_FRAGMENT",
                    declared_intent="Review\tpublic  documents")
    store = Store(tmp_path / "audit.db")
    result = Engine(store).evaluate(event(content=content, **metadata))
    stored = store.get_event(result.id)
    for field, original in metadata.items():
        assert getattr(result.event, field) == sanitize_metadata(original)
        assert stored["event"][field] == sanitize_metadata(original)
    for marker in ("FAKE_METADATA_CREDENTIAL_123456", "fake-user", "fake-password", "FAKE_QUERY", "FAKE_FRAGMENT"):
        assert marker not in result.model_dump_json()
