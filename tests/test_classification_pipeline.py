import pytest

from server.classification import ContentClassifier
from server.classifier_usage import ClassifierUsage, QWEN_BACKEND, empty_counts
from server.store import Store


def test_cache_expiration_and_full_content():
    now = [0]
    c = ContentClassifier(clock=lambda: now[0], ttl=10, capacity=2)
    assert c.labels('password=abc') == ['secret']
    assert c.labels('password=abc') == ['secret']
    assert len(c._cache) == 1
    # Large inputs are classified in full and never cached.
    assert c.labels('a' * 4096) == []
    assert c.labels('a' * 4096 + ' password=secret') == ['secret']
    assert len(c._cache) == 2
    now[0] = 10
    c.labels('third'); c.labels('fourth')
    assert len(c._cache) == 2
    c.clear()
    assert not c._cache


def test_cached_labels_cannot_be_mutated_by_a_caller():
    c = ContentClassifier()
    c.labels('password=abc').append('tampered')
    assert c.labels('password=abc') == ['secret']


def test_cache_holds_digests_not_content():
    c = ContentClassifier()
    marker = 'FAKE_PRIVATE_CLASSIFIER_MARKER'
    c.labels(marker)
    assert marker not in repr(c._cache)


def test_backend_totals_survive_store_reopen_without_content(tmp_path):
    store = Store(tmp_path / 'events.sqlite3')
    usage = ClassifierUsage(store)
    usage.record(QWEN_BACKEND, 'attempts')
    usage.record(QWEN_BACKEND, 'uncertain')
    counts = usage.snapshot()
    assert counts['persistence_ok'] is True
    expected = empty_counts()
    expected[QWEN_BACKEND].update(attempts=1, uncertain=1)
    assert counts['backends'] == expected
    assert ClassifierUsage(Store(store.path)).snapshot() == counts
    with store.connection() as db:
        assert len(db.execute('SELECT * FROM classifier_usage').fetchall()) == 2
        assert db.execute('SELECT COUNT(*) FROM events').fetchone()[0] == 0


def test_failed_usage_write_stops_persisting_but_keeps_memory_totals(tmp_path, monkeypatch):
    store = Store(tmp_path / 'events.sqlite3')
    def failed_write(*args):
        raise OSError('PRIVATE_DATABASE_ERROR')
    monkeypatch.setattr(store, 'record_classifier_usage', failed_write)
    usage = ClassifierUsage(store)
    usage.record(QWEN_BACKEND, 'attempts')
    usage.record(QWEN_BACKEND, 'ready')
    stats = usage.snapshot()
    assert stats['persistence_ok'] is False
    assert stats['backends'][QWEN_BACKEND] == dict(empty_counts()[QWEN_BACKEND], attempts=1, ready=1)
    assert store.classifier_usage() == empty_counts()
    assert 'PRIVATE_DATABASE_ERROR' not in repr(stats)


def test_usage_read_failure_is_visible_and_does_not_poison_counting(tmp_path, monkeypatch):
    store = Store(tmp_path / 'events.sqlite3')
    def broken(): raise OSError('PRIVATE_READ_ERROR')
    monkeypatch.setattr(store, 'classifier_usage', broken)
    usage = ClassifierUsage(store)
    usage.record(QWEN_BACKEND, 'attempts')
    assert usage.snapshot()['persistence_ok'] is False
    assert usage.snapshot()['backends'][QWEN_BACKEND]['attempts'] == 1
    with pytest.raises(ValueError): store.record_classifier_usage('PRIVATE_BACKEND', 'attempts')
    with pytest.raises(ValueError): store.record_classifier_usage(QWEN_BACKEND, 'PRIVATE_COUNTER')


def test_unknown_or_inconsistent_stored_totals_are_refused(tmp_path):
    store = Store(tmp_path / 'events.sqlite3')
    with store.connection() as db:
        db.execute("INSERT INTO classifier_usage VALUES (?, 'ready', 3)", (QWEN_BACKEND,))
    assert ClassifierUsage(store).snapshot()['persistence_ok'] is False
