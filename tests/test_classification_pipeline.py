from threading import Event
import json
import pytest

from server.classification import ContentClassifier, LocalAdvisor, Observation
from server.classifier_usage import ClassifierUsage, MINILM_BACKEND, QWEN_BACKEND, empty_counts
from server.engine import Engine
from server.models import EventInput
from server.store import Store


def test_cache_expiration_full_content_and_version():
    now = [0]
    c = ContentClassifier(clock=lambda: now[0], ttl=10, capacity=2)
    assert c.labels('password=abc') == ['secret']
    assert c.labels('password=abc') == ['secret']
    assert c.stats()['hits'] == 1
    assert c.labels('a' * 4096) == []
    assert c.labels('a' * 4096 + ' password=secret') == ['secret']
    now[0] = 10
    assert c.observation('password=abc').state == 'missing'
    c.labels('password=abc'); c.version = 'new'
    assert c.observation('password=abc').state == 'missing'
    c.close()
    assert c.stats()['cached'] == 0


def test_blocking_model_never_blocks_rules_and_queue_is_bounded():
    entered, release = Event(), Event()
    def advisor(text):
        entered.set(); release.wait(3)
        return Observation('ready', 'public', 'test')
    c = ContentClassifier(advisor, queue_capacity=2)
    try:
        c.labels('first'); assert entered.wait(1)
        for text in ['second', 'third', 'fourth']: c.labels(text)
        assert c.labels('password=abc') == ['secret']
        assert c.stats()['queued'] == 2
        assert c.stats()['dropped'] == 2
        c.clear(); release.set()
        with c._cv: assert c._cv.wait_for(lambda: c._active is None, timeout=2)
        assert c.stats()['cached'] == 0
        assert c.observation('first').state == 'missing'
    finally:
        release.set(); c.close()


def test_public_model_result_cannot_weaken_policy_and_destination_is_live(tmp_path):
    c = ContentClassifier(lambda text: Observation('ready', 'public', 'wrong-model'))
    engine = Engine(Store(tmp_path / 'events.sqlite3'), classifier=c)
    def event(destination):
        return EventInput(session_id='s', actor='human', role='engineering', action='paste',
                          app='test', destination=destination, content='password=abc')
    try:
        assert engine.evaluate(event('local')).decision.action == 'warn'
        with c._cv: assert c._cv.wait_for(lambda: c._active is None and not c._pending, timeout=2)
        assert c.observation('password=abc').category == 'public'
        assert engine.evaluate(event('https://external.example')).decision.action == 'block'
        assert c.stats()['hits'] == 1
    finally: c.close()


def test_advisor_failure_is_explicit_and_content_not_in_cache():
    def broken(text): raise RuntimeError(text)
    c = ContentClassifier(broken)
    try:
        c.labels('unique private material')
        with c._cv: assert c._cv.wait_for(lambda: c._active is None and not c._pending, timeout=2)
        assert c.observation('unique private material').state == 'error'
        assert 'unique private material' not in repr(c._cache)
        assert c.stats()['failures'] == 1
    finally: c.close()


def test_isolated_text_advisor_has_no_external_service_fallback():
    assert not hasattr(LocalAdvisor, '_review')


def wait_for_classifier(classifier):
    with classifier._cv:
        assert classifier._cv.wait_for(lambda: classifier._active is None and not classifier._pending, timeout=3)


def test_backend_totals_survive_cache_clear_and_store_reopen_without_content(tmp_path, monkeypatch):
    store = Store(tmp_path / 'events.sqlite3')
    advisor = LocalAdvisor(ClassifierUsage(store))
    monkeypatch.setattr(advisor, '_classify', lambda text: Observation('uncertain', backend=MINILM_BACKEND))
    c = ContentClassifier(advisor)
    marker = 'FAKE_PRIVATE_CLASSIFIER_USAGE_MARKER'
    try:
        c.labels(marker); wait_for_classifier(c)
        c.labels(marker)  # A cache hit is not another model attempt.
        c.clear()
        counts = c.stats()['model_usage']
        assert counts['persistence_ok'] is True
        expected = empty_counts()
        expected[MINILM_BACKEND].update(attempts=1, uncertain=1)
        assert counts['backends'] == expected
        assert c.stats()['cached'] == 0 and c.stats()['hits'] == 1
    finally:
        c.close()
    assert ClassifierUsage(Store(store.path)).snapshot() == counts
    with store.connection() as db:
        assert len(db.execute('SELECT * FROM classifier_usage').fetchall()) == 2
        assert db.execute('SELECT COUNT(*) FROM events').fetchone()[0] == 0
    from hashlib import sha256
    for file in tmp_path.iterdir():
        data = file.read_bytes()
        assert marker.encode() not in data and sha256(marker.encode()).digest() not in data
        assert b'credentials' not in data  # Predictions are not usage telemetry.


@pytest.mark.parametrize('state', ['ready', 'uncertain', 'unsupported', 'unavailable', 'error'])
def test_minilm_outcome_is_counted_without_calling_qwen(tmp_path, monkeypatch, state):
    advisor = LocalAdvisor(ClassifierUsage(Store(tmp_path / 'events.sqlite3')))
    def classify(text):
        if state == 'error':
            raise ImportError('PRIVATE_RUNTIME_ERROR')
        return Observation(state, backend=MINILM_BACKEND)
    monkeypatch.setattr(advisor, '_classify', classify)
    result = advisor('synthetic')
    assert result.state == state and result.backend == MINILM_BACKEND
    counts = advisor.usage.snapshot()['backends']
    assert counts[MINILM_BACKEND]['attempts'] == counts[MINILM_BACKEND][state] == 1
    assert counts[QWEN_BACKEND]['attempts'] == 0
    assert 'PRIVATE_RUNTIME_ERROR' not in repr(advisor.usage.snapshot()) + repr(result)


def test_stale_completion_counts_real_work_but_dropped_jobs_do_not(tmp_path, monkeypatch):
    entered, release = Event(), Event()
    advisor = LocalAdvisor(ClassifierUsage(Store(tmp_path / 'events.sqlite3')))
    def classify(text):
        entered.set(); assert release.wait(3)
        return Observation('ready', backend=MINILM_BACKEND)
    monkeypatch.setattr(advisor, '_classify', classify)
    c = ContentClassifier(advisor, queue_capacity=1)
    try:
        c.labels('first'); assert entered.wait(1)
        c.labels('dropped'); c.labels('cleared')
        c.clear(); release.set(); wait_for_classifier(c)
        assert c.stats()['completed'] == 0 and c.stats()['dropped'] == 1
        assert c.stats()['model_usage']['backends'][MINILM_BACKEND]['ready'] == 1
        assert c.stats()['model_usage']['backends'][MINILM_BACKEND]['attempts'] == 1
    finally:
        release.set(); c.close()


def test_blocked_or_failed_usage_write_does_not_block_rules_or_status(tmp_path, monkeypatch):
    entered, release = Event(), Event()
    store = Store(tmp_path / 'events.sqlite3')
    def blocked_write(*args):
        entered.set(); assert release.wait(3)
        raise OSError('PRIVATE_DATABASE_ERROR')
    monkeypatch.setattr(store, 'record_classifier_usage', blocked_write)
    advisor = LocalAdvisor(ClassifierUsage(store))
    monkeypatch.setattr(advisor, '_classify', lambda text: Observation('ready', backend=MINILM_BACKEND))
    c = ContentClassifier(advisor)
    try:
        c.labels('synthetic'); assert entered.wait(1)
        assert c.stats()['model_usage']['backends'][MINILM_BACKEND]['attempts'] == 1
        assert c.labels('password=FAKE_1234') == ['secret']
        c.clear(); release.set(); wait_for_classifier(c)
        stats = c.stats()['model_usage']
        assert stats['persistence_ok'] is False
        assert stats['backends'][MINILM_BACKEND]['ready'] == 1
        assert store.classifier_usage() == empty_counts()
        assert 'PRIVATE_DATABASE_ERROR' not in repr(stats)
    finally:
        release.set(); c.close()


def test_usage_read_failure_is_visible_and_does_not_poison_inference(tmp_path, monkeypatch):
    store = Store(tmp_path / 'events.sqlite3')
    def broken(): raise OSError('PRIVATE_READ_ERROR')
    monkeypatch.setattr(store, 'classifier_usage', broken)
    usage = ClassifierUsage(store)
    usage.record(MINILM_BACKEND, 'attempts')
    assert usage.snapshot()['persistence_ok'] is False
    assert usage.snapshot()['backends'][MINILM_BACKEND]['attempts'] == 1
    with pytest.raises(ValueError): store.record_classifier_usage('PRIVATE_BACKEND', 'attempts')
    with pytest.raises(ValueError): store.record_classifier_usage(MINILM_BACKEND, 'PRIVATE_COUNTER')


def test_self_test_rejects_missing_or_corrupt_model_without_network(tmp_path, monkeypatch, capsys):
    from server import semantic
    from server.desktop import main
    monkeypatch.setattr(semantic, 'DEFAULT_MODEL_DIR', tmp_path)
    for corrupt in (False, True):
        if corrupt:
            for artifact in semantic.ARTIFACTS:
                (tmp_path / artifact.filename).write_bytes(b'invalid')
        assert main(['--classifier-self-test']) == 1
        assert json.loads(capsys.readouterr().out)['ready'] is False


def test_self_test_accepts_successful_minilm_inference_without_qwen(monkeypatch, capsys):
    from server.desktop import main
    monkeypatch.setattr(LocalAdvisor, '_classify', lambda *args: Observation('uncertain', backend=MINILM_BACKEND))
    assert main(['--classifier-self-test']) == 0
    assert json.loads(capsys.readouterr().out) == {'ready': True, 'backend': MINILM_BACKEND, 'shadow_only': True}


def test_legacy_text_review_usage_is_preserved_but_not_relabelled(tmp_path):
    store = Store(tmp_path / 'events.sqlite3')
    with store.connection() as db:
        db.execute("INSERT INTO classifier_usage VALUES ('qwen3.5-4b-review-v1', 'attempts', 7)")
        db.execute("INSERT INTO classifier_usage VALUES ('qwen3.5-4b-review-v1', 'ready', 6)")
    usage = ClassifierUsage(store)
    assert usage.snapshot()['persistence_ok']
    assert usage.snapshot()['backends'][QWEN_BACKEND]['attempts'] == 0
    usage.record(QWEN_BACKEND, 'attempts')
    usage.record(QWEN_BACKEND, 'ready')
    assert ClassifierUsage(Store(store.path)).snapshot() == usage.snapshot()
    with store.connection() as db:
        assert db.execute("SELECT count FROM classifier_usage WHERE backend='qwen3.5-4b-review-v1' AND counter='attempts'").fetchone()[0] == 7
