"""Aggregate model attempts only: no content, hashes, categories or exception text."""
from threading import Lock


MINILM_BACKEND = 'minilm-head-v1'
QWEN_BACKEND = 'qwen3.5-4b-workflow-v2'
LEGACY_BACKENDS = ('qwen3.5-4b-review-v1',)
BACKENDS = (MINILM_BACKEND, QWEN_BACKEND)
OUTCOMES = ('ready', 'uncertain', 'unsupported', 'unavailable', 'error')
COUNTERS = ('attempts', *OUTCOMES)


def empty_counts():
    return {backend: dict.fromkeys(COUNTERS, 0) for backend in BACKENDS}


class ClassifierUsage:
    """The worker writes totals; status reads memory without waiting for SQLite."""
    def __init__(self, store=None):
        self._store = store
        self._lock = Lock()
        self._counts = empty_counts()
        self._persistence_ok = store is not None
        if store is not None:
            try:
                self._counts = store.classifier_usage()
            except Exception:
                self._persistence_ok = False

    def record(self, backend, counter):
        if backend not in BACKENDS or counter not in COUNTERS:
            raise ValueError('Invalid classifier usage counter')
        with self._lock:
            self._counts[backend][counter] += 1
            persist = self._persistence_ok
        # Never hold the status/cache lock across disk I/O. A telemetry failure
        # must not kill the worker or change a policy decision.
        if persist:
            try:
                self._store.record_classifier_usage(backend, counter)
            except Exception:
                with self._lock:
                    # Stop persisting this session: a missing attempt must not
                    # later gain a durable outcome. Memory totals still work.
                    self._persistence_ok = False

    def snapshot(self):
        with self._lock:
            return {'persistence_ok': self._persistence_ok,
                    'backends': {backend: dict(counts) for backend, counts in self._counts.items()}}
