"""Bounded content-only cache and asynchronous local model observations.

No destination decisions are cached. Learned output is shadow-only until qualified.
No network access, model loading or inference happens in the decision caller.
"""
from collections import OrderedDict
from dataclasses import dataclass
from hashlib import sha256
from threading import Condition, Thread
from time import monotonic

from .classify import classify
from .classifier_usage import ClassifierUsage, MINILM_BACKEND, OUTCOMES


@dataclass(frozen=True)
class Observation:
    state: str
    category: str = 'unknown'
    backend: str = 'none'


class ContentClassifier:
    def __init__(self, advisor=None, *, version='rules-v1', capacity=128, ttl=60,
                 queue_capacity=4, clock=monotonic):
        if capacity < 1 or queue_capacity < 1 or ttl <= 0:
            raise ValueError('Invalid classifier bounds')
        self.version, self.capacity, self.ttl = version, capacity, ttl
        self.clock, self.advisor, self.queue_capacity = clock, advisor, queue_capacity
        self.usage = getattr(advisor, 'usage', None) or ClassifierUsage()
        self._cv = Condition()
        self._cache, self._pending = OrderedDict(), OrderedDict()
        self._active = None
        self._closed = False
        self._generation = 0
        self._counts = dict(hits=0, misses=0, coalesced=0, dropped=0, completed=0, failures=0)
        self._worker = None
        if advisor is not None:
            self._worker = Thread(target=self._run, name='boxcop-classifier', daemon=True)
            self._worker.start()

    def _key(self, text):
        return self.version, sha256(text.encode('utf-8')).digest()

    def labels(self, text):
        # Always classify the complete submitted text. Large inputs aren't cached.
        if len(text) > 4096:
            return classify(text)
        key = self._key(text)
        with self._cv:
            row = self._cache.get(key)
            now = self.clock()
            if row and row[0] > now:
                self._cache.move_to_end(key)
                self._counts['hits'] += 1
                return list(row[1])
            self._counts['misses'] += 1
        labels = tuple(classify(text))
        with self._cv:
            if self._closed: return list(labels)
            self._cache[key] = (now + self.ttl, labels, Observation('pending' if self.advisor else 'unavailable'))
            self._cache.move_to_end(key)
            while len(self._cache) > self.capacity:
                self._cache.popitem(last=False)
            if self.advisor and text.strip():
                job = (self._generation, key)
                if job == self._active or job in self._pending:
                    self._counts['coalesced'] += 1
                else:
                    while len(self._pending) >= self.queue_capacity:
                        (_, old_key), _ = self._pending.popitem(last=False)
                        old = self._cache.get(old_key)
                        if old: self._cache[old_key] = (*old[:2], Observation('dropped'))
                        self._counts['dropped'] += 1
                    self._pending[job] = text
                    self._cv.notify()
        return list(labels)

    def observation(self, text):
        if len(text) > 4096: return Observation('unsupported')
        with self._cv:
            row = self._cache.get(self._key(text))
            return row[2] if row and row[0] > self.clock() else Observation('missing')

    def stats(self):
        usage = self.usage.snapshot()
        with self._cv:
            return {**self._counts, 'queued': len(self._pending), 'cached': len(self._cache),
                    'model_usage': usage,
                    'active': self._active is not None, 'shadow_only': True,
                    'ready': sum(row[2].state == 'ready' for row in self._cache.values()),
                    'unavailable': sum(row[2].state in {'unavailable', 'error'} for row in self._cache.values()),
                    'uncertain': sum(row[2].state in {'uncertain', 'unsupported'} for row in self._cache.values())}

    def clear(self):
        with self._cv:
            self._generation += 1
            self._cache.clear(); self._pending.clear()

    def close(self):
        with self._cv:
            self._closed = True
            self.clear(); self._cv.notify_all()
        # Never wait for native inference from an action/teardown thread.

    def _run(self):
        while True:
            with self._cv:
                self._cv.wait_for(lambda: self._closed or self._pending)
                if self._closed: return
                job, text = self._pending.popitem(last=True)  # newest revision first
                self._active = job
            try:
                result = self.advisor(text)
                if not isinstance(result, Observation): raise ValueError('Invalid advisor output')
            except Exception:
                result = Observation('error')  # Never persist exceptions or raw content.
            finally:
                del text
            with self._cv:
                self._active = None
                generation, key = job
                row = self._cache.get(key)
                if not self._closed and generation == self._generation and row and row[0] > self.clock():
                    self._cache[key] = (*row[:2], result)
                    self._counts['completed'] += 1
                    if result.state == 'error': self._counts['failures'] += 1
                self._cv.notify_all()


class LocalAdvisor:
    """Pinned MiniLM head; uncertain fields are reviewed by the holistic workflow model."""
    HEAD_SHA256 = 'aab2c29d5f562daeb612dd4a9011738b40846cb3afcdb2d31c44bb857ff77e17'

    def __init__(self, usage=None):
        self._analyzer = None
        self._head = None
        self.usage = usage or ClassifierUsage()

    def __call__(self, text):
        return self._observe(MINILM_BACKEND, self._classify, text)

    def _observe(self, backend, operation, text):
        self.usage.record(backend, 'attempts')
        try:
            result = operation(text)
            if not isinstance(result, Observation) or result.backend != backend or result.state not in OUTCOMES:
                raise ValueError('Invalid model observation')
        except Exception:
            result = Observation('error', backend=backend)
        self.usage.record(backend, result.state)
        return result

    def _classify(self, text):
        import json
        from pathlib import Path
        from .semantic import SemanticAnalyzer, MODEL_REVISION
        import numpy as np
        if self._analyzer is None:
            self._analyzer = SemanticAnalyzer()
        if self._head is None:
            data = (Path(__file__).parent / 'assets/classifier-head.json').read_bytes()
            if sha256(data).hexdigest() != self.HEAD_SHA256: raise ValueError('Invalid head')
            self._head = json.loads(data)
            if self._head['encoder_revision'] != MODEL_REVISION: raise ValueError('Encoder mismatch')
        analyzer = self._analyzer
        with analyzer._lock:
            if not analyzer._load(): return Observation('unavailable', backend=MINILM_BACKEND)
            vector, truncated = analyzer._embed(text)
        if truncated or len(text) > 4096: return Observation('unsupported', backend=MINILM_BACKEND)
        logits = np.sum(np.asarray(self._head['weights']) * vector, axis=1) + self._head['bias']
        probabilities = np.exp(logits - np.max(logits)); probabilities /= probabilities.sum()
        index = int(np.argmax(probabilities))
        if probabilities[index] >= .8:
            return Observation('ready', self._head['classes'][index], MINILM_BACKEND)
        # Uncertain fields are reviewed in workflow context; no second model here.
        return Observation('uncertain', backend=MINILM_BACKEND)


def self_test():
    """Build diagnostic: fixed synthetic input, real MiniLM/head, no Qwen or DB."""
    import json
    try:
        result = LocalAdvisor()._classify('Public museum announcement: admission is free on Thursdays.')
        ready = result.backend == MINILM_BACKEND and result.state in {'ready', 'uncertain'}
    except Exception:
        ready = False
    print(json.dumps({'ready': ready, 'backend': MINILM_BACKEND, 'shadow_only': True}))
    return 0 if ready else 1
