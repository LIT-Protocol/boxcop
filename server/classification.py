"""Bounded cache in front of the regex content labels. No model, no network."""
from collections import OrderedDict
from hashlib import sha256
from threading import Lock
from time import monotonic

from .classify import classify


class ContentClassifier:
    def __init__(self, *, capacity=128, ttl=60, clock=monotonic):
        if capacity < 1 or ttl <= 0:
            raise ValueError('Invalid classifier bounds')
        self.capacity, self.ttl, self.clock = capacity, ttl, clock
        self._lock = Lock()
        self._cache = OrderedDict()

    def labels(self, text):
        # Always classify the complete submitted text. Large inputs aren't cached.
        if len(text) > 4096:
            return classify(text)
        key = sha256(text.encode('utf-8')).digest()
        now = self.clock()
        with self._lock:
            row = self._cache.get(key)
            if row and row[0] > now:
                self._cache.move_to_end(key)
                return list(row[1])
        labels = tuple(classify(text))
        with self._lock:
            self._cache[key] = (now + self.ttl, labels)
            self._cache.move_to_end(key)
            while len(self._cache) > self.capacity:
                self._cache.popitem(last=False)
        return list(labels)

    def clear(self):
        with self._lock:
            self._cache.clear()
