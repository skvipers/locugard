"""Многомерный ограничитель частоты (sliding window + очистка устаревших бакетов, чистая stdlib)."""
from __future__ import annotations

import threading
import time
from collections import deque


class RateLimiter:
    def __init__(self, *, max_buckets: int = 10_000) -> None:
        self._lock = threading.Lock()
        self._buckets: dict[str, tuple[float, deque[float]]] = {}
        self._max_buckets = max_buckets
        self._ops = 0

    def _prune_locked(self, now: float) -> None:
        dead = [k for k, (win, q) in self._buckets.items() if not q or q[-1] <= now - win]
        for k in dead:
            del self._buckets[k]
        # Защита от неограниченного роста памяти при распределённом флуде уникальных ключей
        if len(self._buckets) > self._max_buckets:
            oldest = sorted(self._buckets.items(), key=lambda kv: kv[1][1][-1] if kv[1][1] else 0.0)
            for k, _ in oldest[: len(self._buckets) - self._max_buckets]:
                del self._buckets[k]

    def allow(self, key: str, limit: int, window_s: float, *, now: float | None = None) -> bool:
        t = time.time() if now is None else now
        cutoff = t - window_s
        with self._lock:
            self._ops += 1
            if self._ops % 256 == 0 or len(self._buckets) > self._max_buckets:
                self._prune_locked(t)
            entry = self._buckets.get(key)
            if entry is None:
                q: deque[float] = deque()
                self._buckets[key] = (window_s, q)
            else:
                _, q = entry
                self._buckets[key] = (max(entry[0], window_s), q)
            while q and q[0] <= cutoff:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(t)
            return True

    def count(self, key: str, window_s: float, *, now: float | None = None) -> int:
        t = time.time() if now is None else now
        cutoff = t - window_s
        with self._lock:
            entry = self._buckets.get(key)
            if not entry:
                return 0
            _, q = entry
            while q and q[0] <= cutoff:
                q.popleft()
            if not q:
                del self._buckets[key]
                return 0
            return len(q)
