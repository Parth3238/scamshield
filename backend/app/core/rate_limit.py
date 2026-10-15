"""Sliding-window rate limiters with a shared interface.

Two implementations behind one small interface:

- InMemoryLimiter: local process memory. Used when REDIS_URL is not set
  and in unit tests. Fast, but each server process counts separately.
- RedisLimiter: counts live in Redis (one sorted set per key), so every
  server process sees the same numbers. Used when REDIS_URL is set.
- FailoverLimiter: tries Redis first, falls back to a local in-memory
  limiter when Redis is unreachable. The app never crashes on Redis
  trouble; limits just become per-process until Redis is back.

RateLimiter is kept as an alias of InMemoryLimiter so existing imports
keep working.
"""

from __future__ import annotations

import hashlib
import logging
import os
import time
import uuid
from collections import deque
from collections.abc import Callable

logger = logging.getLogger("scamshield.ratelimit")

# Prefix for every Redis key. Raw caller data (emails, IPs, key ids)
# is always sha256-hashed before it becomes part of a key.
KEY_PREFIX = "ss:rl"

# Redis commands get at most this long before we give up and fall back.
REDIS_TIMEOUT_SECONDS = 1.0

# Keys expire this long after the window ends, so dead keys vanish alone.
TTL_BUFFER_SECONDS = 60


class RedisUnavailable(Exception):
    """Raised when a Redis operation cannot complete (down, timeout, ...)."""


class InMemoryLimiter:
    """Sliding-window limiter: at most max_attempts hits per key in a window.

    The clock is injectable so tests can move time forward without waiting:
    pass clock=fake_clock, or call set_clock() later on a global instance.
    """

    def __init__(
        self,
        max_attempts: int = 5,
        window_seconds: int = 15 * 60,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        # Injectable clock so tests can move time forward without waiting.
        self._clock: Callable[[], float] = clock or time.monotonic
        self._hits: dict[str, deque[float]] = {}

    def set_clock(self, clock: Callable[[], float]) -> None:
        """Replace the clock (tests use a fake clock to skip waiting)."""
        self._clock = clock

    def _prune(self, key: str) -> deque[float]:
        now = self._clock()
        kept = deque(
            t for t in self._hits.get(key, ()) if now - t < self.window_seconds
        )
        if kept:
            self._hits[key] = kept
        else:
            self._hits.pop(key, None)
        return kept

    def count(self, key: str) -> int:
        """Return the number of hits for a key inside the current window."""
        return len(self._prune(key))

    def remaining(self, key: str) -> int:
        """Return how many more hits are allowed before blocking."""
        return max(0, self.max_attempts - self.count(key))

    def is_blocked(self, key: str) -> tuple[bool, int]:
        """Return (blocked, retry_after_seconds from the oldest hit)."""
        kept = self._prune(key)
        if len(kept) >= self.max_attempts:
            retry = int(self.window_seconds - (self._clock() - kept[0])) + 1
            return True, max(retry, 1)
        return False, 0

    def record_hit(self, key: str) -> None:
        """Count one event (a report, a failure, ...) for a key."""
        kept = self._prune(key)
        kept.append(self._clock())
        self._hits[key] = kept

    def record_failure(self, key: str) -> None:
        """Count one failure for a key. Same mechanism as record_hit."""
        self.record_hit(key)

    def reset(self, key: str) -> None:
        """Clear failures for a key, normally after a successful login."""
        self._hits.pop(key, None)

    def clear(self) -> None:
        """Clear all keys. Mainly useful in tests."""
        self._hits.clear()


# Backwards-compatible name used across the app and tests.
RateLimiter = InMemoryLimiter


class RedisLimiter:
    """Sliding-window limiter backed by one Redis sorted set per key.

    Each hit is a member scored by its timestamp (milliseconds). Every
    check and every record runs as a single MULTI/EXEC pipeline
    (remove-old, count/read, add, expire), so concurrent server
    processes cannot interleave inside one operation.

    The `clock` supplies "now" in seconds (injectable for tests with a
    fake clock). Key expiry still uses the Redis server clock.
    """

    def __init__(
        self,
        max_attempts: int,
        window_seconds: int,
        client,
        scope: str,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._client = client
        self._scope = scope
        self._clock: Callable[[], float] = clock or time.monotonic

    def set_clock(self, clock: Callable[[], float]) -> None:
        """Replace the clock (tests use a fake clock to skip waiting)."""
        self._clock = clock

    @property
    def ttl_seconds(self) -> int:
        """Key expiry: slightly longer than the window."""
        return int(self.window_seconds) + TTL_BUFFER_SECONDS

    def _redis_key(self, key: str) -> str:
        # Never store raw caller text (emails, IPs, key ids) in Redis:
        # hash it first, keep only the scope readable for debugging.
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return f"{KEY_PREFIX}:{self._scope}:{digest}"

    def _window_ms(self) -> tuple[int, int]:
        now_ms = int(self._clock() * 1000)
        return now_ms, int(self.window_seconds * 1000)

    def _run(self, ops):
        import redis as redis_lib

        try:
            return ops()
        except redis_lib.exceptions.RedisError as exc:
            # Log only the error type: messages may echo connection
            # details (host, and never the password, but stay strict).
            logger.warning(
                "redis unavailable for scope=%s (%s); failing over",
                self._scope,
                type(exc).__name__,
            )
            raise RedisUnavailable(str(type(exc).__name__)) from exc

    def _check(self, redis_key: str) -> tuple[int, float | None]:
        """Return (hits-in-window, oldest-hit-time-in-seconds or None)."""
        now_ms, window_ms = self._window_ms()

        def _ops():
            pipe = self._client.pipeline(transaction=True)
            pipe.zremrangebyscore(redis_key, 0, now_ms - window_ms)
            pipe.zcard(redis_key)
            pipe.zrange(redis_key, 0, 0, withscores=True)
            pipe.expire(redis_key, self.ttl_seconds)
            _, count, oldest, _ = pipe.execute()
            oldest_s = oldest[0][1] / 1000.0 if oldest else None
            return count, oldest_s

        return self._run(_ops)

    def _retry_after(self, oldest_s: float) -> int:
        retry = int(self.window_seconds - (self._clock() - oldest_s)) + 1
        return max(retry, 1)

    def count(self, key: str) -> int:
        """Return the number of hits for a key inside the current window."""
        count, _ = self._check(self._redis_key(key))
        return count

    def remaining(self, key: str) -> int:
        """Return how many more hits are allowed before blocking."""
        return max(0, self.max_attempts - self.count(key))

    def is_blocked(self, key: str) -> tuple[bool, int]:
        """Return (blocked, retry_after_seconds from the oldest hit)."""
        count, oldest_s = self._check(self._redis_key(key))
        if count >= self.max_attempts and oldest_s is not None:
            return True, self._retry_after(oldest_s)
        return False, 0

    def record_hit(self, key: str) -> None:
        """Count one event for a key (atomic prune + add + expire)."""
        now_ms, window_ms = self._window_ms()
        key = self._redis_key(key)
        member = f"{now_ms}:{uuid.uuid4().hex}"

        def _ops():
            pipe = self._client.pipeline(transaction=True)
            pipe.zremrangebyscore(key, 0, now_ms - window_ms)
            pipe.zadd(key, {member: now_ms})
            pipe.expire(key, self.ttl_seconds)
            pipe.execute()

        self._run(_ops)

    def record_failure(self, key: str) -> None:
        """Count one failure for a key. Same mechanism as record_hit."""
        self.record_hit(key)

    def reset(self, key: str) -> None:
        """Clear hits for a key, normally after a successful login."""
        key = self._redis_key(key)

        def _ops():
            self._client.delete(key)

        self._run(_ops)

    def clear(self) -> None:
        """Delete every key in this scope. Mainly useful in tests."""

        def _ops():
            cursor_keys = list(
                self._client.scan_iter(match=f"{KEY_PREFIX}:{self._scope}:*")
            )
            if cursor_keys:
                self._client.delete(*cursor_keys)

        self._run(_ops)


class FailoverLimiter:
    """Try the Redis limiter first, fall back to in-memory on trouble.

    Both sides share the interface, so callers never change. A Redis
    outage only weakens limits to per-process until Redis is back —
    requests (including logins) keep working instead of failing.
    """

    def __init__(
        self, primary: RedisLimiter, fallback: InMemoryLimiter
    ) -> None:
        self._primary = primary
        self._fallback = fallback

    @property
    def max_attempts(self) -> int:
        return self._primary.max_attempts

    @max_attempts.setter
    def max_attempts(self, value: int) -> None:
        self._primary.max_attempts = value
        self._fallback.max_attempts = value

    @property
    def window_seconds(self) -> int:
        return self._primary.window_seconds

    def set_clock(self, clock: Callable[[], float]) -> None:
        """Replace the clock on both sides (tests use a fake clock)."""
        self._primary.set_clock(clock)
        self._fallback.set_clock(clock)

    def _try(self, name: str, *args):
        try:
            return getattr(self._primary, name)(*args)
        except RedisUnavailable:
            # Already logged where it was caught; just use the fallback.
            return getattr(self._fallback, name)(*args)

    def count(self, key: str) -> int:
        return self._try("count", key)

    def remaining(self, key: str) -> int:
        return self._try("remaining", key)

    def is_blocked(self, key: str) -> tuple[bool, int]:
        return self._try("is_blocked", key)

    def record_hit(self, key: str) -> None:
        self._try("record_hit", key)

    def record_failure(self, key: str) -> None:
        self._try("record_failure", key)

    def reset(self, key: str) -> None:
        self._try("reset", key)

    def clear(self) -> None:
        """Clear both sides; a dead Redis must not break test teardown."""
        try:
            self._primary.clear()
        except RedisUnavailable:
            pass
        self._fallback.clear()


_redis_client = None


def get_redis_client():
    """Build (once) the shared Redis client from REDIS_URL.

    Raises RedisUnavailable when REDIS_URL is not set. Creating the
    client never connects; the 1 second timeouts apply per operation.
    """
    global _redis_client
    url = os.getenv("REDIS_URL", "").strip()
    if not url:
        raise RedisUnavailable("no REDIS_URL")
    if _redis_client is None:
        import redis as redis_lib

        _redis_client = redis_lib.Redis.from_url(
            url,
            socket_connect_timeout=REDIS_TIMEOUT_SECONDS,
            socket_timeout=REDIS_TIMEOUT_SECONDS,
            decode_responses=True,
        )
    return _redis_client


def reset_redis_client() -> None:
    """Forget the cached client (tests only)."""
    global _redis_client
    _redis_client = None


def build_limiter(
    max_attempts: int,
    window_seconds: int,
    scope: str,
    clock: Callable[[], float] | None = None,
    client=None,
):
    """Build the right limiter: Redis-backed when possible, else in-memory.

    Pass an explicit client (for example fakeredis in tests) to force the
    Redis path. Otherwise REDIS_URL in the environment selects it.
    """
    if client is None:
        try:
            client = get_redis_client()
        except RedisUnavailable:
            client = None
    if client is None:
        return InMemoryLimiter(
            max_attempts=max_attempts,
            window_seconds=window_seconds,
            clock=clock,
        )
    return FailoverLimiter(
        RedisLimiter(
            max_attempts=max_attempts,
            window_seconds=window_seconds,
            client=client,
            scope=scope,
            clock=clock,
        ),
        InMemoryLimiter(
            max_attempts=max_attempts,
            window_seconds=window_seconds,
            clock=clock,
        ),
    )
