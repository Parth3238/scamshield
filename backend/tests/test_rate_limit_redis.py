"""Redis-backed rate limiter tests. No real Redis: fakeredis instead."""

from __future__ import annotations

import fakeredis
import pytest
import redis as redis_lib
from fastapi.testclient import TestClient

import app.services.api_throttle as throttle
from app.api import routes_auth
from app.core.database import get_db
from app.core.rate_limit import (
    FailoverLimiter,
    InMemoryLimiter,
    RedisLimiter,
    build_limiter,
)
from app.main import app


class FakeClock:
    """Injectable clock: tests move time forward without waiting."""

    def __init__(self, start: float = 1_000_000.0):
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _fake_client():
    return fakeredis.FakeStrictRedis(decode_responses=True)


def _limiter(client, clock, limit=2, window=60, scope="t"):
    return RedisLimiter(
        max_attempts=limit,
        window_seconds=window,
        client=client,
        scope=scope,
        clock=clock,
    )


def test_redis_limits_work_and_window_slides():
    clock = FakeClock()
    lim = _limiter(_fake_client(), clock)
    assert lim.is_blocked("k") == (False, 0)
    lim.record_hit("k")
    lim.record_hit("k")
    blocked, retry = lim.is_blocked("k")
    assert blocked and retry == 61  # 60 - 0 elapsed + 1
    clock.advance(61)
    assert lim.is_blocked("k") == (False, 0)
    assert lim.count("k") == 0


def test_retry_after_comes_from_oldest_hit():
    clock = FakeClock()
    lim = _limiter(_fake_client(), clock, limit=3)
    lim.record_hit("k")  # t=0
    clock.advance(10)
    lim.record_hit("k")  # t=10
    clock.advance(10)
    lim.record_hit("k")  # t=20
    clock.advance(5)  # t=25
    blocked, retry = lim.is_blocked("k")
    assert blocked
    assert retry == 60 - 25 + 1  # oldest hit (t=0) decides, not newest


def test_two_instances_share_counts():
    # Two limiter objects on one Redis = two server processes.
    server = _fake_client()
    clock = FakeClock()
    first = _limiter(server, clock, scope="shared")
    second = _limiter(server, clock, scope="shared")
    first.record_hit("k")
    first.record_hit("k")
    assert second.count("k") == 2
    assert second.is_blocked("k")[0] is True


def test_ttl_is_set_on_keys():
    client = _fake_client()
    lim = _limiter(client, FakeClock(), window=60)
    lim.record_hit("k")
    key = lim._redis_key("k")
    ttl = client.ttl(key)
    assert 0 < ttl <= 60 + 60  # window + buffer


def test_keys_do_not_contain_raw_values():
    client = _fake_client()
    lim = _limiter(client, FakeClock())
    lim.record_hit("user@example.com|1.2.3.4")
    lim.record_hit("key:some-api-key-id")
    keys = [str(k) for k in client.keys("*")]
    assert keys, "expected at least one key in Redis"
    assert all(k.startswith("ss:rl:t:") for k in keys)
    blob = " ".join(keys)
    assert "user@example.com" not in blob
    assert "some-api-key-id" not in blob
    assert "1.2.3.4" not in blob


def test_build_limiter_without_client_stays_in_memory(monkeypatch):
    monkeypatch.delenv("REDIS_URL", raising=False)
    from app.core import rate_limit as rl

    monkeypatch.setattr(rl, "_redis_client", None)
    lim = build_limiter(2, 60, scope="t")
    assert isinstance(lim, InMemoryLimiter)


class BrokenRedis:
    """Client that fails every command, like a dead Redis server."""

    def pipeline(self, transaction=True):
        raise redis_lib.exceptions.ConnectionError("redis is down")

    def delete(self, *args):
        raise redis_lib.exceptions.ConnectionError("redis is down")

    def scan_iter(self, *args, **kwargs):
        raise redis_lib.exceptions.ConnectionError("redis is down")


def test_failover_uses_memory_when_redis_is_down(caplog):
    clock = FakeClock()
    lim = FailoverLimiter(
        RedisLimiter(2, 60, BrokenRedis(), "t", clock=clock),
        InMemoryLimiter(2, 60, clock=clock),
    )
    lim.record_hit("k")
    lim.record_hit("k")
    assert lim.is_blocked("k")[0] is True
    assert lim.count("k") == 2
    assert "redis unavailable" in caplog.text


def _make_test_db():
    # Same SQLite-by-default helper as the other endpoint tests.
    from tests.db_helper import make_test_engine, make_testing_session

    engine = make_test_engine()
    return engine, make_testing_session(engine)


@pytest.fixture()
def test_db():
    engine, TestingSession = _make_test_db()

    def _override():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = _override
    try:
        yield TestingSession
    finally:
        app.dependency_overrides.clear()
        engine.dispose()


def _failover(client, clock, limit, window, scope):
    return FailoverLimiter(
        RedisLimiter(limit, window, client, scope, clock=clock),
        InMemoryLimiter(limit, window, clock=clock),
    )


def test_scan_endpoint_shares_redis_counts(test_db, monkeypatch):
    # Both anon windows backed by one fakeredis: the 11th scan is 429.
    server = _fake_client()
    monkeypatch.setattr(
        throttle, "anon_minute_limiter", _failover(server, None, 10, 60, "m")
    )
    monkeypatch.setattr(
        throttle,
        "anon_daily_limiter",
        _failover(server, None, 100, 24 * 60 * 60, "d"),
    )
    anon = TestClient(app)
    for _ in range(10):
        r = anon.post("/api/scan", json={"type": "message", "input": "Hi, dinner at 8?"})
        assert r.status_code == 200, r.text
    r = anon.post("/api/scan", json={"type": "message", "input": "Hi, dinner at 8?"})
    assert r.status_code == 429
    assert "retry-after" in {k.lower() for k in r.headers}


def test_scan_endpoint_falls_back_without_500(test_db, monkeypatch):
    # Dead Redis must not break scans: in-memory takes over, still 200s.
    monkeypatch.setattr(
        throttle,
        "anon_minute_limiter",
        _failover(BrokenRedis(), None, 10, 60, "m"),
    )
    monkeypatch.setattr(
        throttle,
        "anon_daily_limiter",
        _failover(BrokenRedis(), None, 100, 24 * 60 * 60, "d"),
    )
    anon = TestClient(app)
    for _ in range(3):
        r = anon.post("/api/scan", json={"type": "message", "input": "Hi, dinner at 8?"})
        assert r.status_code == 200, r.text


def test_login_falls_back_without_500_or_503(test_db, monkeypatch):
    # Login also falls back to in-memory: still 429 after 5 failures,
    # never a 500 (crash) or 503 (lockout) during a Redis outage.
    monkeypatch.setattr(
        routes_auth,
        "login_limiter",
        _failover(BrokenRedis(), None, 5, 15 * 60, "login"),
    )
    anon = TestClient(app)
    for _ in range(5):
        r = anon.post(
            "/api/auth/login",
            json={"email": "nobody@example.com", "password": "wrongpassword1"},
        )
        assert r.status_code == 401, r.text
    r = anon.post(
        "/api/auth/login",
        json={"email": "nobody@example.com", "password": "wrongpassword1"},
    )
    assert r.status_code == 429
