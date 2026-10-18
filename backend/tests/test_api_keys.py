"""Developer API keys, usage tracking and rate limiting. No real internet."""

from __future__ import annotations

import hashlib
import os

import pytest
from fastapi.testclient import TestClient

from app.api.routes_auth import login_limiter
from app.api.routes_reports import report_limiter
from app.api.routes_scan import get_fetch_function
from app.core.database import get_db
from app.core.security import hash_password
from app.main import app
from app.models.db_models import ApiKey, ApiUsage, User
from app.services.api_throttle import (
    clear_throttle,
    reset_throttle_clock,
    set_throttle_clock,
)
from app.services.safe_fetch import FetchResult


def _fail_fetch(url: str):
    raise AssertionError(f"fetcher must not be called: {url}")


def _ok_fetch(url: str) -> FetchResult:
    return FetchResult(
        final_url=url, status_code=200, redirect_chain=[url], body="ok"
    )


def _make_test_db():
    # In-memory SQLite by default; PostgreSQL when TEST_DATABASE_URL is
    # set (see tests/db_helper.py). Never point it at the app database.
    from tests.db_helper import make_test_engine, make_testing_session

    engine = make_test_engine()
    return engine, make_testing_session(engine)


class FakeClock:
    """Injectable clock: tests move time forward without waiting."""

    def __init__(self, start: float = 1_000_000.0):
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


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
    app.dependency_overrides[get_fetch_function] = lambda: _fail_fetch
    login_limiter.clear()
    report_limiter.clear()
    clear_throttle()
    reset_throttle_clock()
    try:
        yield TestingSession
    finally:
        app.dependency_overrides.clear()
        login_limiter.clear()
        report_limiter.clear()
        clear_throttle()
        reset_throttle_clock()
        os.environ.pop("TRUST_PROXY", None)
        engine.dispose()


def _register(client, email, password="longpassword1"):
    return client.post(
        "/api/auth/register", json={"email": email, "password": password}
    )


def _login_as(client, email, password="longpassword1"):
    r = client.post("/api/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return r.json()


def _user_client(test_db, email, password="longpassword1"):
    _TestingSession = test_db
    client = TestClient(app)
    _register(client, email, password)
    _login_as(client, email, password)
    return client


def _create_key(client, name="my app"):
    return client.post("/api/keys", json={"name": name})


def _scan_message(client, text="Hi, are we meeting for dinner at 8?", headers=None):
    return client.post(
        "/api/scan", json={"type": "message", "input": text}, headers=headers or {}
    )

# --- Key creation ---


def test_full_key_returned_once_and_never_stored(test_db):
    TestingSession = test_db
    client = _user_client(test_db, "dev@example.com")
    r = _create_key(client, "my website")
    assert r.status_code == 200, r.text
    body = r.json()
    full = body["full_key"]
    assert full.startswith("ss_live_")
    assert body["prefix"] == full[:12]
    assert body["key_prefix"] == full[:12]

    # List never returns the full key or the hash.
    lst = client.get("/api/keys")
    assert lst.status_code == 200
    items = lst.json()
    assert len(items) == 1
    assert "full_key" not in items[0]
    assert "api_key" not in items[0]
    assert "key_hash" not in items[0]
    assert items[0]["prefix"] == full[:12]
    assert items[0]["status"] == "active"
    assert items[0]["revoked"] is False

    # Database holds only the hash, never the raw key.
    db = TestingSession()
    try:
        row = db.query(ApiKey).first()
        assert row is not None
        assert row.key_hash == hashlib.sha256(full.encode()).hexdigest()
        assert row.key_prefix == full[:12]
        assert full not in (row.key_hash + row.key_prefix + row.name)
        # No column contains the raw key.
        assert row.key_hash != full
    finally:
        db.close()


def test_create_key_needs_login(test_db):
    anon = TestClient(app)
    assert anon.post("/api/keys", json={"name": "x"}).status_code == 401
    assert anon.get("/api/keys").status_code == 401


def test_key_name_validation(test_db):
    client = _user_client(test_db, "dev@example.com")
    assert client.post("/api/keys", json={"name": ""}).status_code == 422
    assert client.post("/api/keys", json={"name": "x" * 51}).status_code == 422


def test_sixth_key_gives_409(test_db):
    client = _user_client(test_db, "dev@example.com")
    for i in range(5):
        r = _create_key(client, f"app {i}")
        assert r.status_code == 200, r.text
    r = _create_key(client, "one too many")
    assert r.status_code == 409


def test_five_active_limit_ignores_revoked(test_db):
    client = _user_client(test_db, "dev@example.com")
    ids = [_create_key(client, f"app {i}").json()["id"] for i in range(5)]
    assert client.delete(f"/api/keys/{ids[0]}").status_code == 200
    assert _create_key(client, "replacement").status_code == 200

# --- Using keys ---


def test_valid_key_works_updates_last_used_and_headers(test_db):
    TestingSession = test_db
    client = _user_client(test_db, "dev@example.com")
    full = _create_key(client).json()["full_key"]

    db = TestingSession()
    try:
        row = db.query(ApiKey).first()
        assert row is not None
        assert row.last_used_at is None
    finally:
        db.close()

    anon = TestClient(app)
    r = _scan_message(anon, headers={"X-API-Key": full})
    assert r.status_code == 200, r.text
    assert r.headers.get("X-RateLimit-Limit") is not None
    assert r.headers.get("X-RateLimit-Remaining") is not None

    db = TestingSession()
    try:
        row = db.query(ApiKey).first()
        assert row is not None
        assert row.last_used_at is not None
    finally:
        db.close()


def test_valid_key_attributes_scan_to_owner(test_db):
    TestingSession = test_db
    client = _user_client(test_db, "owner@example.com")
    full = _create_key(client).json()["full_key"]
    anon = TestClient(app)
    r = _scan_message(anon, headers={"X-API-Key": full})
    assert r.status_code == 200
    from app.models.db_models import Scan

    db = TestingSession()
    try:
        owner = db.query(User).filter(User.email == "owner@example.com").one()
        scan = db.get(Scan, r.json()["scan_id"])
        assert scan is not None
        assert scan.user_id == owner.id
    finally:
        db.close()


def test_revoked_key_gives_401(test_db):
    client = _user_client(test_db, "dev@example.com")
    created = _create_key(client).json()
    assert client.delete(f"/api/keys/{created['id']}").status_code == 200
    anon = TestClient(app)
    r = _scan_message(anon, headers={"X-API-Key": created["full_key"]})
    assert r.status_code == 401
    assert r.json() == {"detail": "Invalid API key"}
    # Reports too, no fallback to anonymous.
    r = anon.post(
        "/api/reports",
        json={"scam_type": "other", "content": "Someone asked for money here please."},
        headers={"X-API-Key": created["full_key"]},
    )
    assert r.status_code == 401
    assert r.json() == {"detail": "Invalid API key"}


def test_unknown_key_gives_401(test_db):
    anon = TestClient(app)
    r = _scan_message(anon, headers={"X-API-Key": "ss_live_does-not-exist-xyz"})
    assert r.status_code == 401
    assert r.json() == {"detail": "Invalid API key"}


def test_user_cannot_see_or_revoke_other_users_key(test_db):
    alice = _user_client(test_db, "alice@example.com")
    key_id = _create_key(alice, "alice app").json()["id"]
    bob = _user_client(test_db, "bob@example.com")
    # Bob's list does not contain Alice's key.
    ids = [k["id"] for k in bob.get("/api/keys").json()]
    assert key_id not in ids
    # Bob cannot revoke or read usage for Alice's key: generic 404.
    assert bob.delete(f"/api/keys/{key_id}").status_code == 404
    assert bob.post(f"/api/keys/{key_id}/revoke").status_code == 404
    assert bob.get(f"/api/keys/{key_id}/usage").status_code == 404
    # Alice's key still works.
    full = alice.get("/api/keys").json()[0]
    assert full["id"] == key_id


def test_revoke_unknown_id_gives_404(test_db):
    client = _user_client(test_db, "dev@example.com")
    assert client.delete("/api/keys/no-such-id").status_code == 404

# --- Rate limits ---


def test_per_minute_limit_gives_429_with_retry_after(test_db):
    TestingSession = test_db
    client = _user_client(test_db, "dev@example.com")
    full = _create_key(client).json()["full_key"]
    db = TestingSession()
    try:
        row = db.query(ApiKey).first()
        assert row is not None
        row.per_minute_limit = 3
        row.daily_limit = 1000
        db.add(row)
        db.commit()
    finally:
        db.close()
    anon = TestClient(app)
    headers = {"X-API-Key": full}
    for _ in range(3):
        assert _scan_message(anon, headers=headers).status_code == 200
    r = _scan_message(anon, headers=headers)
    assert r.status_code == 429
    assert r.json() == {"detail": "Rate limit exceeded"}
    assert "retry-after" in {k.lower() for k in r.headers}


def test_daily_limit_gives_429(test_db):
    TestingSession = test_db
    client = _user_client(test_db, "dev@example.com")
    full = _create_key(client).json()["full_key"]
    db = TestingSession()
    try:
        row = db.query(ApiKey).first()
        assert row is not None
        row.per_minute_limit = 1000
        row.daily_limit = 3
        db.add(row)
        db.commit()
    finally:
        db.close()
    anon = TestClient(app)
    headers = {"X-API-Key": full}
    for _ in range(3):
        assert _scan_message(anon, headers=headers).status_code == 200
    assert _scan_message(anon, headers=headers).status_code == 429


def test_limit_resets_after_fake_clock_moves_forward(test_db):
    TestingSession = test_db
    fake = FakeClock()
    set_throttle_clock(fake)
    try:
        client = _user_client(test_db, "dev@example.com")
        full = _create_key(client).json()["full_key"]
        db = TestingSession()
        try:
            row = db.query(ApiKey).first()
            assert row is not None
            row.per_minute_limit = 2
            row.daily_limit = 1000
            db.add(row)
            db.commit()
        finally:
            db.close()
        anon = TestClient(app)
        headers = {"X-API-Key": full}
        assert _scan_message(anon, headers=headers).status_code == 200
        assert _scan_message(anon, headers=headers).status_code == 200
        assert _scan_message(anon, headers=headers).status_code == 429
        fake.advance(61)
        assert _scan_message(anon, headers=headers).status_code == 200
    finally:
        reset_throttle_clock()


def test_anonymous_ip_limit_works(test_db):
    anon = TestClient(app)
    for _ in range(10):
        r = _scan_message(anon)
        assert r.status_code == 200, r.text
        assert r.headers.get("X-RateLimit-Limit") == "100"
    r = _scan_message(anon)
    assert r.status_code == 429
    assert r.json() == {"detail": "Rate limit exceeded"}
    assert "retry-after" in {k.lower() for k in r.headers}


def test_anonymous_daily_resets_after_clock_moves(test_db):
    fake = FakeClock()
    set_throttle_clock(fake)
    try:
        anon = TestClient(app)
        for _ in range(10):
            assert _scan_message(anon).status_code == 200
        assert _scan_message(anon).status_code == 429
        fake.advance(61)
        # Minute window reset, but daily still has 10 hits: minute allows,
        # daily (100) still allows, so this succeeds.
        assert _scan_message(anon).status_code == 200
    finally:
        reset_throttle_clock()


def test_forwarded_for_ignored_by_default(test_db):
    anon = TestClient(app)
    for _ in range(10):
        assert _scan_message(anon).status_code == 200
    assert _scan_message(anon).status_code == 429
    # Spoofed header must not dodge the limit by default.
    r = anon.post(
        "/api/scan",
        json={"type": "message", "input": "Hi, are we meeting for dinner at 8?"},
        headers={"X-Forwarded-For": "9.9.9.9"},
    )
    assert r.status_code == 429


def test_forwarded_for_trusted_when_env_set(test_db, monkeypatch):
    monkeypatch.setenv("TRUST_PROXY", "true")
    anon = TestClient(app)
    for _ in range(10):
        assert _scan_message(anon).status_code == 200
    assert _scan_message(anon).status_code == 429
    # Behind a trusted proxy the header identifies a different client.
    r = anon.post(
        "/api/scan",
        json={"type": "message", "input": "Hi, are we meeting for dinner at 8?"},
        headers={"X-Forwarded-For": "9.9.9.9"},
    )
    assert r.status_code == 200, r.text

# --- Usage ---


def test_usage_endpoint_returns_correct_counts(test_db):
    client = _user_client(test_db, "dev@example.com")
    full = _create_key(client).json()["full_key"]
    key_id = client.get("/api/keys").json()[0]["id"]
    anon = TestClient(app)
    headers = {"X-API-Key": full}
    assert _scan_message(anon, headers=headers).status_code == 200
    assert _scan_message(anon, headers=headers).status_code == 200
    r = anon.post(
        "/api/reports",
        json={"scam_type": "other", "content": "Someone asked for money here please."},
        headers=headers,
    )
    assert r.status_code == 200, r.text
    # Anonymous requests must not pollute key usage.
    assert _scan_message(anon).status_code == 200

    u = client.get(f"/api/keys/{key_id}/usage")
    assert u.status_code == 200, u.text
    body = u.json()
    assert len(body["days"]) == 14
    assert body["daily_limit"] == 200
    assert body["days"][-1]["count"] == 3
    assert body["today_remaining"] == 200 - 3

    # Rows in the DB carry endpoint and status.
    db = TestingSession = test_db
    s = TestingSession()
    try:
        rows = s.query(ApiUsage).filter(ApiUsage.api_key_id == key_id).all()
        assert len(rows) == 3
        assert {x.status_code for x in rows} == {200}
        assert "POST /api/scan" in {x.endpoint for x in rows}
        assert "POST /api/reports" in {x.endpoint for x in rows}
    finally:
        s.close()


def test_key_scan_rate_limited_requests_are_logged(test_db):
    TestingSession = test_db
    client = _user_client(test_db, "dev@example.com")
    created = _create_key(client).json()
    db = TestingSession()
    try:
        row = db.query(ApiKey).first()
        assert row is not None
        row.per_minute_limit = 1
        row.daily_limit = 1000
        db.add(row)
        db.commit()
    finally:
        db.close()
    anon = TestClient(app)
    headers = {"X-API-Key": created["full_key"]}
    assert _scan_message(anon, headers=headers).status_code == 200
    assert _scan_message(anon, headers=headers).status_code == 429
    db = TestingSession()
    try:
        rows = (
            db.query(ApiUsage)
            .filter(ApiUsage.api_key_id == created["id"])
            .order_by(ApiUsage.id)
            .all()
        )
        assert [x.status_code for x in rows] == [200, 429]
    finally:
        db.close()
