"""Auth endpoint tests: register, login, cookies, limits, history privacy."""

from __future__ import annotations

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app.api.deps import require_admin
from app.api.routes_auth import REGISTER_MSG, login_limiter
from app.api.routes_scan import get_fetch_function
from app.core.database import get_db
from app.core.rate_limit import RateLimiter
from app.core.security import create_access_token, hash_password
from app.main import app
from app.models.db_models import User

LOGIN_FAILED = {"detail": "Invalid email or password"}


def _fail_fetch(url: str):
    raise AssertionError(f"fetcher must not be called: {url}")


def _make_test_db():
    # In-memory SQLite by default; PostgreSQL when TEST_DATABASE_URL is
    # set (see tests/db_helper.py). Never point it at the app database.
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
    app.dependency_overrides[get_fetch_function] = lambda: _fail_fetch
    login_limiter.clear()
    try:
        yield TestingSession
    finally:
        app.dependency_overrides.clear()
        login_limiter.clear()
        engine.dispose()


def _register(client, email, password="longpassword1"):
    return client.post(
        "/api/auth/register", json={"email": email, "password": password}
    )


def _login(client, email, password="longpassword1"):
    return client.post("/api/auth/login", json={"email": email, "password": password})


def _login_as(client, email, password="longpassword1"):
    r = _login(client, email, password)
    assert r.status_code == 200, r.text
    return r.json()


def test_register_then_login_then_me(test_db):
    client = TestClient(app)
    assert client.get("/api/auth/me").status_code == 401
    r = _register(client, "user1@example.com")
    assert r.status_code == 200
    assert r.json() == {"message": REGISTER_MSG}
    body = _login_as(client, "user1@example.com")
    assert body["email"] == "user1@example.com"
    assert body["role"] == "user"
    assert "access_token" in client.cookies
    me = client.get("/api/auth/me")
    assert me.status_code == 200
    assert me.json() == body


def test_wrong_password_and_unknown_email_identical_401(test_db):
    client = TestClient(app)
    _register(client, "user2@example.com")
    r1 = _login(client, "user2@example.com", "wrongpassword1")
    r2 = _login(client, "nobody@example.com", "wrongpassword1")
    assert r1.status_code == r2.status_code == 401
    assert r1.json() == r2.json() == LOGIN_FAILED


def test_duplicate_registration_same_generic_response(test_db):
    TestingSession = test_db
    client = TestClient(app)
    first = _register(client, "dupe@example.com")
    second = _register(client, "dupe@example.com")
    assert first.status_code == second.status_code == 200
    assert first.json() == second.json() == {"message": REGISTER_MSG}
    db = TestingSession()
    try:
        count = db.query(User).filter(User.email == "dupe@example.com").count()
        assert count == 1
    finally:
        db.close()


def test_short_password_gives_422(test_db):
    client = TestClient(app)
    r = _register(client, "short@example.com", "short123")
    assert r.status_code == 422


def test_register_never_creates_admin(test_db):
    client = TestClient(app)
    r = client.post(
        "/api/auth/register",
        json={
            "email": "wannabe@example.com",
            "password": "longpassword1",
            "role": "admin",
        },
    )
    assert r.status_code == 200
    body = _login_as(client, "wannabe@example.com")
    assert body["role"] == "user"


def test_email_stored_lowercase(test_db):
    client = TestClient(app)
    _register(client, "MixedCase@Example.COM")
    body = _login_as(client, "mixedcase@example.com")
    assert body["email"] == "mixedcase@example.com"


def test_tampered_token_rejected(test_db):
    client = TestClient(app)
    _register(client, "tamp@example.com")
    _login_as(client, "tamp@example.com")
    token = client.cookies["access_token"]
    client.cookies.set("access_token", token + "tampered")
    assert client.get("/api/auth/me").status_code == 401
    fresh = TestClient(app)
    fresh.cookies.set("access_token", "not-a-token")
    assert fresh.get("/api/auth/me").status_code == 401


def test_expired_token_rejected(test_db):
    client = TestClient(app)
    _register(client, "old@example.com")
    body = _login_as(client, "old@example.com")
    expired = create_access_token(body["id"], minutes=-1)
    fresh = TestClient(app)
    fresh.cookies.set("access_token", expired)
    assert fresh.get("/api/auth/me").status_code == 401


def test_logout_clears_cookie(test_db):
    client = TestClient(app)
    _register(client, "bye@example.com")
    _login_as(client, "bye@example.com")
    assert client.get("/api/auth/me").status_code == 200
    r = client.post("/api/auth/logout")
    assert r.status_code == 200
    assert client.get("/api/auth/me").status_code == 401


def test_sixth_failed_login_gives_429(test_db):
    client = TestClient(app)
    _register(client, "locked@example.com")
    for _ in range(5):
        r = _login(client, "locked@example.com", "wrongpassword1")
        assert r.status_code == 401
    r = _login(client, "locked@example.com", "wrongpassword1")
    assert r.status_code == 429
    assert "retry-after" in {k.lower() for k in r.headers}


def test_rate_limiter_window_with_fake_clock():
    now = [1000.0]
    limiter = RateLimiter(
        max_attempts=2, window_seconds=60, clock=lambda: now[0]
    )
    limiter.record_failure("k")
    limiter.record_failure("k")
    blocked, retry = limiter.is_blocked("k")
    assert blocked and retry > 0
    now[0] += 61  # move past the window: no real waiting needed
    blocked, _ = limiter.is_blocked("k")
    assert not blocked
    limiter.record_failure("k")
    limiter.reset("k")
    blocked, _ = limiter.is_blocked("k")
    assert not blocked


def _scan(client, text):
    r = client.post("/api/scan", json={"type": "message", "input": text})
    assert r.status_code == 200, r.text
    return r.json()["scan_id"]


def test_user_sees_only_own_history(test_db):
    alice = TestClient(app)
    bob = TestClient(app)
    _register(alice, "alice@example.com")
    _register(bob, "bob@example.com")
    _login_as(alice, "alice@example.com")
    _login_as(bob, "bob@example.com")
    a1 = _scan(alice, "Alice dinner at 8?")
    a2 = _scan(alice, "Alice meeting at 3pm tomorrow.")
    _scan(bob, "Bob dinner at 9?")

    r = alice.get("/api/scans")
    assert r.status_code == 200
    ids = [row["id"] for row in r.json()]
    assert set(ids) == {a1, a2}
    # Newest first.
    assert ids[0] == a2
    for row in r.json():
        assert set(row.keys()) == {
            "id",
            "type",
            "risk_score",
            "verdict",
            "created_at",
        }

    r = bob.get("/api/scans")
    assert r.status_code == 200
    assert len(r.json()) == 1

    # Pagination: limit 1 gives the newest only.
    r = alice.get("/api/scans", params={"limit": 1})
    assert [row["id"] for row in r.json()] == [a2]
    # Too-large limit is rejected.
    assert alice.get("/api/scans", params={"limit": 51}).status_code == 422


def test_user_cannot_read_other_users_scan(test_db):
    alice = TestClient(app)
    bob = TestClient(app)
    _register(alice, "a2@example.com")
    _register(bob, "b2@example.com")
    _login_as(alice, "a2@example.com")
    _login_as(bob, "b2@example.com")
    scan_id = _scan(alice, "Alice private note here.")

    assert alice.get(f"/api/scan/{scan_id}").status_code == 200
    r = bob.get(f"/api/scan/{scan_id}")
    assert r.status_code == 404
    assert r.json() == {"detail": "Scan not found"}
    anon = TestClient(app)
    assert anon.get(f"/api/scan/{scan_id}").status_code == 404


def test_anonymous_scans_still_work(test_db):
    client = TestClient(app)
    scan_id = _scan(client, "Hi, dinner at 8?")
    r = client.get(f"/api/scan/{scan_id}")
    assert r.status_code == 200
    assert r.json()["scan_id"] == scan_id
    # History needs a login.
    assert client.get("/api/scans").status_code == 401


def test_require_admin_forbids_normal_user(test_db):
    TestingSession = test_db

    probe = FastAPI()

    @probe.get("/admin-only")
    def _admin_only(user: User = Depends(require_admin)):
        return {"ok": True, "email": user.email}

    def _override():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    probe.dependency_overrides[get_db] = _override

    client = TestClient(app)
    _register(client, "normal@example.com")
    _login_as(client, "normal@example.com")
    token = client.cookies["access_token"]

    db = TestingSession()
    try:
        db.add(
            User(
                email="boss@example.com",
                password_hash=hash_password("adminpassword1"),
                role="admin",
                is_active=True,
            )
        )
        db.commit()
    finally:
        db.close()
    admin_client = TestClient(app)
    _login_as(admin_client, "boss@example.com", "adminpassword1")
    admin_token = admin_client.cookies["access_token"]

    user_probe = TestClient(probe)
    user_probe.cookies.set("access_token", token)
    r = user_probe.get("/admin-only")
    assert r.status_code == 403

    admin_probe = TestClient(probe)
    admin_probe.cookies.set("access_token", admin_token)
    r = admin_probe.get("/admin-only")
    assert r.status_code == 200
    assert r.json() == {"ok": True, "email": "boss@example.com"}

    anon_probe = TestClient(probe)
    assert anon_probe.get("/admin-only").status_code == 401
