"""Persistence tests: scans saved to SQLite and re-fetched via GET."""

from __future__ import annotations

import hashlib
import uuid

import pytest
from fastapi.testclient import TestClient

from app.api.routes_scan import SAVE_ERROR_NOTE, get_fetch_function
from app.core.database import get_db
from app.main import app
from app.models.db_models import Scan
from app.services.safe_fetch import FetchResult


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
    app.dependency_overrides[get_fetch_function] = lambda: _ok_fetch
    try:
        yield TestingSession
    finally:
        app.dependency_overrides.clear()
        engine.dispose()


def _expected_hash(raw: str) -> str:
    return hashlib.sha256(raw.strip().lower().encode("utf-8")).hexdigest()


def test_scan_saved_and_fetchable(test_db):
    TestingSession = test_db
    client = TestClient(app)
    r = client.post(
        "/api/scan",
        json={"type": "url", "input": "https://www.google.com/search"},
    )
    assert r.status_code == 200
    body = r.json()
    scan_id = body["scan_id"]
    # Must be a valid uuid since we use the saved Scan id.
    uuid.UUID(scan_id)

    g = client.get(f"/api/scan/{scan_id}")
    assert g.status_code == 200
    fetched = g.json()
    assert fetched == body


def test_findings_saved_in_right_order(test_db):
    client = TestClient(app)
    r = client.post(
        "/api/scan",
        json={"type": "url", "input": "https://paytm.secure-login-verify.xyz/kyc"},
    )
    assert r.status_code == 200
    posted = r.json()
    assert len(posted["findings"]) >= 3

    g = client.get(f"/api/scan/{posted['scan_id']}")
    assert g.status_code == 200
    fetched = g.json()
    assert [f["rule_code"] for f in fetched["findings"]] == [
        f["rule_code"] for f in posted["findings"]
    ]
    severities = [f["severity"] for f in fetched["findings"]]
    assert severities == sorted(severities, reverse=True)


def test_same_input_twice_creates_two_rows_with_same_hash(test_db):
    TestingSession = test_db
    client = TestClient(app)
    raw = "https://www.google.com/search"
    r1 = client.post("/api/scan", json={"type": "url", "input": raw})
    r2 = client.post("/api/scan", json={"type": "url", "input": raw})
    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r1.json()["scan_id"] != r2.json()["scan_id"]

    expected = _expected_hash(raw)
    db = TestingSession()
    try:
        rows = db.query(Scan).filter(Scan.input_hash == expected).all()
    finally:
        db.close()
    assert len(rows) == 2
    assert {row.id for row in rows} == {
        r1.json()["scan_id"],
        r2.json()["scan_id"],
    }
    assert all(row.input_hash == expected for row in rows)


def test_unknown_id_gives_404(test_db):
    client = TestClient(app)
    r = client.get(f"/api/scan/{uuid.uuid4()}")
    assert r.status_code == 404
    assert r.json() == {"detail": "Scan not found"}


def test_invalid_id_gives_same_404(test_db):
    client = TestClient(app)
    r = client.get("/api/scan/abc")
    assert r.status_code == 404
    assert r.json() == {"detail": "Scan not found"}


def test_db_failure_still_returns_200_with_note():
    def _broken_db():
        class _Broken:
            def add(self, *args, **kwargs):
                raise RuntimeError("db down")

            def commit(self):
                raise RuntimeError("db down")

            def rollback(self):
                pass

            def close(self):
                pass

        yield _Broken()

    app.dependency_overrides[get_db] = _broken_db
    app.dependency_overrides[get_fetch_function] = lambda: _ok_fetch
    try:
        client = TestClient(app)
        r = client.post(
            "/api/scan", json={"type": "url", "input": "https://example.com/"}
        )
    finally:
        app.dependency_overrides.clear()
    assert r.status_code == 200
    body = r.json()
    assert SAVE_ERROR_NOTE in body["notes"]
    # Database error text must never leak.
    assert "db down" not in r.text.lower()
