"""Endpoint tests for type=message scans. No real internet."""

from __future__ import annotations

import hashlib

import pytest
from fastapi.testclient import TestClient

from app.api.routes_scan import MESSAGE_LINKS_NOTE
from app.core.database import get_db
from app.main import app
from app.models.db_models import Scan


def _fail_fetch(url: str):  # must never be called for messages
    raise AssertionError(f"fetcher must not be called for messages: {url}")


def _make_test_db():
    # In-memory SQLite by default; PostgreSQL when TEST_DATABASE_URL is
    # set (see tests/db_helper.py). Never point it at the app database.
    from tests.db_helper import make_test_engine, make_testing_session

    engine = make_test_engine()
    return engine, make_testing_session(engine)


@pytest.fixture()
def test_db():
    from app.api.routes_scan import get_fetch_function

    engine, TestingSession = _make_test_db()

    def _override():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = _override
    app.dependency_overrides[get_fetch_function] = lambda: _fail_fetch
    try:
        yield TestingSession
    finally:
        app.dependency_overrides.clear()
        engine.dispose()


def test_message_scan_works_with_links_note_and_empty_chain(test_db):
    client = TestClient(app)
    r = client.post(
        "/api/scan",
        json={
            "type": "message",
            "input": "Your SBI account will be blocked today. Update KYC immediately: http://sbi-kyc-update.xyz",
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["type"] == "message"
    assert body["verdict"] in ("suspicious", "dangerous")
    assert len(body["findings"]) >= 3
    assert body["redirect_chain"] == []
    assert MESSAGE_LINKS_NOTE in body["notes"]

    # Fetched from DB: same shape.
    g = client.get(f"/api/scan/{body['scan_id']}")
    assert g.status_code == 200
    assert g.json() == body


def test_harmless_message_has_no_links_note(test_db):
    client = TestClient(app)
    r = client.post(
        "/api/scan",
        json={"type": "message", "input": "Hi, are we meeting for dinner at 8?"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["findings"] == []
    assert body["redirect_chain"] == []
    assert MESSAGE_LINKS_NOTE not in body["notes"]


def test_message_is_redacted_before_saving(test_db):
    TestingSession = test_db
    client = TestClient(app)
    original = "My OTP is 482910 call me at 9811045678 please"
    r = client.post("/api/scan", json={"type": "message", "input": original})
    assert r.status_code == 200
    scan_id = r.json()["scan_id"]

    db = TestingSession()
    try:
        row = db.get(Scan, scan_id)
        assert row is not None
        assert "[REDACTED]" in row.raw_input
        assert "482910" not in row.raw_input
        assert "9811045678" not in row.raw_input
        expected_hash = hashlib.sha256(
            row.raw_input.strip().lower().encode("utf-8")
        ).hexdigest()
        assert row.input_hash == expected_hash
    finally:
        db.close()


def test_message_upi_id_redacted_in_db(test_db):
    TestingSession = test_db
    client = TestClient(app)
    r = client.post(
        "/api/scan",
        json={"type": "message", "input": "Pay to ram@okhdfc now, OTP 123456"},
    )
    assert r.status_code == 200
    db = TestingSession()
    try:
        row = db.get(Scan, r.json()["scan_id"])
        assert row is not None
        assert "ram@okhdfc" not in row.raw_input
        assert "123456" not in row.raw_input
        assert "[REDACTED]" in row.raw_input
    finally:
        db.close()
