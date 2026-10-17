"""Endpoint tests for type=upi and message-with-UPI scans. No real internet."""

from __future__ import annotations

import hashlib

import pytest
from fastapi.testclient import TestClient

from app.api.routes_scan import UPI_NOTE, get_fetch_function
from app.core.database import get_db
from app.main import app
from app.models.db_models import Scan


def _fail_fetch(url: str):  # must never be called for upi/messages
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
    try:
        yield TestingSession
    finally:
        app.dependency_overrides.clear()
        engine.dispose()


def test_upi_scan_masks_and_hashes(test_db):
    TestingSession = test_db
    client = TestClient(app)
    r = client.post("/api/scan", json={"type": "upi", "input": "Rahul@OKSBI"})
    assert r.status_code == 200
    body = r.json()
    assert body["type"] == "upi"
    assert UPI_NOTE in body["notes"]
    assert body["redirect_chain"] == []

    db = TestingSession()
    try:
        row = db.get(Scan, body["scan_id"])
        assert row is not None
        # Masked: first 2 chars + ***@handle.
        assert row.raw_input == "ra***@oksbi"
        assert "rahul@oksbi" not in row.raw_input
        expected = hashlib.sha256("rahul@oksbi".encode("utf-8")).hexdigest()
        assert row.input_hash == expected
    finally:
        db.close()


def test_upi_scan_safe_for_normal_id(test_db):
    client = TestClient(app)
    r = client.post("/api/scan", json={"type": "upi", "input": "9876543210@ybl"})
    assert r.status_code == 200
    body = r.json()
    assert body["findings"] == []
    assert body["verdict"] == "safe"


def test_message_with_upi_yields_upi_findings(test_db):
    client = TestClient(app)
    r = client.post(
        "/api/scan",
        json={"type": "message", "input": "send money to sbi.refund.support@ybl please"},
    )
    assert r.status_code == 200
    body = r.json()
    codes = [f["rule_code"] for f in body["findings"]]
    assert "BRAND_IN_UPI_NAME" in codes or "SUPPORT_WORD_IN_UPI" in codes


def test_message_with_email_has_no_upi_findings(test_db):
    client = TestClient(app)
    r = client.post(
        "/api/scan",
        json={"type": "message", "input": "mail me at name@gmail.com please"},
    )
    assert r.status_code == 200
    body = r.json()
    codes = [f["rule_code"] for f in body["findings"]]
    assert "BRAND_IN_UPI_NAME" not in codes
    assert "SUPPORT_WORD_IN_UPI" not in codes
    assert "UNKNOWN_UPI_HANDLE" not in codes
    assert "INVALID_UPI_FORMAT" not in codes
