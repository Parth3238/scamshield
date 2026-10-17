"""Endpoint tests for POST /api/scan/qr. QR images made in memory, no internet."""

from __future__ import annotations

import io

import pytest
import qrcode
from fastapi.testclient import TestClient
from PIL import Image

from app.api.routes_scan import QR_PAY_NOTE, get_fetch_function
from app.core.database import get_db
from app.main import app
from app.models.db_models import Scan
from app.services.safe_fetch import FetchResult
from app.services.upi_qr_parser import parse_upi_uri

NORMAL_UPI = "upi://pay?pa=rahul.sharma@okaxis&pn=Rahul%20Sharma&cu=INR"
SCAMMY_UPI = (
    "upi://pay?pa=sbi.refund.support@ybl&pn=SBI%20Refund%20Team"
    "&am=1&tn=refund%20claim&cu=INR"
)
HARMLESS_URL = "https://example.com"


def _qr_bytes(payload: str) -> bytes:
    img = qrcode.make(payload)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _plain_png_bytes() -> bytes:
    img = Image.new("RGB", (200, 200), (255, 255, 255))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


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


def _post_qr(png: bytes, name: str = "qr.png", ctype: str = "image/png"):
    client = TestClient(app)
    return client.post(
        "/api/scan/qr", files={"file": (name, png, ctype)}
    )


def test_parse_upi_uri_extracts_fields():
    parsed = parse_upi_uri(SCAMMY_UPI)
    assert parsed["pa"] == "sbi.refund.support@ybl"
    assert parsed["pn"] == "SBI Refund Team"
    assert parsed["am"] == "1"
    assert parsed["tn"] == "refund claim"
    assert parsed["cu"] == "INR"


def test_parse_upi_uri_ignores_unknown_params():
    parsed = parse_upi_uri(NORMAL_UPI + "&tr=ABC123&foo=bar")
    assert parsed["pa"] == "rahul.sharma@okaxis"
    assert parsed["pn"] == "Rahul Sharma"


def test_normal_upi_qr_is_safe_with_pay_note(test_db):
    r = _post_qr(_qr_bytes(NORMAL_UPI))
    assert r.status_code == 200
    body = r.json()
    assert body["type"] == "qr"
    assert body["verdict"] == "safe"
    assert body["risk_score"] <= 30
    assert QR_PAY_NOTE in body["notes"]


def test_scammy_upi_qr_is_suspicious_or_dangerous(test_db):
    r = _post_qr(_qr_bytes(SCAMMY_UPI))
    assert r.status_code == 200
    body = r.json()
    assert body["verdict"] in ("suspicious", "dangerous")
    codes = [f["rule_code"] for f in body["findings"]]
    assert "QR_PAYEE_NAME_MISMATCH" in codes
    assert "QR_PREFILLED_AMOUNT" in codes
    assert "QR_NOTE_SCAM_WORDS" in codes
    assert QR_PAY_NOTE in body["notes"]


def test_url_qr_goes_through_url_flow(test_db):
    calls: list[str] = []

    def _recording_fetch(url: str) -> FetchResult:
        calls.append(url)
        return FetchResult(
            final_url=url, status_code=200, redirect_chain=[url], body="ok"
        )

    app.dependency_overrides[get_fetch_function] = lambda: _recording_fetch
    try:
        r = _post_qr(_qr_bytes(HARMLESS_URL))
    finally:
        # restore is handled by fixture teardown, but keep calls recorded
        pass
    assert r.status_code == 200
    body = r.json()
    assert body["type"] == "qr"
    assert body["verdict"] == "safe"
    assert body["redirect_chain"] == [HARMLESS_URL]
    assert calls == [HARMLESS_URL]


def test_plain_image_without_qr_returns_422(test_db):
    r = _post_qr(_plain_png_bytes())
    assert r.status_code == 422
    assert r.json() == {"detail": "No QR code found in this image"}


def test_text_file_renamed_to_png_returns_400(test_db):
    r = _post_qr(b"hello, this is plain text, not an image", "evil.png")
    assert r.status_code == 400
    assert r.json() == {"detail": "This file is not a valid image"}


def test_file_bigger_than_5mb_returns_413(test_db):
    big = b"x" * (5 * 1024 * 1024 + 1)
    r = _post_qr(big, "big.png")
    assert r.status_code == 413
    assert r.json() == {"detail": "The image is too large (max 5 MB)"}


def test_db_row_masks_upi_id(test_db):
    TestingSession = test_db
    r = _post_qr(_qr_bytes(SCAMMY_UPI))
    assert r.status_code == 200
    scan_id = r.json()["scan_id"]

    db = TestingSession()
    try:
        row = db.get(Scan, scan_id)
        assert row is not None
        assert row.input_type == "qr"
        assert "sbi.refund.support@ybl" not in row.raw_input
        assert "sb***@ybl" in row.raw_input
    finally:
        db.close()
