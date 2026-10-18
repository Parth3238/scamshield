"""Attack-style regression tests: hostile input must be handled safely.

Every case asserts the app stays up, stores hostile text literally (never
executes it), and never leaks internals. No real internet: fetches use a mock
transport or fail closed with the standard fetch note.
"""

from __future__ import annotations

import httpx
import pytest
from fastapi.testclient import TestClient

from app.api.routes_scan import get_fetch_function
from app.core.database import get_db
from app.main import app
from app.models.db_models import Report, Scan
from app.services.safe_fetch import FetchResult, safe_fetch


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

SQLI = "' OR '1'='1' --"


def test_sqli_in_scan_input_stored_as_plain_text(test_db):
    TestingSession = test_db
    client = TestClient(app, raise_server_exceptions=False)
    text = f"Your account is blocked {SQLI}"
    r = client.post("/api/scan", json={"type": "message", "input": text})
    assert r.status_code == 200
    db = TestingSession()
    try:
        row = db.query(Scan).order_by(Scan.created_at.desc()).first()
        assert row is not None
        assert SQLI in row.raw_input  # literal text, not executed
        assert "Traceback" not in r.text
    finally:
        db.close()


def test_sqli_in_report_content_stored_as_plain_text(test_db):
    TestingSession = test_db
    client = TestClient(app, raise_server_exceptions=False)
    content = f"Fake bank call asking for OTP {SQLI} please check this now"
    r = client.post(
        "/api/reports", json={"scam_type": "other", "content": content}
    )
    assert r.status_code == 200
    report_id = r.json()["report_id"]
    db = TestingSession()
    try:
        row = db.get(Report, report_id)
        assert row is not None
        assert SQLI in row.content
    finally:
        db.close()


def test_sqli_in_search_query_is_safe(test_db):
    client = TestClient(app, raise_server_exceptions=False)
    r = client.get("/api/campaigns/search", params={"q": "' OR '1'='1"})
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_extremely_long_input_rejected(test_db):
    client = TestClient(app, raise_server_exceptions=False)
    r = client.post("/api/scan", json={"type": "url", "input": "x" * 5000})
    assert r.status_code in (413, 422)
    assert "x" * 100 not in r.text


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/\x00evil",
        "https://exam\x00ple.com/",
        "https://\u2024example\u2024com/",
        "https://example.com/\r\nX-Injected: 1",
        "https://example.com/%0d%0aX-Injected",
        "https://example.com/%00",
    ],
)
def test_tricky_urls_never_500(test_db, url):
    client = TestClient(app, raise_server_exceptions=False)
    r = client.post("/api/scan", json={"type": "url", "input": url})
    assert r.status_code in (200, 422)
    assert "Traceback" not in r.text
    assert "x-injected" not in {k.lower() for k in r.headers}


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost/",
        "http://127.0.0.1/",
        "http://169.254.169.254/",
        "http://[::1]/",
    ],
)
def test_ssrf_targets_fail_closed_with_note(test_db, url):
    app.dependency_overrides[get_fetch_function] = lambda: safe_fetch
    try:
        client = TestClient(app, raise_server_exceptions=False)
        r = client.post("/api/scan", json={"type": "url", "input": url})
    finally:
        # restore is handled by fixture teardown
        pass
    assert r.status_code == 200
    body = r.json()
    assert any("could not safely open" in n for n in body["notes"])
    assert "Traceback" not in r.text


def test_ssrf_redirect_to_private_fails_closed(test_db):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            302, headers={"location": "http://127.0.0.1/"}, text="redir"
        )

    def fetching(url: str) -> FetchResult:
        return safe_fetch(
            url,
            transport=httpx.MockTransport(handler),
            resolver=lambda host: ["93.184.216.34"],
        )

    app.dependency_overrides[get_fetch_function] = lambda: fetching
    try:
        client = TestClient(app, raise_server_exceptions=False)
        r = client.post(
            "/api/scan", json={"type": "url", "input": "http://public.test/start"}
        )
    finally:
        pass
    assert r.status_code == 200
    assert any("could not safely open" in n for n in r.json()["notes"])


@pytest.mark.parametrize(
    "scan_id",
    ["abc", "null", "%2e%2e", "%00", "x" * 40],
)
def test_path_traversal_scan_id_is_404(test_db, scan_id):
    client = TestClient(app, raise_server_exceptions=False)
    r = client.get(f"/api/scan/{scan_id}")
    assert r.status_code == 404
    assert r.json() == {"detail": "Scan not found"}


@pytest.mark.parametrize(
    "scan_id",
    ["../x", "..%2F..%2Fx", "%2e%2e/x", "/etc/passwd", "..", "."],
)
def test_multisegment_scan_id_never_reaches_data(test_db, scan_id):
    client = TestClient(app, raise_server_exceptions=False)
    r = client.get(f"/api/scan/{scan_id}")
    # No route matches (404) or the wrong method set (405): the id can never
    # address stored scans either way.
    assert r.status_code in (404, 405)
