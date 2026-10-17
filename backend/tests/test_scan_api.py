from fastapi.testclient import TestClient

from app.api.routes_scan import get_fetch_function
from app.main import app
from app.services.safe_fetch import BlockedURLError, FetchResult

client = TestClient(app)


def _ok_fetch(url: str) -> FetchResult:
    return FetchResult(
        final_url=url, status_code=200, redirect_chain=[url], body="ok"
    )


def test_normal_url_returns_safe():
    app.dependency_overrides[get_fetch_function] = lambda: _ok_fetch
    try:
        r = client.post(
            "/api/scan", json={"type": "url", "input": "https://www.google.com/search"}
        )
    finally:
        app.dependency_overrides.clear()
    assert r.status_code == 200
    body = r.json()
    assert body["verdict"] == "safe"
    assert body["risk_score"] <= 30


def test_scam_url_suspicious_or_dangerous():
    app.dependency_overrides[get_fetch_function] = lambda: _ok_fetch
    try:
        r = client.post(
            "/api/scan",
            json={"type": "url", "input": "https://paytm.secure-login-verify.xyz/kyc"},
        )
    finally:
        app.dependency_overrides.clear()
    assert r.status_code == 200
    body = r.json()
    assert body["verdict"] in ("suspicious", "dangerous")
    assert len(body["findings"]) >= 3


def test_blocked_fetch_still_200_with_note():
    def _blocked(url: str):
        raise BlockedURLError("blocked")

    app.dependency_overrides[get_fetch_function] = lambda: _blocked
    try:
        r = client.post(
            "/api/scan", json={"type": "url", "input": "http://127.0.0.1/"}
        )
    finally:
        app.dependency_overrides.clear()
    assert r.status_code == 200
    body = r.json()
    assert len(body["notes"]) >= 1
    # Raw exception text must not leak.
    assert "blocked" not in " ".join(body["notes"]).lower()


def test_empty_input_422():
    r = client.post("/api/scan", json={"type": "url", "input": ""})
    assert r.status_code == 422
    assert '""' not in r.text or "input" not in r.text.lower().replace(" ", "")


def test_long_input_422():
    long_url = "https://example.com/" + "a" * 3000
    r = client.post("/api/scan", json={"type": "url", "input": long_url})
    assert r.status_code == 422
    assert "a" * 100 not in r.text  # raw input must not echo


def test_wrong_type_422():
    r = client.post("/api/scan", json={"type": "email", "input": "hello"})
    assert r.status_code == 422


def test_input_without_scheme_works():
    app.dependency_overrides[get_fetch_function] = lambda: _ok_fetch
    try:
        r = client.post("/api/scan", json={"type": "url", "input": "example.com"})
    finally:
        app.dependency_overrides.clear()
    assert r.status_code == 200
    body = r.json()
    assert body["redirect_chain"][0].startswith("https://")
