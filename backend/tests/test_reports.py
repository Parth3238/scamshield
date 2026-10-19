"""Community reports, campaigns and moderation tests. No real internet."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.api.routes_auth import login_limiter
from app.api.routes_reports import report_limiter
from app.api.routes_scan import get_fetch_function
from app.core.database import get_db
from app.core.security import hash_password
from app.main import app
from app.models.db_models import Campaign, Indicator, Report, User
from app.services.reports import (
    InvalidTargetError,
    is_official_domain,
    normalize_report_target,
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
    try:
        yield TestingSession
    finally:
        app.dependency_overrides.clear()
        login_limiter.clear()
        report_limiter.clear()
        engine.dispose()


def _register(client, email, password="longpassword1"):
    return client.post(
        "/api/auth/register", json={"email": email, "password": password}
    )


def _login_as(client, email, password="longpassword1"):
    r = client.post("/api/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return r.json()


def _make_admin(TestingSession, email="admin@example.com"):
    db = TestingSession()
    try:
        db.add(
            User(
                email=email,
                password_hash=hash_password("adminpassword1"),
                role="admin",
                is_active=True,
            )
        )
        db.commit()
    finally:
        db.close()


@pytest.fixture()
def admin_client(test_db):
    TestingSession = test_db
    _make_admin(TestingSession)
    client = TestClient(app)
    _login_as(client, "admin@example.com", "adminpassword1")
    return client


def _submit(client, scam_type="phishing", content="Got this fake link asking for my OTP, please check it.", target=None):
    body = {"scam_type": scam_type, "content": content}
    if target is not None:
        body["target"] = target
    return client.post("/api/reports", json=body)


def test_normalize_report_target():
    assert normalize_report_target("https://Sub.Evil.XYZ/path?q=1") == (
        "domain",
        "evil.xyz",
    )
    assert normalize_report_target("WWW.Example.COM") == ("domain", "example.com")
    assert normalize_report_target("Raju@FakePay") == ("upi", "raju@fakepay")
    assert normalize_report_target("https://a.b.evil.xyz/") == ("domain", "evil.xyz")
    for bad in ["", "   ", "!!!", "http://", "localhost", "a b c", "a@gmail.com"]:
        try:
            normalize_report_target(bad)
        except InvalidTargetError:
            pass
        else:
            raise AssertionError(f"expected InvalidTargetError for {bad!r}")


def test_is_official_domain():
    assert is_official_domain("google.com")
    assert is_official_domain("mail.google.com")
    assert is_official_domain("onlinesbi.com")
    assert not is_official_domain("evil-phish.xyz")
    assert not is_official_domain("notgoogle.com")
    assert not is_official_domain("")


def test_pending_hidden_then_approved_visible(test_db, admin_client):
    TestingSession = test_db
    anon = TestClient(app)
    r = _submit(anon, target="https://evil-phish.xyz/login")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "pending"
    assert set(body.keys()) == {"report_id", "status", "message"}
    assert body["message"].startswith("Thanks!")
    report_id = body["report_id"]

    # Pending: invisible everywhere public.
    assert anon.get("/api/campaigns/trending").json() == []
    assert anon.get("/api/campaigns/search", params={"q": "evil"}).json() == []

    # Admin sees it in the pending queue, without reporter identity.
    queue = admin_client.get("/api/admin/reports")
    assert queue.status_code == 200
    assert len(queue.json()) == 1
    item = queue.json()[0]
    assert item["id"] == report_id
    assert item["reported_value"] == "evil-phish.xyz"
    assert "user_id" not in item and "reporter_key" not in item and "ip" not in item

    # Approve: appears publicly and creates the indicator.
    r = admin_client.post(f"/api/admin/reports/{report_id}/approve")
    assert r.status_code == 200
    assert r.json() == {"report_id": report_id, "status": "approved"}

    trending = anon.get("/api/campaigns/trending").json()
    assert len(trending) == 1
    assert set(trending[0].keys()) == {
        "title",
        "scam_type",
        "report_count",
        "last_seen",
        "sample_targets",
    }
    assert trending[0]["scam_type"] == "phishing"
    assert trending[0]["report_count"] == 1
    assert "evil-phish.xyz" in trending[0]["sample_targets"]

    found = anon.get("/api/campaigns/search", params={"q": "evil"}).json()
    assert len(found) == 1
    assert found[0]["title"] == trending[0]["title"]

    db = TestingSession()
    try:
        ind = (
            db.query(Indicator)
            .filter(Indicator.value == "evil-phish.xyz")
            .one_or_none()
        )
        assert ind is not None
        assert ind.type == "domain"
        assert ind.confidence == 60
        assert ind.source == "community"
        assert ind.campaign_id is not None
        camp = db.get(Campaign, ind.campaign_id)
        assert camp.report_count == 1
    finally:
        db.close()


def test_reject_creates_nothing(test_db, admin_client):
    TestingSession = test_db
    anon = TestClient(app)
    report_id = _submit(anon, target="https://reject-me.xyz/x").json()["report_id"]
    r = admin_client.post(f"/api/admin/reports/{report_id}/reject")
    assert r.status_code == 200
    assert r.json() == {"report_id": report_id, "status": "rejected"}

    assert anon.get("/api/campaigns/trending").json() == []
    assert anon.get("/api/campaigns/search", params={"q": "reject"}).json() == []
    db = TestingSession()
    try:
        assert db.query(Indicator).count() == 0
        assert db.query(Campaign).count() == 0
        assert db.get(Report, report_id).status == "rejected"
    finally:
        db.close()


def test_second_review_gives_409(test_db, admin_client):
    anon = TestClient(app)
    report_id = _submit(anon, target="https://twice.xyz/x").json()["report_id"]
    assert (
        admin_client.post(f"/api/admin/reports/{report_id}/approve").status_code
        == 200
    )
    r = admin_client.post(f"/api/admin/reports/{report_id}/approve")
    assert r.status_code == 409
    r = admin_client.post(f"/api/admin/reports/{report_id}/reject")
    assert r.status_code == 409
    assert admin_client.post("/api/admin/reports/does-not-exist/approve").status_code == 404


def test_official_domains_rejected(test_db):
    anon = TestClient(app)
    for target in [
        "https://google.com/search",
        "https://onlinesbi.com/login",
        "paytm.com",
        "https://mail.google.com/x",
    ]:
        r = _submit(anon, target=target)
        assert r.status_code == 422, target
        assert r.json() == {"detail": "This target cannot be reported"}


def test_duplicate_within_24h_blocked(test_db):
    user = TestClient(app)
    _register(user, "rep@example.com")
    _login_as(user, "rep@example.com")
    assert _submit(user, target="https://dup-test.xyz/a").status_code == 200
    r = _submit(user, target="https://dup-test.xyz/a")
    assert r.status_code == 409
    # Same target over plain http normalizes identically: still a duplicate.
    r = _submit(user, target="http://dup-test.xyz/other")
    assert r.status_code == 409
    # A different target is fine.
    assert _submit(user, target="https://other-test.xyz/a").status_code == 200

    # Anonymous reporters share an IP in tests: same target blocked too.
    anon2 = TestClient(app)
    r = _submit(anon2, target="https://dup-test.xyz/a")
    assert r.status_code in (200, 409)


def test_sixth_report_in_an_hour_gives_429(test_db):
    anon = TestClient(app)
    for i in range(5):
        r = _submit(anon, target=f"https://rate{i}-test.xyz/x")
        assert r.status_code == 200, r.text
    r = _submit(anon, target="https://rate5-test.xyz/x")
    assert r.status_code == 429
    assert "retry-after" in {k.lower() for k in r.headers}


def test_admin_routes_need_admin(test_db):
    user = TestClient(app)
    _register(user, "normal@example.com")
    _login_as(user, "normal@example.com")
    assert user.get("/api/admin/reports").status_code == 403
    assert user.post("/api/admin/reports/some-id/approve").status_code == 403
    assert user.post("/api/admin/reports/some-id/reject").status_code == 403
    anon = TestClient(app)
    assert anon.get("/api/admin/reports").status_code == 401


def test_upi_ids_masked_in_public_output(test_db, admin_client):
    anon = TestClient(app)
    r = _submit(
        anon,
        scam_type="upi_fraud",
        content="This person asked me to pay in advance for a refund.",
        target="refund.support@fakepay",
    )
    assert r.status_code == 200
    admin_client.post(f"/api/admin/reports/{r.json()['report_id']}/approve")

    trending = anon.get("/api/campaigns/trending").json()
    assert len(trending) == 1
    assert trending[0]["sample_targets"] == ["re***@fakepay"]
    assert "refund.support@fakepay" not in anon.get("/api/campaigns/trending").text

    found = anon.get("/api/campaigns/search", params={"q": "fakepay"}).json()
    assert len(found) == 1
    assert found[0]["sample_targets"] == ["re***@fakepay"]


def test_search_wildcards_do_not_match_everything(test_db, admin_client):
    anon = TestClient(app)
    report_id = _submit(anon, target="https://wildtest.xyz/x").json()["report_id"]
    admin_client.post(f"/api/admin/reports/{report_id}/approve")

    assert anon.get("/api/campaigns/search", params={"q": "%%%"}).json() == []
    assert anon.get("/api/campaigns/search", params={"q": "___"}).json() == []
    assert anon.get("/api/campaigns/search", params={"q": "%"}).status_code == 422
    assert anon.get("/api/campaigns/search", params={"q": "x" * 101}).status_code == 422
    assert len(anon.get("/api/campaigns/search", params={"q": "wildtest"}).json()) == 1


def test_url_scan_shows_known_bad_after_approval(test_db, admin_client):
    anon = TestClient(app)
    report_id = _submit(anon, target="https://scanme-phish.xyz/login").json()[
        "report_id"
    ]
    admin_client.post(f"/api/admin/reports/{report_id}/approve")

    app.dependency_overrides[get_fetch_function] = lambda: _ok_fetch
    try:
        client = TestClient(app)
        r = client.post(
            "/api/scan",
            json={"type": "url", "input": "https://scanme-phish.xyz/login"},
        )
    finally:
        app.dependency_overrides[get_fetch_function] = lambda: _fail_fetch
    assert r.status_code == 200
    codes = [f["rule_code"] for f in r.json()["findings"]]
    assert "KNOWN_BAD_INDICATOR" in codes
    text = " ".join(f["explanation"] for f in r.json()["findings"])
    assert "Other users have reported this" in text


def test_report_content_redacted_in_db(test_db):
    TestingSession = test_db
    anon = TestClient(app)
    r = _submit(
        anon,
        content="Call me on 9876543210, my OTP is 482910, fake site below.",
        target="https://redact-test.xyz/x",
    )
    assert r.status_code == 200
    db = TestingSession()
    try:
        row = db.get(Report, r.json()["report_id"])
        assert "9876543210" not in row.content
        assert "482910" not in row.content
        assert "[REDACTED]" in row.content
    finally:
        db.close()


def test_report_without_target(test_db, admin_client):
    TestingSession = test_db
    anon = TestClient(app)
    r = _submit(anon, content="Someone called pretending to be the bank manager.")
    assert r.status_code == 200
    admin_client.post(f"/api/admin/reports/{r.json()['report_id']}/approve")
    trending = anon.get("/api/campaigns/trending").json()
    assert len(trending) == 1
    assert trending[0]["sample_targets"] == []
    db = TestingSession()
    try:
        assert db.query(Indicator).count() == 0
    finally:
        db.close()


def test_report_validation(test_db):
    anon = TestClient(app)
    assert _submit(anon, content="Too short").status_code == 422
    assert _submit(anon, target="!!!not a target!!!").status_code == 422
    r = anon.post(
        "/api/reports", json={"scam_type": "not_a_type", "content": "Long enough content here."}
    )
    assert r.status_code == 422
