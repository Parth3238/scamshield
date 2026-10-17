"""Domain age (RDAP) tests: lookup, cache, analyzer rules, endpoints.

No real internet: RDAP uses httpx.MockTransport, age lookups use dependency
overrides, and cache expiry uses explicit fake datetimes.
"""

from __future__ import annotations

import datetime

import httpx
import pytest
from fastapi.testclient import TestClient

from app.api.routes_scan import get_age_lookup, get_fetch_function
from app.core.database import get_db
from app.main import app
from app.models.db_models import DomainAgeCache
from app.services.domain_age import get_domain_age_cached, get_domain_age_days
from app.services.safe_fetch import FetchResult
from app.services.url_analyzer import analyze_url, check_domain_age

UTC = datetime.timezone.utc


def _now() -> datetime.datetime:
    return datetime.datetime.now(UTC)


def _rdap_transport(days_ago=None, status=200, raw=None, calls=None):
    def handler(request: httpx.Request) -> httpx.Response:
        if calls is not None:
            calls.append(str(request.url))
        assert request.url.host == "rdap.org", request.url
        if status != 200:
            return httpx.Response(status, text="nope")
        if raw is not None:
            return httpx.Response(200, content=raw)
        created = (_now() - datetime.timedelta(days=days_ago)).isoformat()
        return httpx.Response(
            200,
            json={"events": [{"eventAction": "registration", "eventDate": created}]},
        )

    return httpx.MockTransport(handler)


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

    def _ok_fetch(url: str) -> FetchResult:
        return FetchResult(
            final_url=url, status_code=200, redirect_chain=[url], body="ok"
        )

    app.dependency_overrides[get_db] = _override
    app.dependency_overrides[get_fetch_function] = lambda: _ok_fetch
    try:
        yield TestingSession
    finally:
        app.dependency_overrides.clear()
        engine.dispose()

# --- Analyzer rules (offline) ---


def test_very_new_domain_gets_domain_very_new():
    findings = analyze_url("https://example.xyz/info", age_days=12)
    codes = {f.rule_code: f for f in findings}
    assert "DOMAIN_VERY_NEW" in codes
    assert codes["DOMAIN_VERY_NEW"].severity == 30
    assert "12 days ago" in codes["DOMAIN_VERY_NEW"].explanation


def test_60_day_domain_gets_domain_new():
    findings = analyze_url("https://example.xyz/info", age_days=60)
    codes = {f.rule_code: f for f in findings}
    assert "DOMAIN_NEW" in codes
    assert codes["DOMAIN_NEW"].severity == 15
    assert "DOMAIN_VERY_NEW" not in codes


def test_five_year_domain_gets_nothing():
    assert check_domain_age(1825) is None
    assert check_domain_age(None) is None
    findings = analyze_url("https://example.xyz/info", age_days=1825)
    assert "DOMAIN_VERY_NEW" not in {f.rule_code for f in findings}
    assert "DOMAIN_NEW" not in {f.rule_code for f in findings}


def test_age_boundary_30_and_90():
    assert check_domain_age(29) is not None
    assert check_domain_age(29).rule_code == "DOMAIN_VERY_NEW"  # type: ignore[union-attr]
    assert check_domain_age(30).rule_code == "DOMAIN_NEW"  # type: ignore[union-attr]
    assert check_domain_age(89).rule_code == "DOMAIN_NEW"  # type: ignore[union-attr]
    assert check_domain_age(90) is None

# --- RDAP lookup ---


def test_rdap_returns_age_in_days():
    transport = _rdap_transport(days_ago=12)
    age = get_domain_age_days("example.xyz", transport=transport)
    assert age is not None
    assert 11 <= age <= 13


def test_malformed_domain_returns_none_without_network():
    calls: list[str] = []
    transport = _rdap_transport(days_ago=12, calls=calls)
    for bad in ["", "not a domain!", "http://evil.com/x", "a" * 300, "EVIL.COM", "a/b"]:
        assert get_domain_age_days(bad, transport=transport) is None
    assert calls == []


def test_rdap_failures_return_none_without_raising():
    assert get_domain_age_days("example.xyz", transport=_rdap_transport(status=404)) is None
    assert get_domain_age_days("example.xyz", transport=_rdap_transport(raw=b"not json")) is None
    assert (
        get_domain_age_days(
            "example.xyz",
            transport=_rdap_transport(raw=b'{"events": []}'),
        )
        is None
    )
    assert (
        get_domain_age_days(
            "example.xyz",
            transport=_rdap_transport(raw=b'{"events": [{"eventAction": "registration"}]}'),
        )
        is None
    )

    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down", request=request)

    assert get_domain_age_days("example.xyz", transport=httpx.MockTransport(boom)) is None


def test_rdap_follows_at_most_two_https_redirects():
    hops = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        hops["n"] += 1
        if hops["n"] <= 2:
            return httpx.Response(
                302, headers={"location": "https://rdap.org/domain/example.xyz"}
            )
        created = (_now() - datetime.timedelta(days=12)).isoformat()
        return httpx.Response(
            200,
            json={"events": [{"eventAction": "registration", "eventDate": created}]},
        )

    age = get_domain_age_days("example.xyz", transport=httpx.MockTransport(handler))
    assert age is not None and 11 <= age <= 13
    assert hops["n"] == 3


def test_rdap_redirect_to_http_is_rejected():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "http://rdap.org/domain/x"})

    assert (
        get_domain_age_days("example.xyz", transport=httpx.MockTransport(handler))
        is None
    )


def test_rdap_oversize_body_returns_none():
    big = b"x" * (200 * 1024 + 16)
    assert (
        get_domain_age_days("example.xyz", transport=_rdap_transport(raw=big)) is None
    )

# --- Cache ---


def test_cache_hit_avoids_second_call(test_db):
    TestingSession = test_db
    calls: list[str] = []
    transport = _rdap_transport(days_ago=12, calls=calls)
    db = TestingSession()
    try:
        first = get_domain_age_cached(db, "example.xyz", transport=transport)
        second = get_domain_age_cached(db, "example.xyz", transport=transport)
    finally:
        db.close()
    assert first is not None and second is not None
    assert abs(first - 12) <= 1 and abs(second - 12) <= 1
    assert len(calls) == 1


def test_cache_expiry_with_fake_clock(test_db):
    TestingSession = test_db
    base = _now()
    db = TestingSession()
    try:
        # Fresh success: no network.
        db.add(
            DomainAgeCache(
                domain="fresh.test",
                created_on=base - datetime.timedelta(days=12),
                checked_at=base,
            )
        )
        # Stale success (8 days): refetch.
        db.add(
            DomainAgeCache(
                domain="stale.test",
                created_on=base - datetime.timedelta(days=100),
                checked_at=base - datetime.timedelta(days=8),
            )
        )
        # Fresh failure (30 min): no network, None.
        db.add(
            DomainAgeCache(
                domain="failfresh.test",
                created_on=None,
                checked_at=base - datetime.timedelta(minutes=30),
            )
        )
        # Stale failure (2 h): refetch.
        db.add(
            DomainAgeCache(
                domain="failstale.test",
                created_on=None,
                checked_at=base - datetime.timedelta(hours=2),
            )
        )
        db.commit()

        def boom(request: httpx.Request) -> httpx.Response:
            raise AssertionError("network must not be used on a fresh cache hit")

        no_net = httpx.MockTransport(boom)
        assert get_domain_age_cached(db, "fresh.test", transport=no_net, now=base) == 12
        assert get_domain_age_cached(db, "failfresh.test", transport=no_net, now=base) is None

        calls: list[str] = []
        age = get_domain_age_cached(
            db, "stale.test", transport=_rdap_transport(days_ago=5, calls=calls), now=base
        )
        assert age is not None and abs(age - 5) <= 1
        assert len(calls) == 1

        calls2: list[str] = []
        age2 = get_domain_age_cached(
            db,
            "failstale.test",
            transport=_rdap_transport(days_ago=9, calls=calls2),
            now=base,
        )
        assert age2 is not None and abs(age2 - 9) <= 1
        assert len(calls2) == 1
    finally:
        db.close()


def test_failure_caches_for_an_hour(test_db):
    TestingSession = test_db
    calls: list[str] = []
    transport = _rdap_transport(status=404, calls=calls)
    db = TestingSession()
    try:
        assert get_domain_age_cached(db, "missing.test", transport=transport) is None
        assert get_domain_age_cached(db, "missing.test", transport=transport) is None
    finally:
        db.close()
    assert len(calls) == 1

# --- Endpoints ---


def test_url_scan_with_new_domain_flags_it(test_db):
    app.dependency_overrides[get_age_lookup] = lambda: (lambda domain: 12)
    try:
        client = TestClient(app)
        r = client.post(
            "/api/scan",
            json={"type": "url", "input": "https://brand-new-shop.xyz/deal"},
        )
    finally:
        app.dependency_overrides.pop(get_age_lookup, None)
    assert r.status_code == 200, r.text
    codes = [f["rule_code"] for f in r.json()["findings"]]
    assert "DOMAIN_VERY_NEW" in codes


def test_url_scan_failed_lookup_adds_note_not_finding(test_db):
    client = TestClient(app)  # autouse fixture: age lookup returns None
    r = client.post(
        "/api/scan", json={"type": "url", "input": "https://some-shop.xyz/deal"}
    )
    assert r.status_code == 200, r.text
    body = r.json()
    codes = [f["rule_code"] for f in body["findings"]]
    assert "DOMAIN_VERY_NEW" not in codes
    assert "DOMAIN_NEW" not in codes
    assert "We could not check how old this website is." in body["notes"]


def test_official_domains_skip_the_lookup(test_db):
    calls: list[str] = []

    def counting(domain: str) -> int | None:
        calls.append(domain)
        return 12

    app.dependency_overrides[get_age_lookup] = lambda: counting
    try:
        client = TestClient(app)
        r = client.post(
            "/api/scan",
            json={"type": "url", "input": "https://www.google.com/search"},
        )
    finally:
        app.dependency_overrides.pop(get_age_lookup, None)
    assert r.status_code == 200, r.text
    assert calls == []
    assert "DOMAIN_VERY_NEW" not in [f["rule_code"] for f in r.json()["findings"]]


def test_message_with_five_links_does_at_most_two_lookups(test_db):
    calls: list[str] = []

    def counting(domain: str) -> int | None:
        calls.append(domain)
        return 60

    app.dependency_overrides[get_age_lookup] = lambda: counting
    try:
        client = TestClient(app)
        text = " ".join(f"visit http://shop{i}.test/deal now" for i in range(5))
        r = client.post("/api/scan", json={"type": "message", "input": text})
    finally:
        app.dependency_overrides.pop(get_age_lookup, None)
    assert r.status_code == 200, r.text
    assert len(calls) == 2
    codes = [f["rule_code"] for f in r.json()["findings"]]
    assert codes.count("DOMAIN_NEW") == 1


def test_ip_host_skips_the_lookup(test_db):
    calls: list[str] = []

    def counting(domain: str) -> int | None:
        calls.append(domain)
        return 12

    app.dependency_overrides[get_age_lookup] = lambda: counting
    try:
        client = TestClient(app)
        r = client.post("/api/scan", json={"type": "url", "input": "http://93.184.216.34/"})
    finally:
        app.dependency_overrides.pop(get_age_lookup, None)
    assert r.status_code == 200, r.text
    assert calls == []
