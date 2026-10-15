"""Pytest setup: test-only settings before any app module is imported."""

import os

# The app refuses to start without SECRET_KEY, so tests provide a fixed one.
# This is only a test secret and is never used in production.
os.environ.setdefault(
    "SECRET_KEY", "test-only-secret-key-that-is-long-enough-123456"
)

import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def _clear_all_limiters():
    """Reset every in-memory limiter before and after each test.

    Scan/report anonymous limits are global and shared by IP ("testserver"
    in TestClient), so without this, hits would leak across tests and old
    tests could hit the new 10/minute anonymous limit.
    """
    from app.api.routes_auth import login_limiter
    from app.api.routes_reports import report_limiter
    from app.api.routes_scan import get_age_lookup
    from app.main import app
    from app.services.api_throttle import clear_throttle, reset_throttle_clock

    os.environ.pop("TRUST_PROXY", None)
    login_limiter.clear()
    report_limiter.clear()
    clear_throttle()
    reset_throttle_clock()
    # No real RDAP in tests: age lookups return None (unknown) unless a test
    # overrides the dependency itself with a fake age.
    app.dependency_overrides[get_age_lookup] = lambda: (lambda domain: None)
    try:
        yield
    finally:
        os.environ.pop("TRUST_PROXY", None)
        login_limiter.clear()
        report_limiter.clear()
        clear_throttle()
        reset_throttle_clock()
        app.dependency_overrides.pop(get_age_lookup, None)
