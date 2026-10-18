"""Security behavior: headers, CORS, body limits, docs modes, errors, logs."""

from __future__ import annotations

import json
import logging

from fastapi.testclient import TestClient

from app.core.log_scrub import scrub_for_log
from app.main import app, create_app

client = TestClient(app, raise_server_exceptions=False)


def test_security_headers_on_api_response():
    r = client.get("/api/auth/me")
    assert r.status_code == 401
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["Referrer-Policy"] == "no-referrer"
    assert r.headers["Permissions-Policy"] == "camera=(), microphone=(), geolocation=()"
    assert r.headers["Cache-Control"] == "no-store"
    assert r.headers["X-Request-ID"]


def test_health_has_headers_but_no_cache_control():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert "Cache-Control" not in r.headers


def test_unknown_origin_gets_no_cors_headers():
    r = client.get("/health", headers={"Origin": "https://evil.example"})
    assert "Access-Control-Allow-Origin" not in r.headers


def test_allowed_origin_gets_cors_headers(monkeypatch):
    monkeypatch.setenv("ALLOWED_ORIGINS", "https://app.example, https://other.example")
    r = client.get("/health", headers={"Origin": "https://app.example"})
    assert r.headers["Access-Control-Allow-Origin"] == "https://app.example"
    assert r.headers["Access-Control-Allow-Credentials"] == "true"


def test_preflight_unknown_origin_has_no_cors(monkeypatch):
    monkeypatch.setenv("ALLOWED_ORIGINS", "https://app.example")
    r = client.options(
        "/api/scan",
        headers={
            "Origin": "https://evil.example",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert "Access-Control-Allow-Origin" not in r.headers


def test_json_body_over_20kb_rejected():
    big = {"type": "message", "input": "x" * 21000}
    r = client.post("/api/scan", json=big)
    assert r.status_code == 413
    assert r.json() == {"detail": "Request body too large"}


def test_body_over_6mb_rejected():
    r = client.post(
        "/api/scan", content=b"x" * (6 * 1024 * 1024 + 100), headers={"Content-Type": "text/plain"}
    )
    assert r.status_code == 413


def test_qr_upload_exempt_from_20kb_json_rule():
    blob = b"not-an-image" * 3000  # ~36 KB, multipart (not JSON)
    r = client.post("/api/scan/qr", files={"file": ("evil.png", blob, "image/png")})
    # 400 from image validation proves the 20 KB JSON rule did not fire.
    assert r.status_code == 400


def test_docs_disabled_in_production():
    prod = TestClient(create_app("production"), raise_server_exceptions=False)
    assert prod.get("/docs").status_code == 404
    assert prod.get("/redoc").status_code == 404
    assert prod.get("/openapi.json").status_code == 404


def test_docs_enabled_in_development():
    dev = TestClient(create_app("development"), raise_server_exceptions=False)
    assert dev.get("/docs").status_code == 200


def test_unexpected_error_is_generic_with_id(caplog):
    crashing = create_app("development")

    @crashing.get("/api/boom")
    def boom():  # pragma: no cover - deliberate crash route for this test
        raise RuntimeError("secret internals: db password hunter2")

    c = TestClient(crashing, raise_server_exceptions=False)
    with caplog.at_level(logging.ERROR, logger="scamshield.error"):
        r = c.get("/api/boom")
    assert r.status_code == 500
    assert r.json() == {"detail": "Something went wrong"}
    assert "secret internals" not in r.text
    assert "Traceback" not in r.text
    error_id = r.headers.get("X-Error-ID")
    assert error_id
    logged = "\n".join(rec.getMessage() for rec in caplog.records)
    assert error_id in logged
    assert "secret internals" in logged  # full detail stays server-side


def test_sensitive_data_never_logged(caplog):
    secret_key = "ss_live_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
    with caplog.at_level(logging.INFO, logger="scamshield.request"):
        client.post(
            "/api/auth/login",
            json={"email": "a@b.com", "password": "supersecretpw1"},
            headers={"X-API-Key": secret_key, "Cookie": "access_token=fake.jwt.token"},
        )
    logged = "\n".join(rec.getMessage() for rec in caplog.records)
    assert "supersecretpw1" not in logged
    assert secret_key not in logged
    assert "fake.jwt.token" not in logged


def test_scrub_helper_redacts_secrets():
    assert "ABCDEF1234567890" not in scrub_for_log("key=ss_live_ABCDEF1234567890")
    assert "[REDACTED]" in scrub_for_log("key=ss_live_ABCDEF1234567890")
    assert "supersecretpw1" not in scrub_for_log('{"password": "supersecretpw1"}')
    assert "482910" not in scrub_for_log("your OTP is 482910")
    assert "ram@okhdfc" not in scrub_for_log("pay ram@okhdfc now")
    assert "Bearer abc.def.ghi" not in scrub_for_log("Authorization: Bearer abc.def.ghi")
    # Ordinary text survives scrubbing.
    assert json.loads('{"a": 1}') == {"a": 1}
    assert scrub_for_log("hello world") == "hello world"
