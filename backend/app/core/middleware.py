"""HTTP middleware: request IDs + JSON logs, security headers, CORS, limits.

Order when added in app/main.py (first added = outermost):
RequestID -> SecurityHeaders -> CORS -> BodyLimit -> app.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from urllib.parse import urlparse

from starlette.datastructures import Headers, MutableHeaders
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.config import get_allowed_origins

REQUEST_ID_HEADER = "X-Request-ID"
REQUEST_ID_SCOPE_KEY = "scamshield.request_id"

MAX_BODY_BYTES = 6 * 1024 * 1024  # 6 MB for every request
MAX_JSON_BYTES = 20 * 1024  # 20 KB JSON for non-upload endpoints
QR_PATH = "/api/scan/qr"

request_logger = logging.getLogger("scamshield.request")


def _json_limit_for(scope: Scope) -> int:
    headers = Headers(scope=scope)
    content_type = headers.get("content-type", "")
    if "application/json" in content_type and urlparse(scope.get("path", "")).path != QR_PATH:
        return MAX_JSON_BYTES
    return MAX_BODY_BYTES


class RequestIDMiddleware:
    """One id per request: returned as X-Request-ID and written into logs."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request_id = uuid.uuid4().hex
        scope[REQUEST_ID_SCOPE_KEY] = request_id
        method = scope.get("method", "")
        path = urlparse(scope.get("path", "")).path
        started = time.monotonic()
        status = 500

        async def send_with_id(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message.get("status", 500)
                headers = MutableHeaders(raw=message.setdefault("headers", []))
                headers[REQUEST_ID_HEADER] = request_id
            await send(message)

        try:
            await self.app(scope, receive, send_with_id)
        finally:
            duration_ms = round((time.monotonic() - started) * 1000, 2)
            # Metadata only: never bodies, secrets or cookies.
            request_logger.info(
                json.dumps(
                    {
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "level": "INFO",
                        "request_id": request_id,
                        "method": method,
                        "path": path,
                        "status": status,
                        "duration_ms": duration_ms,
                    }
                )
            )


class SecurityHeadersMiddleware:
    """No sniffing, no framing, no referrer leak, no sensors, no caching."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        is_api = urlparse(scope.get("path", "")).path.startswith("/api")

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(raw=message.setdefault("headers", []))
                headers["X-Content-Type-Options"] = "nosniff"
                headers["X-Frame-Options"] = "DENY"
                headers["Referrer-Policy"] = "no-referrer"
                headers["Permissions-Policy"] = (
                    "camera=(), microphone=(), geolocation=()"
                )
                if is_api:
                    headers["Cache-Control"] = "no-store"
            await send(message)

        await self.app(scope, receive, send_with_headers)


class CorsMiddleware:
    """Minimal CORS: only origins in ALLOWED_ORIGINS get CORS headers.

    Default allow-list is empty (the frontend uses the same-origin proxy),
    so cross-origin browsers get nothing. Never "*" (that would also forbid
    credentials). The list is read per request so tests need no app rebuild.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = Headers(scope=scope)
        origin = headers.get("origin", "")
        allowed = get_allowed_origins()
        if not origin or origin not in allowed:
            # Unknown or absent origin: pass through with no CORS headers.
            await self.app(scope, receive, send)
            return

        if scope.get("method") == "OPTIONS" and headers.get(
            "access-control-request-method"
        ):
            response = PlainTextResponse("ok")
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Vary"] = "Origin"
            response.headers["Access-Control-Allow-Credentials"] = "true"
            response.headers["Access-Control-Allow-Methods"] = (
                "GET, POST, PUT, PATCH, DELETE, OPTIONS"
            )
            response.headers["Access-Control-Allow-Headers"] = headers.get(
                "access-control-request-headers", "*"
            )
            response.headers["Access-Control-Max-Age"] = "600"
            await response(scope, receive, send)
            return

        async def send_with_cors(message: Message) -> None:
            if message["type"] == "http.response.start":
                out = MutableHeaders(raw=message.setdefault("headers", []))
                out["Access-Control-Allow-Origin"] = origin
                out["Vary"] = "Origin"
                out["Access-Control-Allow-Credentials"] = "true"
            await send(message)

        await self.app(scope, receive, send_with_cors)


class BodyLimitMiddleware:
    """Reject oversized bodies with 413 before the app reads them.

    Every request is capped at 6 MB. JSON bodies on non-upload endpoints are
    capped at 20 KB (the QR upload uses multipart and keeps its own 5 MB
    check under the 6 MB cap).
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit = _json_limit_for(scope)
        headers = Headers(scope=scope)
        raw_length = headers.get("content-length", "")
        if raw_length.strip():
            try:
                if int(raw_length) > limit:
                    await self._too_large(scope, receive, send)
                    return
            except ValueError:
                pass
            await self.app(scope, receive, send)
            return

        # No content-length (chunked): count while buffering, then replay.
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] != "http.request":
                return
            body += message.get("body", b"")
            if len(body) > limit:
                await self._too_large(scope, receive, send)
                return
            if not message.get("more_body", False):
                break
        replayed = False

        async def replay() -> Message:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return {"type": "http.disconnect"}

        await self.app(scope, replay, send)

    async def _too_large(self, scope: Scope, receive: Receive, send: Send) -> None:
        response = JSONResponse(
            status_code=413, content={"detail": "Request body too large"}
        )
        await response(scope, receive, send)
