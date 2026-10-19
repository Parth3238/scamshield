"""Shared API-key auth and sliding-window rate limiting for scans/reports.

Limiters come from core/rate_limit.py as Redis-backed (shared across
server processes) when REDIS_URL is set, with an in-memory fallback if
Redis is unreachable. Without REDIS_URL they are plain in-memory.

The clock is injectable so tests can move time forward with a fake clock.
"""

from __future__ import annotations

import datetime
import hashlib
import os
import time
from collections.abc import Callable

from fastapi import HTTPException, Request
from sqlalchemy.orm import Session

from app.core.rate_limit import build_limiter
from app.models.db_models import ApiKey, ApiUsage, User

ANON_PER_MINUTE = 10
ANON_PER_DAY = 100

RATE_LIMIT_MSG = "Rate limit exceeded"
INVALID_KEY_MSG = "Invalid API key"

# Shared mutable clock so tests can inject a fake clock once for every
# limiter below. Each RateLimiter is built with clock=_shared_clock, which
# reads _clock_fn at call time, so set_throttle_clock() affects all of them.
_clock_fn: Callable[[], float] = time.monotonic


def _shared_clock() -> float:
    return _clock_fn()


def set_throttle_clock(clock: Callable[[], float]) -> None:
    """Point every throttle limiter at a fake clock (tests only)."""
    global _clock_fn
    _clock_fn = clock


def reset_throttle_clock() -> None:
    """Point every throttle limiter back at the real clock."""
    global _clock_fn
    _clock_fn = time.monotonic


# Anonymous per-IP limiters (fixed limits from the spec).
# Redis-backed when REDIS_URL is set (shared across processes),
# in-memory otherwise. Redis keys are hashed inside the limiter,
# so raw IPs never reach Redis.
anon_minute_limiter = build_limiter(
    ANON_PER_MINUTE, 60, scope="anon-minute", clock=_shared_clock
)
anon_daily_limiter = build_limiter(
    ANON_PER_DAY, 24 * 60 * 60, scope="anon-daily", clock=_shared_clock
)

# Per-key limiters, one limiter per key id per window. The max_attempts
# is synced from the key's own per_minute_limit / daily_limit on each
# request, so custom limits in the DB are respected.
_key_minute_limiters: dict = {}
_key_daily_limiters: dict = {}


def _key_minute_limiter(key_id: str, limit: int):
    lim = _key_minute_limiters.get(key_id)
    if lim is None:
        lim = build_limiter(limit, 60, scope="key-minute", clock=_shared_clock)
        _key_minute_limiters[key_id] = lim
    else:
        lim.max_attempts = limit
    return lim


def _key_daily_limiter(key_id: str, limit: int):
    lim = _key_daily_limiters.get(key_id)
    if lim is None:
        lim = build_limiter(
            limit, 24 * 60 * 60, scope="key-daily", clock=_shared_clock
        )
        _key_daily_limiters[key_id] = lim
    else:
        lim.max_attempts = limit
    return lim


def clear_throttle() -> None:
    """Clear all in-memory hits (tests call this between cases)."""
    anon_minute_limiter.clear()
    anon_daily_limiter.clear()
    _key_minute_limiters.clear()
    _key_daily_limiters.clear()


def client_ip(request: Request) -> str:
    """Return the caller IP.

    Uses request.client.host only by default. The X-Forwarded-For header is
    attacker-controlled (any client can send a fake one to dodge limits or
    frame someone else), so it is ignored unless TRUST_PROXY=true is set in
    the environment — only enable that behind a proxy you control that
    strips or overwrites spoofed values.
    """
    if os.getenv("TRUST_PROXY", "").strip().lower() in ("1", "true", "yes", "on"):
        fwd = request.headers.get("x-forwarded-for", "")
        if fwd.strip():
            first = fwd.split(",")[0].strip()
            if first:
                return first
    if request.client is not None:
        return request.client.host
    return "unknown"


def hash_api_key(raw: str) -> str:
    """sha256 hex of the full key. Look keys up by this hash only."""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def lookup_api_key(db: Session, raw: str) -> ApiKey | None:
    """Find a key row by hashing the presented key. Never log the raw key."""
    digest = hash_api_key(raw)
    return db.query(ApiKey).filter(ApiKey.key_hash == digest).first()


def check_key_limits(key: ApiKey) -> tuple[bool, int, int, int]:
    """Return (blocked, retry_after, limit, remaining-after-this-request).

    Minute window is checked first, then the daily window. The header limit
    is always the daily limit; remaining is daily remaining after recording.
    """
    minute_lim = _key_minute_limiter(key.id, key.per_minute_limit)
    blocked, retry = minute_lim.is_blocked(f"key:{key.id}:minute")
    if blocked:
        daily_lim = _key_daily_limiter(key.id, key.daily_limit)
        daily_remaining = daily_lim.remaining(f"key:{key.id}:daily")
        return True, retry, key.daily_limit, daily_remaining
    daily_lim = _key_daily_limiter(key.id, key.daily_limit)
    blocked, retry = daily_lim.is_blocked(f"key:{key.id}:daily")
    if blocked:
        return True, retry, key.daily_limit, 0
    # Allowed: remaining as it will be after this hit is recorded.
    remaining = max(0, daily_lim.remaining(f"key:{key.id}:daily") - 1)
    return False, 0, key.daily_limit, remaining


def record_key_hit(key_id: str) -> None:
    """Count one request for a key in both windows."""
    minute_lim = _key_minute_limiters.get(key_id)
    if minute_lim is not None:
        minute_lim.record_hit(f"key:{key_id}:minute")
    daily_lim = _key_daily_limiters.get(key_id)
    if daily_lim is not None:
        daily_lim.record_hit(f"key:{key_id}:daily")


def check_anon_limits(ip: str) -> tuple[bool, int, int, int]:
    """Return (blocked, retry_after, limit, remaining) for an anonymous IP."""
    blocked, retry = anon_minute_limiter.is_blocked(f"ip:{ip}:minute")
    if blocked:
        remaining = anon_daily_limiter.remaining(f"ip:{ip}:daily")
        return True, retry, ANON_PER_DAY, remaining
    blocked, retry = anon_daily_limiter.is_blocked(f"ip:{ip}:daily")
    if blocked:
        return True, retry, ANON_PER_DAY, 0
    remaining = max(0, anon_daily_limiter.remaining(f"ip:{ip}:daily") - 1)
    return False, 0, ANON_PER_DAY, remaining


def record_anon_hit(ip: str) -> None:
    """Count one anonymous request in both windows."""
    anon_minute_limiter.record_hit(f"ip:{ip}:minute")
    anon_daily_limiter.record_hit(f"ip:{ip}:daily")


def touch_key_last_used(db: Session, key: ApiKey) -> None:
    """Update last_used_at. A failed write must never break the request."""
    try:
        key.last_used_at = datetime.datetime.now(datetime.timezone.utc)
        db.add(key)
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:  # nosec B110 - auxiliary timestamp write must never break the request
            pass


def log_key_usage(
    db: Session, api_key_id: str, endpoint: str, status_code: int
) -> None:
    """Write one ApiUsage row. A failed write must never break the request."""
    try:
        db.add(
            ApiUsage(
                api_key_id=api_key_id,
                endpoint=endpoint,
                status_code=status_code,
            )
        )
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:  # nosec B110 - usage logging must never break the request
            pass


def rate_limit_headers(limit: int, remaining: int) -> dict[str, str]:
    """Headers added to successful scan/report responses."""
    return {
        "X-RateLimit-Limit": str(limit),
        "X-RateLimit-Remaining": str(max(0, remaining)),
    }


def resolve_caller(
    request: Request,
    db: Session,
    cookie_user: User | None,
    endpoint: str,
) -> tuple[User | None, ApiKey | None, int, int]:
    """Identify the caller via X-API-Key or anonymous IP, enforcing limits.

    - Valid key: caller is the key owner, key limits apply.
    - Invalid/revoked/unknown key: 401, never fall back to anonymous.
    - No key: anonymous per-IP limits (10/min, 100/day).
    Returns (caller_user, api_key_row_or_None, limit, remaining).
    Raises 401 or 429 with Retry-After when blocked.
    """
    raw = ""
    try:
        raw = (request.headers.get("x-api-key") or "").strip()
    except Exception:
        raw = ""
    if raw:
        row = lookup_api_key(db, raw)
        if row is None or row.revoked:
            raise HTTPException(status_code=401, detail=INVALID_KEY_MSG)
        owner = db.get(User, row.user_id)
        if owner is None or not owner.is_active:
            raise HTTPException(status_code=401, detail=INVALID_KEY_MSG)
        blocked, retry, limit, remaining = check_key_limits(row)
        if blocked:
            log_key_usage(db, row.id, endpoint, 429)
            raise HTTPException(
                status_code=429,
                detail=RATE_LIMIT_MSG,
                headers={"Retry-After": str(retry)},
            )
        record_key_hit(row.id)
        return owner, row, limit, remaining
    ip = client_ip(request)
    blocked, retry, limit, remaining = check_anon_limits(ip)
    if blocked:
        raise HTTPException(
            status_code=429,
            detail=RATE_LIMIT_MSG,
            headers={"Retry-After": str(retry)},
        )
    record_anon_hit(ip)
    return cookie_user, None, limit, remaining


# Re-export deque import guard for type checkers (keeps unused-import clean).
__all__ = [
    "ANON_PER_DAY",
    "ANON_PER_MINUTE",
    "INVALID_KEY_MSG",
    "RATE_LIMIT_MSG",
    "anon_daily_limiter",
    "anon_minute_limiter",
    "check_anon_limits",
    "check_key_limits",
    "clear_throttle",
    "client_ip",
    "hash_api_key",
    "log_key_usage",
    "lookup_api_key",
    "rate_limit_headers",
    "record_anon_hit",
    "record_key_hit",
    "reset_throttle_clock",
    "resolve_caller",
    "set_throttle_clock",
    "touch_key_last_used",
]
