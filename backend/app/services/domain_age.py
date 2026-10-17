"""Domain age via RDAP. Network failures always mean None, never raise."""

from __future__ import annotations

import datetime
import json
import re
from urllib.parse import quote, urljoin, urlparse

import httpx
from sqlalchemy.orm import Session

from app.models.db_models import DomainAgeCache

RDAP_BASE = "https://rdap.org/domain/"
RDAP_TIMEOUT = 3.0
RDAP_MAX_BYTES = 200 * 1024  # 200 KB
RDAP_MAX_REDIRECTS = 2

# Strict allow-list for the value placed into the RDAP URL: lowercase
# letters, digits, hyphens and dots only. Anything else returns None
# without any network call.
_DOMAIN_RE = re.compile(r"[a-z0-9.\-]+")


def _valid_domain(domain: str) -> str | None:
    cleaned = (domain or "").strip()
    if not cleaned or len(cleaned) >= 253:
        return None
    if _DOMAIN_RE.fullmatch(cleaned) is None:
        return None
    return cleaned


def _registration_date(data: object) -> datetime.datetime | None:
    if not isinstance(data, dict):
        return None
    events = data.get("events")
    if not isinstance(events, list):
        return None
    for event in events:
        if not isinstance(event, dict):
            continue
        if str(event.get("eventAction", "")).lower() != "registration":
            continue
        raw = event.get("eventDate")
        if not isinstance(raw, str) or not raw.strip():
            continue
        try:
            moment = datetime.datetime.fromisoformat(raw.strip().replace("Z", "+00:00"))
        except ValueError:
            continue
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=datetime.timezone.utc)
        return moment
    return None


def get_domain_age_days(
    registered_domain: str,
    *,
    transport: httpx.BaseTransport | None = None,
) -> int | None:
    """Return whole days since the domain was registered, or None.

    Queries the fixed trusted host rdap.org (never a user URL). Returns None
    for bad input and for every failure: timeout, 404, oversize body, bad
    JSON, missing date. Never raises. Certificate verification stays on.
    """
    domain = _valid_domain(registered_domain)
    if domain is None:
        return None
    try:
        with httpx.Client(
            follow_redirects=False, timeout=RDAP_TIMEOUT, transport=transport
        ) as client:
            created = _fetch_created_on(client, domain)
    except Exception:
        return None
    if created is None:
        return None
    now = datetime.datetime.now(datetime.timezone.utc)
    return max(0, (now - created).days)


CACHE_HIT_DAYS = 7
CACHE_MISS_HOURS = 1


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _as_aware(moment: datetime.datetime | None) -> datetime.datetime | None:
    if moment is None:
        return None
    if moment.tzinfo is None:
        return moment.replace(tzinfo=datetime.timezone.utc)
    return moment


def get_domain_age_cached(
    db: Session,
    registered_domain: str,
    *,
    transport: httpx.BaseTransport | None = None,
    now: datetime.datetime | None = None,
) -> int | None:
    """Cached wrapper around get_domain_age_days.

    Successful lookups are reused for 7 days, failures for 1 hour. The
    `now` parameter exists so tests can move time with a fake clock.
    Never raises: database trouble falls back to a live lookup, and a
    failed lookup simply returns None.
    """
    domain = _valid_domain(registered_domain)
    if domain is None:
        return None
    moment = _as_aware(now) or _utcnow()
    try:
        row = db.query(DomainAgeCache).filter(DomainAgeCache.domain == domain).first()
    except Exception:
        row = None
    if row is not None:
        checked = _as_aware(row.checked_at)
        if checked is not None:
            age = moment - checked
            if row.created_on is not None:
                if age < datetime.timedelta(days=CACHE_HIT_DAYS):
                    created = _as_aware(row.created_on)
                    if created is not None:
                        return max(0, (moment - created).days)
            elif age < datetime.timedelta(hours=CACHE_MISS_HOURS):
                return None
    try:
        with httpx.Client(
            follow_redirects=False, timeout=RDAP_TIMEOUT, transport=transport
        ) as client:
            # Reuse the same parsing: fetch raw creation date via a helper.
            created_on = _fetch_created_on(client, domain)
    except Exception:
        created_on = None
    try:
        if row is None:
            row = DomainAgeCache(domain=domain)
            db.add(row)
        row.created_on = created_on
        row.checked_at = moment
        db.add(row)
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:  # nosec B110 - cache write is best-effort; lookup result is already known
            pass
    if created_on is None:
        return None
    return max(0, (moment - created_on).days)


def _fetch_created_on(
    client: httpx.Client, domain: str
) -> datetime.datetime | None:
    """Fetch the RDAP registration date with an existing client (testable)."""
    url = RDAP_BASE + quote(domain, safe="")
    current = url
    for _ in range(RDAP_MAX_REDIRECTS + 1):
        with client.stream("GET", current) as response:
            if response.status_code in (301, 302, 303, 307, 308):
                target = response.headers.get("location")
                response.close()
                if not target:
                    return None
                nxt = urljoin(current, target)
                if (urlparse(nxt).scheme or "").lower() != "https":
                    return None
                current = nxt
                continue
            if response.status_code != 200:
                return None
            total = 0
            chunks: list[bytes] = []
            for chunk in response.iter_bytes(chunk_size=8192):
                total += len(chunk)
                if total > RDAP_MAX_BYTES:
                    return None
                chunks.append(chunk)
            try:
                data = json.loads(b"".join(chunks).decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                return None
            created = _registration_date(data)
            if created is None:
                return None
            return _as_aware(created)
    return None
