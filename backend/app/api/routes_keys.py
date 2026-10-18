"""Developer API keys: create, list, revoke and usage (login required)."""

from __future__ import annotations

import datetime
import secrets

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models.db_models import ApiKey, ApiUsage, User
from app.schemas.keys import KeyCreate, KeyCreatedOut, KeyOut, UsageDayOut, UsageOut
from app.services.api_throttle import hash_api_key

router = APIRouter()

MAX_ACTIVE_KEYS = 5
KEY_PREFIX = "ss_live_"

TOO_MANY_KEYS_MSG = "You already have 5 active keys. Revoke one first."
NOT_FOUND_MSG = "API key not found"


def _key_out(row: ApiKey) -> KeyOut:
    status = "revoked" if row.revoked else "active"
    return KeyOut(
        id=row.id,
        name=row.name,
        prefix=row.key_prefix,
        key_prefix=row.key_prefix,
        daily_limit=row.daily_limit,
        per_minute_limit=row.per_minute_limit,
        revoked=row.revoked,
        status=status,
        created_at=row.created_at,
        last_used_at=row.last_used_at,
        last_used=row.last_used_at,
    )


def _get_owned_key(db: Session, user: User, key_id: str) -> ApiKey:
    row = (
        db.query(ApiKey)
        .filter(ApiKey.id == key_id, ApiKey.user_id == user.id)
        .first()
    )
    if row is None:
        # Same generic 404 whether the id is unknown or belongs to someone
        # else, so key ids cannot be probed across users.
        raise HTTPException(status_code=404, detail=NOT_FOUND_MSG)
    return row


@router.post("/api/keys", response_model=KeyCreatedOut)
def create_key(
    req: KeyCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    name = (req.name or "").strip()
    if not 1 <= len(name) <= 50:
        raise HTTPException(
            status_code=422, detail="Name must be 1 to 50 characters."
        )
    active = (
        db.query(ApiKey)
        .filter(ApiKey.user_id == user.id, ApiKey.revoked.is_(False))
        .count()
    )
    if active >= MAX_ACTIVE_KEYS:
        raise HTTPException(status_code=409, detail=TOO_MANY_KEYS_MSG)
    # "ss_live_" + random part. The full key is shown once below and never
    # stored; only its sha256 hash goes in the database.
    full_key = KEY_PREFIX + secrets.token_urlsafe(32)
    prefix = full_key[:12]
    row = ApiKey(
        user_id=user.id,
        name=name,
        key_prefix=prefix,
        key_hash=hash_api_key(full_key),
        daily_limit=200,
        per_minute_limit=20,
        revoked=False,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return KeyCreatedOut(
        id=row.id,
        name=row.name,
        prefix=row.key_prefix,
        key_prefix=row.key_prefix,
        full_key=full_key,
        api_key=full_key,
        daily_limit=row.daily_limit,
        per_minute_limit=row.per_minute_limit,
    )


@router.get("/api/keys", response_model=list[KeyOut])
def list_keys(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    rows = (
        db.query(ApiKey)
        .filter(ApiKey.user_id == user.id)
        .order_by(ApiKey.created_at.desc())
        .all()
    )
    # Never return key_hash or the full key here.
    return [_key_out(r) for r in rows]


def _revoke_owned(db: Session, user: User, key_id: str) -> dict[str, str]:
    row = _get_owned_key(db, user, key_id)
    if not row.revoked:
        row.revoked = True
        db.add(row)
        db.commit()
    return {"message": "API key revoked"}


@router.delete("/api/keys/{key_id}")
def revoke_key(
    key_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    return _revoke_owned(db, user, key_id)


@router.post("/api/keys/{key_id}/revoke")
def revoke_key_alias(
    key_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    # Alias for older frontend clients that POST to /revoke.
    return _revoke_owned(db, user, key_id)


@router.get("/api/keys/{key_id}/usage", response_model=UsageOut)
def key_usage(
    key_id: str,
    response: Response,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    row = _get_owned_key(db, user, key_id)
    now = datetime.datetime.now(datetime.timezone.utc)
    today = now.date()
    days: list[UsageDayOut] = []
    for back in range(13, -1, -1):
        day = today - datetime.timedelta(days=back)
        start = datetime.datetime.combine(
            day, datetime.time.min, tzinfo=datetime.timezone.utc
        )
        end = start + datetime.timedelta(days=1)
        count = (
            db.query(ApiUsage)
            .filter(
                ApiUsage.api_key_id == row.id,
                ApiUsage.created_at >= start,
                ApiUsage.created_at < end,
            )
            .count()
        )
        days.append(UsageDayOut(date=day.isoformat(), count=count))
    today_count = days[-1].count if days else 0
    remaining = max(0, row.daily_limit - today_count)
    response.headers["X-RateLimit-Limit"] = str(row.daily_limit)
    response.headers["X-RateLimit-Remaining"] = str(remaining)
    return UsageOut(
        days=days, today_remaining=remaining, daily_limit=row.daily_limit
    )
