"""Small ORM-only helpers for known-bad indicators."""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.models.db_models import Indicator


def _normalize_value(value: str) -> str:
    return (value or "").strip().lower()


def is_known_bad(db: Session | None, type: str, value: str) -> bool:
    """Return True when (type, normalized value) exists in indicators table."""
    if db is None:
        return False
    norm = _normalize_value(value)
    if not norm or not type:
        return False
    row = (
        db.query(Indicator)
        .filter(Indicator.type == type, Indicator.value == norm)
        .first()
    )
    return row is not None
