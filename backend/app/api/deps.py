"""Login dependencies: optional user, required user, required admin."""

from __future__ import annotations

import jwt
from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import decode_access_token
from app.models.db_models import User

COOKIE_NAME = "access_token"


def _user_from_cookie(request: Request, db: Session) -> User | None:
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None
    try:
        user_id = decode_access_token(token)
    except jwt.PyJWTError:
        return None
    except Exception:
        return None
    user = db.get(User, user_id)
    if user is None or not user.is_active:
        return None
    return user


def get_current_user_optional(
    request: Request, db: Session = Depends(get_db)
) -> User | None:
    """Return the logged-in user, or None when anonymous/logged out."""
    return _user_from_cookie(request, db)


def get_current_user(
    request: Request, db: Session = Depends(get_db)
) -> User:
    """Return the logged-in user, or 401 when missing, bad or inactive."""
    user = _user_from_cookie(request, db)
    if user is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


def require_admin(user: User = Depends(get_current_user)) -> User:
    """Return the user when admin, else 401 (not logged in) or 403."""
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user
