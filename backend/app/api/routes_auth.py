"""Register, login, logout and /me endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.deps import COOKIE_NAME, get_current_user
from app.core.config import ACCESS_TOKEN_MINUTES, COOKIE_SECURE
from app.core.database import get_db
from app.core.rate_limit import build_limiter
from app.core.security import (
    DUMMY_HASH,
    create_access_token,
    hash_password,
    verify_password,
)
from app.models.db_models import User
from app.schemas.auth import LoginRequest, MessageOut, RegisterRequest, UserOut

router = APIRouter()

REGISTER_MSG = "If this email can be registered, your account is created"
LOGIN_FAILED_MSG = "Invalid email or password"
RATE_LIMIT_MSG = "Too many failed login attempts. Try again later."

# Login attempts: Redis-backed when REDIS_URL is set (shared across
# processes), in-memory otherwise. Redis keys are hashed, so raw
# emails never reach Redis.
login_limiter = build_limiter(5, 15 * 60, scope="login")


def _client_ip(request: Request) -> str:
    if request.client is not None:
        return request.client.host
    return "unknown"


@router.post("/api/auth/register", response_model=MessageOut)
def register(req: RegisterRequest, db: Session = Depends(get_db)):
    email = (req.email or "").strip().lower()
    existing = db.query(User).filter(User.email == email).first()
    if existing is not None:
        # Same generic reply, plus a dummy hash so timing looks similar.
        hash_password("dummy-password-for-timing-equality")
        return MessageOut(message=REGISTER_MSG)
    # Role is always "user" here; admins are created with scripts/create_admin.py.
    db.add(
        User(
            email=email,
            password_hash=hash_password(req.password),
            role="user",
            is_active=True,
        )
    )
    try:
        db.commit()
    except IntegrityError:
        # Two requests raced for the same email: same generic reply.
        db.rollback()
    return MessageOut(message=REGISTER_MSG)


@router.post("/api/auth/login", response_model=UserOut)
def login(
    req: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    email = (req.email or "").strip().lower()
    key = f"{email}|{_client_ip(request)}"
    blocked, retry_after = login_limiter.is_blocked(key)
    if blocked:
        raise HTTPException(
            status_code=429,
            detail=RATE_LIMIT_MSG,
            headers={"Retry-After": str(retry_after)},
        )
    user = db.query(User).filter(User.email == email).first()
    if user is None:
        # Dummy check so unknown emails cost the same time as wrong passwords.
        verify_password(DUMMY_HASH, req.password)
        ok = False
    elif not user.is_active:
        verify_password(user.password_hash, req.password)
        ok = False
    else:
        ok = verify_password(user.password_hash, req.password)
    if not ok or user is None:
        login_limiter.record_failure(key)
        raise HTTPException(status_code=401, detail=LOGIN_FAILED_MSG)
    login_limiter.reset(key)
    token = create_access_token(user.id)
    response.set_cookie(
        COOKIE_NAME,
        token,
        max_age=ACCESS_TOKEN_MINUTES * 60,
        httponly=True,
        samesite="lax",
        secure=COOKIE_SECURE,
        path="/",
    )
    return UserOut(id=user.id, email=user.email, role=user.role)


@router.post("/api/auth/logout", response_model=MessageOut)
def logout(response: Response):
    response.delete_cookie(COOKIE_NAME, path="/")
    return MessageOut(message="Logged out")


@router.get("/api/auth/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return UserOut(id=user.id, email=user.email, role=user.role)
