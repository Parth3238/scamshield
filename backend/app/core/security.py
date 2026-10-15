"""Password hashing (argon2) and login tokens (JWT, HS256)."""

from __future__ import annotations

import datetime

import jwt
from argon2 import PasswordHasher

from app.core.config import ACCESS_TOKEN_MINUTES, SECRET_KEY

_ph = PasswordHasher()

# A precomputed argon2 hash used only for dummy verification when an email
# does not exist, so unknown emails take the same time as wrong passwords.
DUMMY_HASH = (
    "$argon2id$v=19$m=65536,t=3,p=4$LPGV/9+6Fz6zR8qsz+EMgA"
    "$HdtCQ94s4ZWDMz+7Qvy0Majxq4F5gjjf+RIinO+/hZI"
)


def hash_password(password: str) -> str:
    """Hash a password with argon2. The hash goes in the database, never the password."""
    return _ph.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """Return True only when the password matches the stored argon2 hash."""
    try:
        return _ph.verify(password_hash, password)
    except Exception:
        # Wrong password, damaged hash, or anything unexpected: just say no.
        return False


def create_access_token(user_id: str, minutes: int | None = None) -> str:
    """Create a short-lived JWT with sub (user id), iat and exp claims."""
    now = datetime.datetime.now(datetime.timezone.utc)
    lifetime = datetime.timedelta(
        minutes=ACCESS_TOKEN_MINUTES if minutes is None else minutes
    )
    payload = {
        "sub": user_id,
        "iat": int(now.timestamp()),
        "exp": int((now + lifetime).timestamp()),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def decode_access_token(token: str) -> str:
    """Return the user id (sub) or raise when the token is expired or tampered."""
    payload = jwt.decode(
        token,
        SECRET_KEY,
        algorithms=["HS256"],
        options={"require": ["sub", "exp", "iat"]},
    )
    sub = payload.get("sub")
    if not sub or not isinstance(sub, str):
        raise jwt.InvalidTokenError("missing subject")
    return sub
