"""Application settings from environment variables.

SECRET_KEY is required and must be at least 32 characters long; the app
refuses to start otherwise. The secret value is never printed or logged.
"""

from __future__ import annotations

import os


def _get_secret_key() -> str:
    value = os.getenv("SECRET_KEY", "")
    if not value:
        raise RuntimeError(
            "SECRET_KEY is not set. Set a random string of at least 32 "
            "characters in the SECRET_KEY environment variable before "
            "starting the app."
        )
    if len(value) < 32:
        raise RuntimeError(
            "SECRET_KEY is too short. It must be at least 32 characters long."
        )
    return value


def _get_int(name: str, default: int) -> int:
    raw = os.getenv(name, "")
    if not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError:
        raise RuntimeError(f"{name} must be a whole number, got {raw!r}.")


def _get_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name, "")
    if not raw.strip():
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


SECRET_KEY = _get_secret_key()
ACCESS_TOKEN_MINUTES = _get_int("ACCESS_TOKEN_MINUTES", 60)
COOKIE_SECURE = _get_bool("COOKIE_SECURE", False)


def _get_environment() -> str:
    value = os.getenv("ENVIRONMENT", "development").strip().lower()
    if value not in ("development", "production"):
        raise RuntimeError(
            "ENVIRONMENT must be 'development' or 'production', "
            f"got {value!r}."
        )
    return value


ENVIRONMENT = _get_environment()


def get_allowed_origins() -> list[str]:
    """Parse ALLOWED_ORIGINS (comma-separated). Empty by default.

    The frontend uses the same-origin /api proxy, so browsers never need
    cross-origin access. Read per call (not cached) so tests can change it.
    """
    raw = os.getenv("ALLOWED_ORIGINS", "")
    return [o.strip() for o in raw.split(",") if o.strip()]
