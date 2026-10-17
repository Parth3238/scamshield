"""Request and response shapes for register, login and /me."""

from __future__ import annotations

from email_validator import EmailNotValidError, validate_email
from pydantic import BaseModel, Field, field_validator


def normalize_email(value: str) -> str:
    """Validate the address format and return it lowercased.

    Deliverability is not checked (no DNS/internet), only the format.
    """
    cleaned = (value or "").strip()
    try:
        validate_email(cleaned, check_deliverability=False)
    except EmailNotValidError as exc:
        raise ValueError("Enter a valid email address.") from exc
    return cleaned.lower()


class RegisterRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=10, max_length=128)

    @field_validator("email")
    @classmethod
    def _valid_email(cls, v: str) -> str:
        return normalize_email(v)


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=1, max_length=128)

    @field_validator("email")
    @classmethod
    def _valid_email(cls, v: str) -> str:
        return normalize_email(v)


class UserOut(BaseModel):
    id: str
    email: str
    role: str


class MessageOut(BaseModel):
    message: str
